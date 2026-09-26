import argparse
import threading
import json
from datetime import datetime, timezone
from confluent_kafka import Producer, Consumer, KafkaError

from crypto_aes import derive_shared_key, encrypt, decrypt, MessageIntegrityError, CryptoAESError
from dlp_llm import inspect_and_mask


CONSENT_MENU = """\n
=======================================================================
               TERMO DE CONSCIENTIZAÇÃO E CONSENTIMENTO
=======================================================================

Bem-vindo ao Chat Seguro E2EE. Antes de prosseguir e acessar a 
aplicação, por favor, esteja ciente das seguintes diretrizes:

1. PRIVACIDADE: O chat não compartilha dados com terceiros e não 
   realiza transferência internacional com os seus dados.

2. FINALIDADE: A finalidade exclusiva do tratamento de dados neste 
   sistema é viabilizar uma comunicação privada entre dois usuários.

3. PREVENÇÃO DE VAZAMENTOS (DLP): É estritamente proibido o envio de 
   dados pessoais ou sensíveis. Se isso for tentado, o sistema gerará 
   um alerta de auditoria e realizará o mascaramento automático do dado.

4. SEGURANÇA: Todas as mensagens em trânsito e em repouso são 
   encriptadas de ponta a ponta.

Para mais informações, acesse:
https://github.com/TCC-Eduardo-Sandes-e-Vinicius-Santos/TCC-PoC3-Chat-com-Mascaramento-de-PII

=======================================================================
Você consente com esse uso, processamento de seus dados e concorda 
com as regras descritas acima? (aperte 's' para sim ou 'n' para não):\n"""

def kafka_consumer_thread(consumer, shared_key, my_id, target_id, chat_topic):
    consumer.subscribe([chat_topic])
    while True:
        msg = consumer.poll(1.0)

        if msg is None:
            continue

        if msg.error():
            # Ignora o aviso caso a sala ainda não exista
            if msg.error().code() == KafkaError.UNKNOWN_TOPIC_OR_PART:
                continue

            print(f"\n[ERRO KAFKA]: {msg.error()}")
            print(f"[{my_id}]: ", end="", flush=True)
            continue

        try:
            payload = json.loads(msg.value().decode('utf-8'))

            if payload.get('to') == my_id and payload.get('from') == target_id:
                texto_claro = decrypt(
                    ciphertext_b64=payload['ciphertext'],
                    nonce_b64=payload['nonce'],
                    key=shared_key
                )
                print(f"\n[{target_id}]: {texto_claro}")
                print(f"[{my_id}]: ", end="", flush=True)

        except MessageIntegrityError:
            print("\033[93m\n[ALERTA DE SEGURANÇA]: Mensagem interceptada! O payload falhou na validação de integridade e foi descartado.\033[0m")
            print(f"[{my_id}]: ", end="", flush=True)
        except (CryptoAESError, json.JSONDecodeError, KeyError):
            pass


def main() -> None:
    print(CONSENT_MENU)
    consent = input()

    if (consent.lower()) != 's':
        print("\nSaindo...")
        exit()

    parser = argparse.ArgumentParser(description="Chat Seguro E2EE com DLP")
    parser.add_argument("--my-id", required=True, help="Seu ID de Usuário")
    parser.add_argument("--target-id", required=True, help="ID do Destinatário")
    parser.add_argument("--chat", required=True, help="ID da Sala de Chat (Tópico)")
    args = parser.parse_args()

    print("--- Iniciando Chat Seguro ---")
    print(f"Logado como: {args.my_id} | Conversando com: {args.target_id} | Sala: {args.chat}")

    try:
        shared_key = derive_shared_key(args.my_id, args.target_id)
    except CryptoAESError as e:
        print(f"Erro crítico ao derivar chaves: {e}")
        return

    producer = Producer({'bootstrap.servers': 'localhost:9092'})
    consumer = Consumer({
        'bootstrap.servers': 'localhost:9092',
        'group.id': f'group_{args.my_id}',
        'auto.offset.reset': 'earliest',  # restaura sessao
        'enable.auto.commit': False,
    })

    threading.Thread(
        target=kafka_consumer_thread,
        args=(consumer, shared_key, args.my_id, args.target_id, args.chat),
        daemon=True
    ).start()

    while True:
        try:
            texto_original = input(f"[{args.my_id}]: ")
            if texto_original.lower() in ['sair', 'exit', 'quit']:
                break

            if not texto_original.strip():
                continue

            dlp_result = inspect_and_mask(texto_original)
            texto_mascarado = dlp_result.masked_message
            is_violation = dlp_result.was_masked

            if is_violation:
                alerta = {
                    "alert_type": dlp_result.alert_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "chatid": args.chat,
                    "user1id": args.my_id,
                    "user2id": args.target_id
                }
                producer.produce('security-logs', value=json.dumps(alerta).encode('utf-8'))
                print("\033[93m[AVISO LOCAL]: Sua mensagem continha dados sensíveis e foi mascarada antes do envio.\033[0m")

            envelope = encrypt(texto_mascarado, shared_key)

            msg_payload = {
                "from": args.my_id,
                "to": args.target_id,
                "nonce": envelope.nonce,
                "ciphertext": envelope.ciphertext
            }
            producer.produce(args.chat, value=json.dumps(msg_payload).encode('utf-8'))
            producer.flush()

        except KeyboardInterrupt:
            break

    print("\nDesconectando do servidor Kafka...")
    consumer.close()

if __name__ == "__main__":
    main()