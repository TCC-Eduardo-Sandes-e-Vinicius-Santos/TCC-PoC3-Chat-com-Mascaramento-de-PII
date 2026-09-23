import argparse
import threading
import json
import requests
from datetime import datetime
from confluent_kafka import Producer, Consumer, KafkaError

# Importa as funções de segurança do módulo dedicado
from crypto_aes import derive_shared_key, encrypt, decrypt, MessageIntegrityError

# ==========================================
# 1. MÓDULO DE DLP (OLLAMA LOCAL)
# ==========================================
def inspect_and_mask_pii(text):
    """
    Envia o texto para o modelo local do Ollama para aplicar o mascaramento.
    Retorna o texto mascarado e um booleano indicando se houve violação (PII detectado).
    """
    prompt = f"""
    Atue como um filtro de privacidade (DLP).
    Sua tarefa é ler a mensagem abaixo e substituir CPFs, e-mails, cartões de crédito e nomes completos por [DADO_SENSÍVEL_REMOVIDO].
    Responda APENAS com a mensagem higienizada. Não adicione explicações.
    Mensagem original: '{text}'
    """
    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": "llama3", 
            "prompt": prompt,
            "stream": False
        })
        masked_text = response.json()['response'].strip()
        
        has_violation = "[DADO_SENSÍVEL_REMOVIDO]" in masked_text
        return masked_text, has_violation
    except Exception as e:
        print(f"\n[ERRO LLM] Falha ao conectar no Ollama: {e}")
        # Princípio Fail-Safe: Se o DLP falhar, bloqueia o dado por precaução
        return "[ERRO_INSPECAO_DLP]", True 

# ==========================================
# 2. MÓDULO DO KAFKA (CONSUMER THREAD)
# ==========================================
def kafka_consumer_thread(consumer, shared_key, my_id, target_id, chat_topic):
    consumer.subscribe([chat_topic])
    while True:
        msg = consumer.poll(1.0)
        
        if msg is None:
            continue
            
        if msg.error():
            # Ignora o aviso inofensivo de quando a sala ainda não existe no Kafka
            if msg.error().code() == KafkaError.UNKNOWN_TOPIC_OR_PART:
                continue
            
            print(f"\n[ERRO KAFKA]: {msg.error()}")
            print(f"[{my_id}]: ", end="", flush=True)
            continue
            
        try:
            payload = json.loads(msg.value().decode('utf-8'))
            
            # Só processa mensagens destinadas a este usuário e vindas do alvo correto
            if payload.get('to') == my_id and payload.get('from') == target_id:
                
                # Decifra e valida a integridade usando o crypto_aes.py
                texto_claro = decrypt(
                    ciphertext_b64=payload['ciphertext'],
                    nonce_b64=payload['nonce'],
                    key=shared_key
                )
                
                # Imprime a mensagem decifrada e repinta o prompt do usuário
                print(f"\n[{target_id}]: {texto_claro}")
                print(f"[{my_id}]: ", end="", flush=True)
                
        except MessageIntegrityError:
            # Captura a exceção específica do crypto_aes.py caso a Tag GCM falhe
            print(f"\n⚠️ [ALERTA DE SEGURANÇA]: Mensagem interceptada! O payload falhou na validação de integridade e foi descartado.")
            print(f"[{my_id}]: ", end="", flush=True)
        except Exception:
            # Ignora erros genéricos de parsing JSON (mensagens malformadas no tópico)
            pass

# ==========================================
# 3. LOOP PRINCIPAL (PRODUCER E CLI)
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="Chat Seguro E2EE com DLP")
    parser.add_argument("--my-id", required=True, help="Seu ID de Usuário")
    parser.add_argument("--target-id", required=True, help="ID do Destinatário")
    parser.add_argument("--chat", required=True, help="ID da Sala de Chat (Tópico)")
    args = parser.parse_args()

    print(f"--- Iniciando Chat Seguro ---")
    print(f"Logado como: {args.my_id} | Conversando com: {args.target_id} | Sala: {args.chat}")
    
    # 1. Deriva a chave compartilhada via HKDF (crypto_aes.py)
    try:
        shared_key = derive_shared_key(args.my_id, args.target_id)
    except Exception as e:
        print(f"Erro crítico ao derivar chaves: {e}")
        return

    # 2. Configura os Clientes Kafka
    producer = Producer({'bootstrap.servers': 'localhost:9092'})
    consumer = Consumer({
        'bootstrap.servers': 'localhost:9092',
        'group.id': f'group_{args.my_id}',
        'auto.offset.reset': 'earliest' # Restaura backup do chat
    })

    # 3. Inicia a escuta de mensagens em background
    threading.Thread(
        target=kafka_consumer_thread, 
        args=(consumer, shared_key, args.my_id, args.target_id, args.chat), 
        daemon=True
    ).start()

    # 4. Loop de Digitação (Prompt)
    while True:
        try:
            texto_original = input(f"[{args.my_id}]: ")
            if texto_original.lower() in ['sair', 'exit', 'quit']:
                break
            
            # Pula envios vazios
            if not texto_original.strip():
                continue
                
            # Passo A: Inspeção Local (DLP via LLM)
            texto_mascarado, is_violation = inspect_and_mask_pii(texto_original)
            
            # Passo B: Disparo de Auditoria para o Security Monitor
            if is_violation:
                alerta = {
                    "alert_type": "PII_DETECTED_BLOCKED",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "chatid": args.chat,
                    "user1id": args.my_id,
                    "user2id": args.target_id
                }
                producer.produce('security-logs', value=json.dumps(alerta).encode('utf-8'))
                print(f"⚠️ [AVISO LOCAL]: Sua mensagem continha dados sensíveis e foi mascarada antes do envio.")
            
            # Passo C: Criptografia AES-GCM (crypto_aes.py)
            envelope = encrypt(texto_mascarado, shared_key)
            
            # Passo D: Envio para o Kafka com Base64
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