# Arquitetura Técnica

## Introdução

<div align="justify">&emsp;&emsp;
Este documento descreve o funcionamento interno da PoC: os módulos que a compõem, como eles se comunicam, o fluxo de dados desde a digitação da mensagem pelo usuário até a persistência do *ciphertext* no Apache Kafka, e as decisões de design de segurança e privacidade adotadas em especial a atuação do LLM local como firewall de DLP (*Data Loss Prevention*) e a cifragem ponta a ponta com AES-256-GCM. Cabe ressaltar que a implentação prioriza aspectos relacionados à privacidade dos usuários, e que não compartilha dados com terceiros nem realiza transferência internacional com os dados envolvidos. Por fim, destaca-se que a finalidade do tratamento é viabilizar uma comunicação privada entre dois usários com mascaramento e cifragem das mensagens enviadas.
</div>

---

## Visão Geral dos Componentes

```text
┌───────────────────────────────┐                   ┌──────────────────────────────┐
│   chat_client.py (U-100)      │                   │   chat_client.py (U-200)     │
│                               │                   │                              │
│  ┌──────────┐   ┌───────────┐ │                   │ ┌──────────┐   ┌───────────┐ │
│  │dlp_llm.py│   │crypto_aes │ │                   │ │dlp_llm.py│   │crypto_aes │ │
│  │(inspeção)│   │(AES-GCM)  │ │                   │ │(inspeção)│   │(AES-GCM)  │ │
│  └────┬─────┘   └─────┬─────┘ │                   │ └────┬─────┘   └─────┬─────┘ │
└───────┼───────────────┼───────┘                   └──────┼───────────────┼───────┘
        │ HTTP local    │ produce/consume                  │ HTTP local    │ produce/consume
        ▼               ▼                                  ▼               ▼
┌─────────────────┐  ┌──────────────────────────────────────────────────────────┐
│ Ollama          │  │                     Apache Kafka (broker)                │
│ (llama3, local) │  │  tópico `chat-room-<chatid>`   tópico `security-logs`    │
│ localhost:11434 │  │  (ciphertext + nonce + tag)    (metadados de auditoria)  │
└─────────────────┘  └───────────────────────────────────┬──────────────────────┘
                                                         │ consume (security-logs)
                                                         ▼
                                                ┌───────────────────────────┐
                                                │  security_monitor.py      │
                                                │  (terminal de auditoria)  │
                                                └───────────────────────────┘
```

**Por que essa separação?** Cada cliente de chat é responsável por higienizar e cifrar a própria mensagem *antes* de qualquer contato com a rede - o Kafka nunca recebe texto em claro nem dados sensíveis, apenas *ciphertext* e, no tópico de auditoria, metadados sem o conteúdo da violação. O monitor de segurança é um processo independente, que só enxerga o tópico `security-logs`, nunca os tópicos de conversa (`chat-room-*`), reforçando o princípio de minimização também dentro da própria infraestrutura de auditoria.

---

## Módulos

### `crypto_aes.py` - Criptografia Simétrica Ponta a Ponta

Responsável por toda a cifragem/decifragem das mensagens de chat. Usa **AES-256 no modo GCM** (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`), por ser um modo *authenticated encryption* (AEAD): garante confidencialidade e integridade/autenticidade em uma única primitiva, sem exigir um HMAC separado.

| Método                                                    | Função                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `derive_shared_key(id_a: str, id_b: str)`                 | Ordena os dois IDs de forma determinística (`sorted([id_a, id_b])`) e deriva uma chave de 256 bits via **HKDF-SHA256** a partir da concatenação ordenada, garantindo que `derive_shared_key(U-100, U-200)` e `derive_shared_key(U-200, U-100)` produzam sempre a mesma chave. |
| `encrypt(plaintext: str, key: bytes)`                     | Gera um *nonce* aleatório de 96 bits (recomendado para GCM), cifra o `plaintext` com `AESGCM(key).encrypt(nonce, data, aad=None)` e retorna `{"ciphertext": ..., "nonce": ...}` em base64 - a *tag* de autenticação de 128 bits já vem concatenada ao final do *ciphertext* pela própria API do GCM.                    |
| `decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes)`| Decodifica de base64 e chama `AESGCM(key).decrypt(nonce, ciphertext, aad=None)`. Se a *tag* não bater (mensagem adulterada ou chave incorreta), a biblioteca levanta `InvalidTag`, que o `chat_client.py` trata como erro crítico de integridade.                          |

**Por que derivação por par de IDs, e não uma chave global:** se todos os pares de usuários compartilhassem a mesma chave simétrica, qualquer participante do sistema poderia decifrar qualquer conversa. Derivar a chave a partir do par `(id_a, id_b)` restringe criptograficamente o acesso ao *ciphertext* apenas aos dois IDs envolvidos naquela conversa - é essa chave, e não um controle de acesso da aplicação, que impede a leitura por terceiros, mesmo que consigam acesso de leitura ao tópico Kafka.

**Limitação assumida na PoC:** a derivação da chave depende apenas dos IDs, que são informados livremente via linha de comando (`--my-id`/`--target-id`), sem nenhum mecanismo de autenticação de identidade (não há *handshake* como Diffie-Hellman, nem verificação de posse de chave privada). Isso é suficiente para demonstrar o *softgoal* de Confidencialidade via AES, mas não substitui um protocolo de troca de chaves autenticado em um cenário de produção.

### `dlp_llm.py` - DLP Local via LLM

Encapsula a chamada ao Ollama (`llama3` ou `phi3`, conforme configuração) para inspecionar cada mensagem digitada e mascarar Dados Pessoais Identificáveis (PII) **antes** de qualquer serialização, cifragem ou envio à rede.

- `SYSTEM_PROMPT`: instrui o modelo a atuar estritamente como um firewall de privacidade - identificar PII **pelo contexto** (CPF, número de cartão de crédito, e-mail, telefone, endereço, entre outros), substituir cada ocorrência por uma tag padronizada (`[DADO_SENSÍVEL_REMOVIDO]`) e preservar o restante da frase sem alterar o sentido. O prompt é explícito ao proibir o modelo de responder à mensagem ou adicionar comentários - a saída deve ser **apenas** o texto reescrito.
- `inspect_and_mask(message: str) -> DlpResult`: monta a requisição para `http://localhost:11434/api/generate` (ou via `langchain_community.chat_models.ChatOllama`, conforme o restante da PoC), com `temperature` baixa (ex.: `0.0`–`0.1`) para reduzir variabilidade entre execuções, e devolve um `DlpResult` contendo `masked_message`, `was_masked: bool` e `alert_type` (categoria da PII detectada, ex.: `"CPF"`, `"CARTAO_CREDITO"`, `"GENERICO"`).
- `was_masked` é decidido comparando a mensagem original com a mensagem mascarada (`masked_message != message`) - é esse booleano que dispara (ou não) o evento de auditoria descrito em `security_monitor.py`.
- **Nunca há chamada de rede externa:** toda a inferência ocorre via HTTP para `localhost:11434`, cumprindo o requisito de **Processamento Descentralizado e Local** (US07) - o texto em claro do usuário nunca sai da própria máquina, nem mesmo para o Kafka.

**Por que usar um LLM em vez de regex/expressões regulares:** dados como CPF, cartão de crédito ou endereço frequentemente aparecem em formatos variados, abreviados ou embutidos em frases naturais ("meu documento termina em ..."), o que expressões regulares fixas tendem a não cobrir. O LLM interpreta a PII **pelo contexto semântico** da frase, e não apenas pelo formato do padrão, reduzindo falsos negativos ao custo de uma inferência local mais pesada que uma checagem por regex.

### `security_monitor.py` - Auditoria e Alerta de Segurança

Processo standalone que atua como consumidor Kafka dedicado ao tópico `security-logs`, funcionando como a central de monitoramento da infração de privacidade.

- **Publicação do evento (feita pelo `chat_client.py`, não por este módulo):** quando `dlp_llm.inspect_and_mask()` retorna `was_masked=True`, o cliente publica no tópico `security-logs` um JSON estruturado contendo `alert_type`, `timestamp` (UTC), `chatid`, `user1id` (remetente) e `user2id` (destinatário) - **nunca** o conteúdo da mensagem original ou mascarada.
- `SecurityMonitor.consume_and_print()`: assina o tópico `security-logs` desde o início (`auto_offset_reset="earliest"`) e imprime cada alerta recebido em um formato legível no terminal, permitindo ao operador correlacionar `user1id`/`user2id`/`chatid` sem nunca visualizar o dado sensível em si.
- O consumidor deste módulo **não** assina nenhum tópico `chat-room-*`: ele não tem acesso, nem por engano, ao conteúdo cifrado das conversas, apenas aos metadados de infração.

**Por que o log nunca carrega o dado sensível (Requisito Crítico, US06):** o objetivo da auditoria é permitir rastreabilidade de tentativas de vazamento - quem tentou enviar o quê, para quem e quando - sem recriar, no servidor de monitoramento, o mesmo problema de exposição de PII que o DLP foi criado para evitar. Registrar apenas a categoria (`alert_type`) e os metadados de identificação das partes é suficiente para auditoria e investigação, e satisfaz o princípio de minimização mesmo dentro do próprio mecanismo de segurança.

### `chat_client.py` - Orquestração e Interface (Terminal)

Não contém lógica de negócio própria - orquestra os três módulos acima a partir de uma interface de linha de comando, configurada via `argparse` (`--my-id`, `--target-id`, `--chat`).

**Fluxo de envio (por mensagem digitada):**
1. Lê o texto digitado pelo usuário no terminal.
2. Chama `dlp_llm.inspect_and_mask(texto)`. Se `was_masked=True`, publica silenciosamente (sem bloquear o envio) o evento de auditoria no tópico `security-logs`, conforme descrito em `security_monitor.py`.
3. Deriva a chave do par com `crypto_aes.derive_shared_key(my_id, target_id)` (cacheada em memória durante a sessão, para não recalcular o HKDF a cada mensagem).
4. Cifra a mensagem **já higienizada** (nunca a original) com `crypto_aes.encrypt(masked_message, key)`.
5. Publica `{"ciphertext": ..., "nonce": ..., "sender": my_id}` no tópico Kafka `chat-room-<chatid>`.

**Fluxo de recepção / restauração de histórico (US05):**
1. Ao iniciar, o cliente assina o tópico `chat-room-<chatid>` com `auto_offset_reset="earliest"`, consumindo desde o primeiro registro retido pelo Kafka - é essa retenção nativa do broker que implementa o backup contínuo do histórico.
2. Para cada mensagem consumida, deriva a mesma chave do par (`derive_shared_key`) e chama `crypto_aes.decrypt(...)`.
3. Se a decifragem falhar por `InvalidTag`, o cliente trata o evento como violação de integridade (mensagem adulterada) e não a exibe como texto válido - em vez de arriscar mostrar um *ciphertext* corrompido decifrado incorretamente.
4. Mensagens do próprio remetente (`sender == my_id`) e do destinatário (`sender == target_id`) são diferenciadas na exibição em terminal (ex.: prefixo `[Eu]` vs. `[target_id]`).

**Importante:** como a mensagem só é cifrada **depois** de passar pelo `dlp_llm.py`, o histórico restaurado do Kafka (passo de recepção) é, por construção, sempre a versão já mascarada - o dado sensível em claro nunca chega a existir fora da memória volátil do processo que o digitou, cumprindo o critério de aceitação da US05 de que o backup nunca retém PII.

---

## Modelo de Ameaças (resumo)

| Ameaça                                                                    | Mitigação atual                                                                                          | Limitação conhecida                                                                                                             |
| ---------------------------------------------------------------------------| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------|
| Vazamento de PII na rede/broker                                          | `dlp_llm.py` intercepta e mascara a mensagem **antes** de qualquer cifragem ou envio ao Kafka            | Detecção depende da capacidade do LLM local; falsos negativos (PII não reconhecida pelo modelo) não são mascarados              |
| Interceptação do canal (MITM) / leitura do conteúdo no broker            | AES-256-GCM E2EE - o Kafka só armazena *ciphertext*, *nonce* e *tag*                                     | Derivação de chave por par de IDs sem *handshake* autenticado (sem Diffie-Hellman nem verificação de identidade)                |
| Adulteração de mensagens em trânsito ou em repouso no Kafka              | *Tag* de autenticação do GCM é validada na decifragem; falha gera `InvalidTag` e a mensagem é rejeitada  | Não há proteção dedicada contra *replay* (reenvio de uma mensagem cifrada antiga válida) no protocolo desta PoC                 |
| Vazamento de PII pelo próprio canal de auditoria                         | `security-logs` carrega apenas metadados (`alert_type`, `timestamp`, `chatid`, `user1id`, `user2id`)     | Requisito Crítico (US06) depende de o LLM nunca ecoar o dado sensível no campo `alert_type`; não há segunda camada de verificação |
| Retenção indevida de PII no backup (retenção nativa do Kafka)            | Apenas mensagens já higienizadas e cifradas chegam a ser publicadas em `chat-room-*`                     | Se o DLP falhar silenciosamente, o dado sensível cifrado fica retido indefinidamente, sem mecanismo de expurgo (*purge*) na PoC  |
| Personificação de identidade (qualquer processo pode se declarar `U-100`)| -                                                                                                         | `--my-id`/`--target-id` são informados livremente via CLI, sem autenticação; fora do escopo desta PoC de DLP/E2EE               |

---

## Dependências Externas

| Componente          | Papel                                                                          | Observação                                                                                          |
| -------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Apache Kafka**      | *Broker* de mensageria; transporta e retém `chat-room-<chatid>` e `security-logs` | Subido via `docker-compose.yml`/`Dockerfile`; retenção nativa do tópico implementa o backup contínuo (US05) |
| **Ollama**            | Serve o LLM (`llama3`/`phi3`) localmente via HTTP (`localhost:11434`)          | Requer instalação e `ollama pull` separados; único uso de inferência de IA da PoC, 100% local (US07)      |
| **cryptography**      | Implementa `AESGCM` para a cifragem/decifragem simétrica ponta a ponta         | Also usada para a derivação de chave (HKDF-SHA256) a partir do par de IDs                              |
| **kafka-python** (ou equivalente) | Cliente Python para produzir/consumir mensagens no Kafka             | Usado tanto em `chat_client.py` quanto em `security_monitor.py`                                        |