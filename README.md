# TCC-PoC3 Prevenção de Perda de Dados (DLP) com Mascaramento de PII

| Aluno                             | Matrícula |
| --------------------------------- | --------- |
| Eduardo Matheus dos Santos Sandes | 221008024 |
| Vinícius de Oliveira Santos       | 202017263 |

Esta Prova de Conceito (PoC) tem como objetivo demonstrar a aplicação do *softgoal* **Segurança [Dados]**, fundamentado no Art. 6º, inciso VII da LGPD, através da tríade CIA de segurança da informação: **Confidencialidade**, **Integridade** e **Disponibilidade**. A PoC avalia a viabilidade de um sistema de comunicação entre computadores (chat) utilizando o *broker* Apache Kafka, operando com **Criptografia Simétrica (AES)** de ponta a ponta e um motor de Inteligência Artificial local (NLP) para inspeção e mascaramento de Dados Pessoais Identificáveis (PII) antes da cifragem, garantindo também a **Auditoria** de tentativas de vazamento sem expor o dado sensível.

## Objetivos da PoC

1. **Confidencialidade [Dados] via Criptografia:** Implementar o *softgoal* **Criptografia [Dados]** por meio da operacionalização **Aplicar Advanced Encryption Standard (AES)** (criptografia simétrica), garantindo que os dados em trânsito e em repouso no Kafka sejam ininteligíveis para partes não autorizadas.
2. **Confidencialidade [Dados] via Auditoria:** Operacionalizar a **Auditoria [Manipulação dos Dados]** através de um terminal de monitoramento que registra tentativas de compartilhamento de dados sigilosos (gerando rastreabilidade), respeitando o princípio da minimização.
3. **Integridade e Disponibilidade [Dados]:** Assegurar os *softgoals* **Recuperação [Dados]** (através de **Fazer Backup**) e **Disponibilidade [Dados]** (através de **Restaurar Backup**), utilizando a retenção nativa do Kafka para armazenar o histórico e restaurar a conversa com exatidão a cada inicialização do sistema.

4. **Minimização [Dados] e Minimização [Dano] via DLP Local** Utilizar processamento de linguagem natural local para identificar e mascarar PII (ex: CPF, cartão de crédito) na máquina do remetente, impedindo que a informação sensível seja transmitida à rede. Satisfaz as operacionalisações **Minimizar com Agente de IA**, filho de **Minimização [Dano]** e **A ser inventado**, filho de **Minimização do Raio de Impacto**.

## Arquitetura e Fluxo de Dados

O processo está dividido em 5 etapas lineares (ver `docs/arquitetura.md` para o detalhamento técnico completo):

1. **Inspeção e Mascaramento (DLP via LLM):** O usuário digita uma mensagem no cliente de chat, direcionada a um destinatário específico (via ID). A mensagem passa por uma inferência do modelo local (ex: `llama3` ou `phi3`) instruído a atuar como um firewall de privacidade. O LLM detecta entidades sensíveis pelo contexto e retorna a mensagem mascarada (ex: `[DADO_SENSÍVEL_REMOVIDO]`).
2. **Auditoria e Alerta de Segurança:** Caso o LLM identifique dados sensíveis na requisição original, o cliente envia silenciosamente um log estruturado em JSON para um tópico de monitoramento (`security-logs`) no Kafka, contendo os metadados da violação (`alert_type`, `timestamp`, `chatid`, `user1id`, `user2id`).
3. **Criptografia E2EE (`cryptography`):** A mensagem (agora higienizada) é submetida à **Criptografia Simétrica AES-256 no modo GCM** utilizando uma chave derivada compartilhada exclusivamente entre o remetente e o destinatário escolhido. 
4. **Mensageria e Retenção (`Kafka`):** O *ciphertext* (junto ao *nonce* e à *tag* de autenticação gerada pelo GCM) é enviado para o tópico de comunicação (ex: `chat-room-123`). O broker Kafka atua armazenando os dados cifrados e mascarados de forma imutável, consolidando o mecanismo de backup contínuo.
5. **Recepção e Restauração:** Ao iniciar o cliente e definir o alvo da conversa, o usuário receptor consome as mensagens passadas do tópico Kafka. Utilizando a chave simétrica AES correspondente àquela dupla de IDs, o cliente verifica a integridade e decifra as mensagens para exibi-las. Como o dado foi mascarado na origem pelo LLM, o receptor vê apenas a informação higienizada.

---

## Documentação

- `docs/arquitetura.md`: detalhamento técnico da mensageria (Kafka), fluxo E2EE (AES-GCM) e do *prompt engineering* para o DLP via LLM.
- `docs/historias-de-usuario.md`: histórias de usuário que orientaram os requisitos de privacidade e comunicação (*Peer-to-Peer* simulado).

---

## Estrutura de Diretórios

O repositório segue a seguinte estrutura:

```text
root/
│
├── docs/
│   ├── historias-de-usuario.md
│   └── arquitetura.md                 # Detalhamento do Kafka, AES-GCM e Ollama
│
├── src/
│   ├── chat_client.py                 # Interface do chat (Terminal) 
│   ├── security_monitor.py            # Central de logs/auditoria (topico 'security-logs')
│   ├── dlp_llm.py                     # Módulo de NLP usando a API local do Ollama
│   ├── crypto_aes.py                  # Módulo de criptografia simétrica AES-GCM (cryptography)
│   └── test/                          # Scripts de teste manual por módulo
│
├── Dockerfile                         # Arquivo para subir o Apache Kafka localmente
├── docker-compose.yml                 # Arquivo para subir o Apache Kafka localmente
├── requirements.txt                   # Dependências do projeto em Python
└── README.md

```

## Como Executar

### Pré-requisitos

1. Certifique-se de ter o Python 3.8+ e o **Docker** instalados na sua máquina.
2. Certifique-se de ter o **Ollama** instalado e rodando.

Baixe o modelo leve recomendado para atuar como DLP (exemplo com o `llama3:8b`):

```bash
ollama pull llama3

```

### Configuração do Ambiente

1. Clone este repositório e navegue até a pasta do projeto:

```bash
git clone [git@github.com:TCC-Eduardo-Sandes-e-Vinicius-Santos/TCC-PoC3-Chat-com-Mascaramento-de-PII.git](git@github.com:TCC-Eduardo-Sandes-e-Vinicius-Santos/TCC-PoC3-Chat-com-Mascaramento-de-PII.git)
cd TCC-PoC3-Chat-com-Mascaramento-de-PII.git

```

2. Suba a infraestrutura do Apache Kafka usando o Docker:

```bash
docker-compose up -d
cd ..

```

3. Crie e ative um ambiente virtual Python:

```bash
python3 -m venv venv

# Para ativar no Windows:
venv\Scripts\activate
# Para ativar no Linux/Mac:
source venv/bin/activate

```

4. Instale as dependências:

```bash
pip install -r requirements.txt

```

5. Configure o segredo da derivação de chaves E2EE:

```bash
cp .env.example .env
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
# cole o valor gerado em POC3_HKDF_SALT no .env

```

Todos os clientes que conversam entre si precisam do **mesmo** `.env`, entregue por um canal fora do Kafka. O arquivo não é versionado e não deve ser copiado para o host do broker. Sem `POC3_HKDF_SALT`, o cliente se recusa a derivar chaves. As limitações desse modelo (segredo de grupo, sem *forward secrecy*) estão em `docs/arquitetura.md`.

### Executando a Prova de Conceito

Para simular o ambiente adequadamente e testar a escolha de destinatários, abra três instâncias de terminal:

**Terminal 1: Central de Monitoramento (Auditoria)**
Inicie o observador de logs que registrará as infrações de segurança interceptadas pelo LLM:

```bash
python3 src/security_monitor.py

```

**Terminal 2: Cliente do Usuário 1 (Remetente)**
Inicie o chat informando o seu próprio ID (`--my-id`), o ID da pessoa com quem deseja conversar (`--target-id`) e a sala:

```bash
python3 src/chat_client.py --my-id U-100 --target-id U-200 --chat C-555

```

**Terminal 3: Cliente do Usuário 2 (Destinatário)**
Inicie o chat configurando as chaves inversas para completar a comunicação bidirecional:

```bash
python3 src/chat_client.py --my-id U-200 --target-id U-100 --chat C-555

```

**Teste Prático:** Tente enviar um dado sensível (ex: *"Meu CPF é 123.456.789-10"*) no Terminal 2. A IA (Ollama) interceptará e reescreverá a mensagem localmente antes de cifrá-la usando o AES-GCM. O Terminal 3 exibirá apenas a versão mascarada da mensagem, e o Terminal 1 registrará o evento de alerta associando a tentativa ao ID `U-100`.

```
