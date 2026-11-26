# Histórias de Usuário (US's)

## Introdução

<div align="justify">&emsp;&emsp;
As histórias de usuário são utilizadas para descrever de forma simples e objetiva as necessidades dos usuários dentro do sistema. Elas têm como foco apresentar o ponto de vista do usuário final, permitindo que a equipe de desenvolvimento compreenda claramente quais funcionalidades devem ser implementadas e qual valor será entregue. Esse método facilita a comunicação entre os envolvidos no projeto e garante que os requisitos estejam alinhados com as expectativas reais.
</div>

## Objetivo

<div align="justify">&emsp;&emsp;
O objetivo principal das histórias de usuário é registrar e organizar as funcionalidades do sistema a partir da perspectiva do usuário, promovendo clareza e priorização das entregas. Dessa forma, é possível assegurar que cada funcionalidade agregue valor, mantenha o foco no usuário final e apoie o desenvolvimento incremental e iterativo do software.
</div>

## Metodologia

<div align="justify">&emsp;&emsp;
A metodologia adotada segue o padrão ágil, onde as histórias de usuário são escritas no formato: "Como [tipo de usuário], eu quero [funcionalidade] para [benefício esperado]". Cada história é complementada por critérios de aceitação, que especificam as condições necessárias para que a entrega seja considerada concluída.
</div>

---

## Histórias

---

### US01 - Comunicação P2P Baseada em IDs

**Como** usuário, **quero** me conectar ao chat informando meu ID e o ID do destinatário **para que** eu possa estabelecer uma comunicação privada e direcionada com outro computador da rede.

#### Critérios de Aceitação

- [x] O cliente de chat deve permitir a configuração via terminal dos parâmetros `--my-id` e `--target-id`.
- [x] As mensagens devem ser enviadas e organizadas na sala de chat (tópico Kafka) especificada pelos usuários.
- [x] O sistema deve exibir as mensagens formatando quem é o remetente e quem é o destinatário no terminal.

---

### US02 - Mascaramento Automático de Dados Sensíveis (DLP Local)

**Como** usuário, **quero** que o sistema identifique e oculte automaticamente meus dados pessoais **para que** eu não tenha como compartilhar ou vaze informações sensíveis (como CPFs e cartões de crédito) acidentalmente na rede.

#### Critérios de Aceitação

- [x] O sistema deve interceptar a mensagem original antes do envio à rede.
- [x] O motor de IA (LLM via Ollama) deve processar a mensagem e identificar dados sensíveis pelo contexto.
- [x] Os dados sensíveis identificados devem ser substituídos por tags de mascaramento (ex: `[DADO_SENSÍVEL_REMOVIDO]`).
- [x] A mensagem mascarada deve manter o sentido original da conversa, removendo estritamente a Informação Pessoal Identificável (PII).

---

### US03 - Confidencialidade via Criptografia E2EE

**Como** usuário, **quero** que minhas mensagens sejam criptografadas antes de saírem do meu computador **para que** os administradores da rede, provedores ou interceptadores não consigam ler o conteúdo das minhas conversas.

#### Critérios de Aceitação

- [x] A mensagem, após ser higienizada pelo DLP, deve ser cifrada utilizando o algoritmo AES-256 no modo GCM (biblioteca `cryptography`).
- [x] O *broker* Apache Kafka deve receber e armazenar estritamente o *ciphertext* (dado ininteligível).
- [x] O processo de cifragem e decifragem deve utilizar chaves derivadas ou compartilhadas exclusivamente entre os IDs envolvidos na comunicação.

---

### US04 - Integridade dos Dados em Trânsito

**Como** usuário, **quero** ter a garantia criptográfica de que as mensagens recebidas são autênticas **para que** eu tenha certeza de que o conteúdo não foi alterado ou corrompido no servidor ou durante a transmissão.

#### Critérios de Aceitação

- [x] O modo de criptografia (AES-GCM) deve gerar um *nonce* e uma *tag* de autenticação para cada mensagem.
- [x] O receptor deve validar a *tag* de autenticação no momento da decifragem.
- [x] O sistema deve rejeitar ou emitir um erro crítico caso detecte que o *ciphertext* foi adulterado no Kafka.

---

### US05 - Restauração de Histórico (Backup Contínuo)

**Como** usuário, **quero** que o histórico do chat seja recuperado automaticamente ao iniciar o sistema **para que** eu não perca o contexto da conversa após fechar o programa.

#### Critérios de Aceitação

- [x] O sistema deve consumir as mensagens retidas no tópico do Apache Kafka desde o início ao ser inicializado.
- [x] O processo de restauração deve decifrar e exibir apenas o histórico pertinente à dupla de comunicação.
- [x] As mensagens restauradas do histórico já devem estar higienizadas/mascaradas, comprovando que o dado sensível não foi retido na infraestrutura de backup.

---

### US06 - Auditoria e Monitoramento de Segurança

**Como** administrador/auditor de segurança, **quero** receber alertas gerados pelo sistema sobre infrações de privacidade **para que** eu possa rastrear e monitorar tentativas de vazamento de dados na organização.

#### Critérios de Aceitação

- [x] O cliente de chat, ao detectar um PII via LLM (US02), deve disparar um evento estruturado em JSON para um tópico segregado no Kafka (ex: `security-logs`).
- [x] O log de auditoria deve conter os metadados da infração: tipo do dado ou tipo do alerta, timestamp, ID do remetente e ID do destinatário.
- [x] **Requisito Crítico (Minimização):** O log enviado ao servidor de monitoramento **não pode**, sob nenhuma circunstância, conter a string do dado sensível em claro.

---

### US07 - Processamento Descentralizado e Local (Privacy by Design)

**Como** usuário focado em privacidade, **quero** que toda a inspeção de IA ocorra localmente na minha máquina **para que** meus textos em claro nunca sejam enviados para APIs na nuvem de empresas terceiras.

#### Critérios de Aceitação

- [x] O processamento do modelo de linguagem (LLM) que atua como DLP deve ser realizado estritamente pelo Ollama hospedado em ambiente local.
- [x] O script Python não deve realizar requisições HTTP para APIs externas (ex: OpenAI, Google Cloud, AWS) durante o fluxo de mensageria e inspeção.
