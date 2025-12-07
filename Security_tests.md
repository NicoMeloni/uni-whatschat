Guia de Validação de Segurança (Testes de Ataque)
Esta seção descreve como executar os scripts de "Exploit" desenvolvidos para validar os requisitos de segurança do projeto: Autenticidade (bloqueio de conexões não autorizadas) e Integridade (detecção de adulteração de mensagens).

    Pré-requisitos
Certifique-se de estar no ambiente Linux (WSL) e de ter instalado as dependências:

Bash

pip install -r requirements.txt
Antes de iniciar os testes, é necessário gerar as credenciais para os usuários envolvidos (Vítima e Atacante):

# Gera certificados para o usuário legítimo (Bob)
python3 create_user.py bob

# Gera certificados para o atacante (Mallory)
python3 create_user.py mallory

    Cenário 1: Teste de Autenticidade
Objetivo: Demonstrar que o servidor implementa mTLS (Mutual TLS) corretamente e rejeita qualquer conexão de clientes que não possuam um certificado digital válido assinado pela CA do projeto.

    Como Executar
1. Inicie o Servidor (Terminal 1):
cd src
python3 server.py

2. Execute o Ataque (Terminal 2): Este script, localizado na raiz do projeto, tenta realizar duas conexões ilegais: uma sem criptografia (TCP puro) e outra com SSL mas sem enviar certificado.

# Certifique-se de estar na raiz do projeto (fora da pasta src)
python3 test_attack_auth.py

    Resultado Esperado
No terminal do ataque, o script deve reportar [SUCESSO] nas falhas de conexão, confirmando que o servidor barrou o acesso:

[ATAQUE 1] Tentando conectar sem SSL (TCP puro)...
[SUCESSO] Conexão rejeitada/fechada pelo servidor: [Errno 104] Connection reset by peer

[ATAQUE 2] Tentando SSL sem certificado de cliente...
[SUCESSO] O Handshake TLS falhou (O servidor exigiu certificado): ...

    Cenário 2: Teste de Integridade (Ataque Man-in-the-Middle)
Objetivo: Demonstrar que, mesmo que um atacante autenticado (Mallory) intercepte o canal, ele não consegue forjar mensagens válidas. O sistema deve detectar que o HMAC da mensagem não corresponde ao conteúdo alterado.

    Como Executar
Você precisará de 3 terminais abertos simultaneamente.

1. Inicie o Servidor (Terminal 1): (Se já estiver rodando, pode manter)

cd src
python3 server.py

2. Inicie a Vítima "Bob" (Terminal 2): Este cliente ficará online aguardando mensagens.

cd src
python3 client.py bob
Mantenha este terminal visível.

3. Execute o Ataque "Mallory" (Terminal 3): O script simula a Mallory enviando uma mensagem com conteúdo falso ("transfira dinheiro") mas tentando usar a assinatura digital de uma mensagem válida ("oi bob").

# Na raiz do projeto
python3 test_attack_integrity.py

    Verificação do Alerta
O script de ataque enviará o pacote malicioso e ficará pausado com a mensagem: >>> Pressione ENTER aqui SÓ DEPOIS de tirar o print no Bob...

Não aperte ENTER ainda. Vá para o terminal do Bob (Terminal 2).

Na lista de usuários, selecione mallory (use as setas) e aperte ENTER para abrir o chat.

    Resultado Esperado
Na tela de chat do Bob, o sistema deve exibir um alerta vermelho, provando que a quebra de integridade foi detectada:

! ALERTA: INTEGRIDADE FALHOU
(ou [ALERTA DE SEGURANÇA]: MENSAGEM FALSA RECEBIDA)

Após confirmar o alerta e tirar o print, volte ao Terminal 3 e pressione ENTER para encerrar o ataque.