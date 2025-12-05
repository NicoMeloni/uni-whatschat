# Uni-WhatsChat - Sistema de Chat Seguro

## 📋 Descrição

Uni-WhatsChat é um sistema de chat em tempo real que implementa múltiplas camadas de segurança para garantir autenticidade, confidencialidade e integridade das comunicações. O sistema utiliza tecnologias criptográficas modernas para proteger as mensagens trocadas entre usuários.

## 🔐 Funcionalidades de Segurança

### 1. Autenticação Mútua (mTLS)
- **TLS Bidirecional**: Tanto o servidor quanto os clientes se autenticam mutuamente usando certificados X.509
- **Autoridade Certificadora (CA)**: Sistema de PKI (Public Key Infrastructure) com CA própria
- **Verificação de Identidade**: Cada usuário possui um certificado único assinado pela CA

### 2. Troca de Chaves Diffie-Hellman (DH)
- **Perfect Forward Secrecy**: Chaves de sessão únicas para cada conexão
- **Parâmetros DH de 2048 bits**: Nível de segurança adequado para aplicações modernas
- **Derivação HKDF**: Transformação segura do segredo compartilhado em chave utilizável

### 3. Verificação de Integridade (HMAC)
- **HMAC-SHA256**: Algoritmo criptográfico robusto para verificação de integridade
- **Proteção contra Modificação**: Detecta qualquer alteração nas mensagens durante a transmissão
- **Autenticação de Mensagens**: Garante que a mensagem veio do remetente correto

## 📦 Requisitos

### Software Necessário
- **Python 3.8+**: Linguagem de programação principal
- **OpenSSL**: Para geração de certificados (versão 1.1.1 ou superior)

### Dependências Python
- `cryptography >= 41.0.0`: Biblioteca criptográfica
- `colorama >= 0.4.6`: Formatação colorida no terminal

## 🚀 Instalação

### 1. Clone ou baixe o projeto
```bash
cd uni-whatschat
```

### 2. Instale as dependências Python
```bash
pip install -r requirements.txt
```

### 3. Verifique se o OpenSSL está instalado
```bash
openssl version
```

**Instalação do OpenSSL:**
- **Windows**: Baixe de https://slproweb.com/products/Win32OpenSSL.html
- **Linux**: `sudo apt-get install openssl` (Ubuntu/Debian) ou `sudo yum install openssl` (RHEL/CentOS)
- **macOS**: `brew install openssl`

## 🔧 Configuração

### 1. Gerar Certificados da CA e do Servidor
```bash
python setup_certs.py
```

Este script cria:
- `certs/ca.crt` e `certs/ca.key`: Certificados da Autoridade Certificadora
- `certs/server.crt` e `certs/server.key`: Certificados do servidor

### 2. Criar Usuários
Para cada usuário que deseja usar o sistema:
```bash
python create_user.py <username>
```

Exemplo:
```bash
python create_user.py alice
python create_user.py bob
python create_user.py charlie
```

Isso cria os certificados:
- `certs/<username>.crt`: Certificado do usuário
- `certs/<username>.key`: Chave privada do usuário

## 💻 Uso

### Iniciar o Servidor

Em um terminal, execute:
```bash
python -m src.server
```

Você verá mensagens como:
```
[SISTEMA]: Servidor iniciado em 127.0.0.1:8443
[SISTEMA]: Aguardando conexões...
```

### Conectar Clientes

Em terminais separados, para cada usuário:
```bash
python -m src.client <username>
```

Exemplo:
```bash
# Terminal 2
python -m src.client alice

# Terminal 3
python -m src.client bob

# Terminal 4
python -m src.client charlie
```

### Enviar Mensagens

Após conectar, digite suas mensagens e pressione Enter. Para sair, digite `quit`, `exit` ou `sair`.

**Exemplo de sessão:**
```
[SISTEMA]: Conectado ao servidor 127.0.0.1:8443
[SISTEMA]: Troca de chaves iniciada...
[SISTEMA]: Troca de chaves concluída! Comunicação segura estabelecida.
[SISTEMA]: Bem-vindo, alice!
[SISTEMA]: Digite suas mensagens (ou 'quit' para sair):

Olá pessoal!
[alice (Verificado)]: Olá pessoal!
[bob (Verificado)]: Oi alice!
```

## 🏗️ Arquitetura

### Estrutura de Diretórios
```
uni-whatschat/
├── src/
│   ├── __init__.py
│   ├── server.py          # Servidor principal
│   ├── client.py          # Cliente principal
│   ├── crypto.py          # Funções criptográficas (DH, HMAC)
│   ├── network.py         # Configuração SSL/TLS
│   ├── protocol.py        # Protocolo de comunicação
│   └── utils.py           # Utilitários (cores, mensagens)
├── certs/                 # Diretório de certificados
│   ├── ca.crt             # Certificado da CA
│   ├── ca.key             # Chave privada da CA
│   ├── server.crt         # Certificado do servidor
│   ├── server.key         # Chave privada do servidor
│   ├── alice.crt           # Certificado do usuário alice
│   ├── alice.key           # Chave privada do usuário alice
│   └── ...                # Outros usuários
├── setup_certs.py         # Script de configuração de certificados
├── create_user.py         # Script para criar usuários
├── test_connection.py     # Script de teste de conexão
├── requirements.txt       # Dependências Python
└── README.md             # Este arquivo
```

### Fluxo de Comunicação

1. **Conexão TLS**:
   - Cliente inicia conexão TCP
   - Handshake TLS com autenticação mútua (mTLS)
   - Verificação de certificados em ambos os lados

2. **Troca de Chaves Diffie-Hellman**:
   - Cliente gera par de chaves DH
   - Cliente envia chave pública para o servidor
   - Servidor gera seu par de chaves DH
   - Servidor envia chave pública para o cliente
   - Ambos calculam o segredo compartilhado
   - Segredo é derivado usando HKDF

3. **Envio de Mensagens**:
   - Cliente cria mensagem
   - Gera HMAC da mensagem usando chave compartilhada
   - Empacota mensagem + HMAC em JSON
   - Envia via conexão TLS
   - Servidor verifica HMAC
   - Servidor reenvia para outros clientes

## 🔒 Detalhes de Segurança

### Autenticação Mútua (mTLS)
- O servidor verifica o certificado do cliente
- O cliente verifica o certificado do servidor
- Ambos confiam na mesma CA
- Conexões sem certificado válido são rejeitadas

### Diffie-Hellman
- **Tamanho da chave**: 2048 bits
- **Gerador**: 2 (padrão seguro)
- **Derivação**: HKDF-SHA256 com info específico
- **Perfect Forward Secrecy**: Cada sessão tem chave única

### HMAC
- **Algoritmo**: HMAC-SHA256
- **Tamanho da chave**: 32 bytes (256 bits)
- **Comparação segura**: Usa `hmac.compare_digest()` para evitar timing attacks

### Protocolo de Mensagens
- **Formato**: JSON
- **Codificação**: UTF-8
- **Delimitador**: `\n` (newline)
- **Tipos de pacote**:
  - `KEY_EXCHANGE`: Troca de chaves DH
  - `MSG`: Mensagem de chat

## 🧪 Testes

### Teste de Conexão Básica
```bash
python test_connection.py
```

Este script testa:
- Criação de contexto SSL
- Handshake TLS
- Autenticação mútua
- Extração de identidade do certificado

### Teste Manual
1. Inicie o servidor
2. Conecte múltiplos clientes
3. Envie mensagens entre eles
4. Verifique que as mensagens aparecem com `(Verificado)`
5. Teste desconexão e reconexão

## ⚠️ Limitações e Considerações

### Limitações Atuais
1. **Parâmetros DH**: Cliente e servidor geram parâmetros separadamente (funciona, mas idealmente o servidor deveria enviar)
2. **Sem criptografia de mensagens**: Mensagens são protegidas apenas por integridade (HMAC), não por confidencialidade adicional
3. **Sem persistência**: Mensagens não são armazenadas
4. **Sem histórico**: Não há histórico de conversas
5. **Rede local**: Configurado para `127.0.0.1` (localhost)

### Melhorias Futuras
- Criptografia de mensagens com AES usando chave derivada do DH
- Persistência de mensagens
- Histórico de conversas
- Suporte a grupos/chat rooms
- Interface gráfica (GUI)
- Suporte a rede externa com configuração de firewall

## 🐛 Solução de Problemas

### Erro: "Certificados não encontrados"
**Solução**: Execute `python setup_certs.py` primeiro

### Erro: "OpenSSL não encontrado"
**Solução**: Instale o OpenSSL e certifique-se de que está no PATH

### Erro: "Erro SSL ao aceitar conexão"
**Possíveis causas**:
- Certificado do cliente inválido ou não assinado pela CA
- Certificado expirado
- Chave privada não corresponde ao certificado

**Solução**: 
- Verifique se o certificado foi criado corretamente
- Recrie o certificado: `python create_user.py <username>`

### Mensagens não aparecem
**Possíveis causas**:
- Troca de chaves não concluída
- Chave compartilhada não estabelecida

**Solução**:
- Aguarde alguns segundos após conectar
- Verifique as mensagens do sistema sobre troca de chaves

### Erro: "Mensagem falhou na verificação de integridade"
**Causa**: HMAC não corresponde (mensagem foi modificada ou chave incorreta)

**Solução**: 
- Verifique se ambos os lados completaram a troca de chaves
- Reconecte o cliente

## 📚 Referências

### Documentação Técnica
- **TLS/mTLS**: RFC 8446 (TLS 1.3)
- **Diffie-Hellman**: RFC 3526
- **HMAC**: RFC 2104
- **HKDF**: RFC 5869

### Bibliotecas Utilizadas
- **cryptography**: https://cryptography.io/
- **Python SSL**: https://docs.python.org/3/library/ssl.html

## 👥 Autores

Trabalho desenvolvido para a disciplina de Segurança Computacional - UNB

## 📄 Licença

Este projeto é um trabalho acadêmico desenvolvido para fins educacionais.

---

**Versão**: 1.0  
**Última atualização**: 2024


