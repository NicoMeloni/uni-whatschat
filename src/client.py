import socket
import threading
import sys
import ssl
import os
import time

# Importações dos nossos módulos
from network import create_client_ssl_context
from protocol import (
    send_packet, recv_packet, parse_packet,
    create_message_packet, create_key_exchange_packet
)
from crypto import (
    generate_dh_parameters, generate_dh_keys, 
    compute_shared_secret, generate_hmac, verify_hmac,
    load_pem_public_key
)
from utils import (
    print_security_alert, print_verified_message, print_system_info
)

# Configurações
HOST = '127.0.0.1'
PORT = 8443
CERTS_DIR = "../certs"
CA_PATH = f"{CERTS_DIR}/ca.crt"

# Estado Global do Cliente
my_username = ""
client_socket = None
# Armazena as chaves de sessão: {'Bob': b'segredo_compartilhado_xyz...'}
session_keys = {} 
# Armazena minha chave privada temporária para terminar o handshake: {'Bob': private_key_obj}
temp_private_keys = {}

def receive_messages():
    """Thread que fica ouvindo mensagens do servidor o tempo todo."""
    while True:
        try:
            raw_data = recv_packet(client_socket)
            if not raw_data:
                print_security_alert("Conexão com o servidor perdida!")
                os._exit(1) # Mata o programa se cair a conexão
            
            packet = parse_packet(raw_data)
            msg_type = packet.get("type")
            sender = packet.get("sender")

            if msg_type == "MSG":
                handle_incoming_chat(sender, packet)
            
            elif msg_type == "DH_EXCHANGE":
                handle_key_exchange(sender, packet)
            
            elif msg_type == "LIST_RESP":
                users = packet.get("users", [])
                print_system_info(f"Usuários Online: {', '.join(users)}")
                
            elif msg_type == "ERROR":
                print_security_alert(f"Erro do Servidor: {packet.get('message')}")

        except Exception as e:
            print_security_alert(f"Erro na recepção: {e}")
            break

def handle_key_exchange(sender, packet):
    """
    Lida com o recebimento de chave pública (Handshake Diffie-Hellman).
    Funciona tanto para quem RECEBE o pedido quanto para quem INICIOU.
    """
    peer_pub_pem_str = packet.get("public_key")
    if not peer_pub_pem_str:
        return

    # Converte string PEM de volta para bytes para a lib de criptografia
    peer_pub_bytes = peer_pub_pem_str.encode('utf-8')

    # Cenário 1: Eu sou o Bob e a Alice quer falar comigo (Não tenho chave privada pra ela ainda)
    if sender not in temp_private_keys:
        print_system_info(f"Recebida solicitação de canal seguro de {sender}...")
        
        # 1. Extraio os parâmetros DH da chave dela (para ser compatível)
        peer_pub_obj = load_pem_public_key(peer_pub_bytes)
        params = peer_pub_obj.parameters()
        
        # 2. Gero meu par de chaves usando os mesmos parâmetros
        my_priv, my_pub_bytes = generate_dh_keys(params)
        
        # 3. Calculo o segredo final
        shared_secret = compute_shared_secret(my_priv, peer_pub_bytes)
        session_keys[sender] = shared_secret
        
        # 4. Envio minha chave pública de volta para completar o ciclo
        resp_packet = create_key_exchange_packet(my_username, sender, my_pub_bytes)
        send_packet(client_socket, resp_packet)
        
        print_system_info(f"Chaves trocadas! Canal seguro estabelecido com {sender}.")
    
    # Cenário 2: Eu sou a Alice, iniciei o papo e o Bob respondeu
    else:
        # Recupero a chave privada que guardei quando mandei o convite
        my_priv = temp_private_keys.pop(sender)
        
        # Calculo o segredo final
        shared_secret = compute_shared_secret(my_priv, peer_pub_bytes)
        session_keys[sender] = shared_secret
        print_system_info(f"Handshake concluído! Canal seguro pronto com {sender}.")

def handle_incoming_chat(sender, packet):
    """Verifica a integridade (HMAC) e exibe a mensagem."""
    content = packet.get("content")
    received_hmac = packet.get("hmac")
    
    # Verifica se temos um segredo compartilhado com esse remetente
    if sender not in session_keys:
        print_security_alert(f"Mensagem recebida de {sender} SEM sessão segura estabelecida. Ignorada.")
        return

    secret = session_keys[sender]
    
    # --- VERIFICAÇÃO DE INTEGRIDADE (O Requisito do HMAC) ---
    is_valid = verify_hmac(secret, content, received_hmac)
    
    if is_valid:
        print_verified_message(sender, content)
    else:
        print_security_alert(f"MENSAGEM VIOLADA DE {sender}! HMAC inválido. O conteúdo pode ter sido alterado.")

def start_chat_initiation(target_user):
    """
    Inicia o processo de troca de chaves (Diffie-Hellman) com outro usuário.
    """
    if target_user == my_username:
        print_security_alert("Você não pode falar consigo mesmo.")
        return

    print_system_info(f"Iniciando negociação de chaves com {target_user}...")
    
    # 1. Gera parâmetros e chaves (pode demorar um pouco se for 2048 bits)
    # Nota: Em produção real, os parametros p e g seriam fixos/carregados de arquivo para ser rápido.
    params = generate_dh_parameters() 
    my_priv, my_pub_bytes = generate_dh_keys(params)
    
    # 2. Guarda a privada temporariamente esperando a resposta
    temp_private_keys[target_user] = my_priv
    
    # 3. Envia a pública para o servidor repassar
    packet = create_key_exchange_packet(my_username, target_user, my_pub_bytes)
    send_packet(client_socket, packet)

def send_chat_message(target_user, msg):
    """Cria o HMAC e envia a mensagem."""
    if target_user not in session_keys:
        print_security_alert(f"Você ainda não tem um canal seguro com {target_user}. Use /chat {target_user} primeiro.")
        return

    secret = session_keys[target_user]
    
    # --- GARANTIA DE INTEGRIDADE ---
    # Assina a mensagem com a chave que só eu e ele temos
    hmac_sig = generate_hmac(secret, msg)
    
    packet_bytes = create_message_packet(my_username, target_user, msg, hmac_sig)
    send_packet(client_socket, packet_bytes)
    # print(f"(Você -> {target_user}): {msg}") # Opcional: mostrar o que eu enviei

def main():
    global client_socket, my_username
    
    if len(sys.argv) < 2:
        print(f"Uso: python client.py <nome_usuario>")
        print("Exemplo: python client.py Alice")
        return

    my_username = sys.argv[1]
    
    # Define caminhos baseados no nome do usuário
    my_cert = f"{CERTS_DIR}/{my_username}.crt"
    my_key = f"{CERTS_DIR}/{my_username}.key"

    # Validação básica
    if not os.path.exists(my_cert) or not os.path.exists(my_key):
        print_security_alert(f"Certificados para '{my_username}' não encontrados em {CERTS_DIR}/")
        print("Use o script create_user.py para gerar primeiro.")
        return

    print_system_info(f"Carregando cliente seguro para: {my_username}...")

    # --- CONEXÃO SSL (Requisito: Autenticação mútua) ---
    try:
        context = create_client_ssl_context(my_cert, my_key, CA_PATH)
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Conecta envelopado com TLS
        client_socket = context.wrap_socket(raw_socket, server_hostname='localhost')
        client_socket.connect((HOST, PORT))
        
        print_system_info(f"Conectado com segurança ao servidor {HOST}:{PORT}")
        
    except Exception as e:
        print_security_alert(f"Falha na conexão: {e}")
        return

    # Inicia a thread que ouve o servidor
    t = threading.Thread(target=receive_messages, daemon=True)
    t.start()

    print("\n--- COMANDOS ---")
    print("/list             -> Ver usuários online")
    print("/chat <usuario>   -> Criar canal seguro (Troca de chaves)")
    print("/msg <user> <txt> -> Enviar mensagem segura")
    print("/exit             -> Sair")
    print("----------------\n")

    # Loop principal de input do usuário
    while True:
        try:
            cmd = input()
            if not cmd: continue

            parts = cmd.split()
            command = parts[0].lower()

            if command == "/list":
                # Envia pedido de lista (JSON manual simples)
                # Precisamos importar json aqui ou usar uma funcao do protocol
                # Vamos fazer um packet manual pra simplificar pois nao criamos helper pra LIST
                import json
                pkt = {"type": "LIST", "sender": my_username}
                send_packet(client_socket, json.dumps(pkt).encode('utf-8'))

            elif command == "/chat":
                if len(parts) < 2:
                    print("Uso: /chat <nome_do_usuario>")
                else:
                    start_chat_initiation(parts[1])

            elif command == "/msg":
                if len(parts) < 3:
                    print("Uso: /msg <nome_do_usuario> <mensagem...>")
                else:
                    target = parts[1]
                    message = " ".join(parts[2:])
                    send_chat_message(target, message)

            elif command == "/exit":
                print("Saindo...")
                break
            
            else:
                print("Comando inválido.")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Erro: {e}")

    client_socket.close()

if __name__ == "__main__":
    main()