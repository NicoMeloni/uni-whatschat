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
session_keys = {} 
temp_private_keys = {}

def receive_messages():
    """Thread que fica ouvindo mensagens do servidor o tempo todo."""
    while True:
        try:
            raw_data = recv_packet(client_socket)
            if not raw_data:
                print_security_alert("Conexão com o servidor perdida!")
                os._exit(1)
            
            packet = parse_packet(raw_data)
            msg_type = packet.get("type")
            
            # FIX: Normaliza quem enviou para minúsculo para evitar duplicação Alice/alice
            sender = packet.get("sender", "").lower()

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
    """Lida com o recebimento de chave pública (Handshake Diffie-Hellman)."""
    peer_pub_pem_str = packet.get("public_key")
    if not peer_pub_pem_str:
        return

    peer_pub_bytes = peer_pub_pem_str.encode('utf-8')

    # FIX: sender já vem com .lower() do receive_messages
    
    # Cenário 1: Sou o RECEPTOR (Bob). Alice quer falar comigo.
    # Se eu não tenho uma chave privada temporária guardada pra ela, é um pedido novo.
    if sender not in temp_private_keys:
        print_system_info(f"Recebida solicitação de canal seguro de {sender}...")
        
        peer_pub_obj = load_pem_public_key(peer_pub_bytes)
        params = peer_pub_obj.parameters()
        
        my_priv, my_pub_bytes = generate_dh_keys(params)
        
        shared_secret = compute_shared_secret(my_priv, peer_pub_bytes)
        session_keys[sender] = shared_secret
        
        # Envio minha chave de volta
        # FIX: Envio meu nome e o destino sempre em minúsculo
        resp_packet = create_key_exchange_packet(my_username.lower(), sender, my_pub_bytes)
        send_packet(client_socket, resp_packet)
        
        print_system_info(f"Chaves trocadas! Canal seguro estabelecido com {sender}.")
    
    # Cenário 2: Sou o INICIADOR (Alice). Bob respondeu meu convite.
    else:
        # Recupero a chave privada que guardei quando mandei o convite
        my_priv = temp_private_keys.pop(sender)
        
        shared_secret = compute_shared_secret(my_priv, peer_pub_bytes)
        session_keys[sender] = shared_secret
        print_system_info(f"Handshake concluído! Canal seguro pronto com {sender}.")

def handle_incoming_chat(sender, packet):
    """Verifica a integridade (HMAC) e exibe a mensagem."""
    content = packet.get("content")
    received_hmac = packet.get("hmac")
    
    if sender not in session_keys:
        print_security_alert(f"Mensagem de {sender} ignorada (Sem sessão segura).")
        return

    secret = session_keys[sender]
    
    # --- VERIFICAÇÃO DE INTEGRIDADE ---
    is_valid = verify_hmac(secret, content, received_hmac)
    
    if is_valid:
        print_verified_message(sender, content)
    else:
        print_security_alert(f"MENSAGEM VIOLADA DE {sender}! HMAC inválido.")

def start_chat_initiation(target_user):
    """Inicia o processo de troca de chaves."""
    # FIX: Garante que o alvo é minúsculo
    target_user = target_user.lower()

    if target_user == my_username.lower():
        print_security_alert("Você não pode falar consigo mesmo.")
        return

    print_system_info(f"Iniciando negociação de chaves com {target_user}...")
    
    params = generate_dh_parameters() 
    my_priv, my_pub_bytes = generate_dh_keys(params)
    
    # Guarda chave privada esperando resposta
    temp_private_keys[target_user] = my_priv
    
    # FIX: Envia nomes normalizados
    packet = create_key_exchange_packet(my_username.lower(), target_user, my_pub_bytes)
    send_packet(client_socket, packet)

def send_chat_message(target_user, msg):
    """Cria o HMAC e envia a mensagem."""
    # FIX: Normaliza alvo
    target_user = target_user.lower()

    if target_user not in session_keys:
        print_security_alert(f"Sem canal seguro com {target_user}. Use /chat {target_user} primeiro.")
        return

    secret = session_keys[target_user]
    
    # Assina e envia
    hmac_sig = generate_hmac(secret, msg)
    
    # FIX: Envia nomes normalizados
    packet_bytes = create_message_packet(my_username.lower(), target_user, msg, hmac_sig)
    send_packet(client_socket, packet_bytes)

def main():
    global client_socket, my_username
    
    if len(sys.argv) < 2:
        print(f"Uso: python client.py <nome_usuario>")
        return

    # Nome do arquivo (Case Sensitive no Linux para carregar o arquivo)
    username_file_input = sys.argv[1]
    
    # Nome lógico (Para o chat, sempre minúsculo)
    my_username = username_file_input.lower()
    
    # Carrega arquivos usando o nome exato do arquivo (pode ser Alice.crt)
    my_cert = f"{CERTS_DIR}/{username_file_input}.crt"
    my_key = f"{CERTS_DIR}/{username_file_input}.key"

    if not os.path.exists(my_cert) or not os.path.exists(my_key):
        print_security_alert(f"Certificados para '{username_file_input}' não encontrados.")
        return

    print_system_info(f"Carregando cliente seguro para: {username_file_input}...")

    try:
        context = create_client_ssl_context(my_cert, my_key, CA_PATH)
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = context.wrap_socket(raw_socket, server_hostname='localhost')
        client_socket.connect((HOST, PORT))
        print_system_info(f"Conectado com segurança ao servidor {HOST}:{PORT}")
    except Exception as e:
        print_security_alert(f"Falha na conexão: {e}")
        return

    t = threading.Thread(target=receive_messages, daemon=True)
    t.start()

    print("\n--- COMANDOS ---")
    print("/list             -> Ver usuários online")
    print("/chat <usuario>   -> Criar canal seguro")
    print("/msg <user> <txt> -> Enviar mensagem")
    print("/exit             -> Sair")
    print("----------------\n")

    while True:
        try:
            cmd = input()
            if not cmd: continue

            parts = cmd.split()
            command = parts[0].lower()

            if command == "/list":
                import json
                # FIX: envia sender normalizado
                pkt = {"type": "LIST", "sender": my_username.lower()}
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
                    send_chat_message(parts[1], " ".join(parts[2:]))

            elif command == "/exit":
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