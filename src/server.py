import socket
import threading
import ssl
import json
from network import create_server_ssl_context
from protocol import parse_packet, send_packet, recv_packet, create_message_packet
from utils import print_system_info

HOST = '0.0.0.0' 
PORT = 8443
CERTS_DIR = "../certs"

# dicionário de usuários online
online_users = {} 
lock = threading.Lock() # para evitar conflito se dois entrarem ao mesmo tempo

def get_client_cn(conn: ssl.SSLSocket) -> str:
    """Extrai o Nome Comum (CN) do certificado do cliente para login automático."""
    try:
        cert = conn.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        return subject.get('commonName')
    except Exception as e:
        print(f"[ERRO DE CERTIFICADO] {e}")
        return None

def handle_client_connection(conn, addr):
    """Função que roda em uma Thread separada para cada usuário."""
    username = get_client_cn(conn)
    
    if not username:
        print(f"[SERVER] Conexão rejeitada (sem certificado): {addr}")
        conn.close()
        return

    # registrar usuário na memória
    with lock:
        if username in online_users:
            try:
                print_system_info(f"Derrubando sessão anterior de {username}...")
                online_users[username].close()
            except:
                pass
        online_users[username] = conn
    
    print_system_info(f"Usuário conectado: {username} {addr}")
    
    try:
        while True:
            # loop de recebimento, fica recebendo dados do cliente até se desconectar
            raw_data = recv_packet(conn)
            if not raw_data:
                break
            
            packet = parse_packet(raw_data)
            msg_type = packet.get("type")

            # um tipo de "roteamento", se é q se pode chamar assim
            if msg_type == "LIST":
                process_list_request(conn)
            
            elif msg_type in ["MSG", "DH_EXCHANGE", "EXIT"]:
                # repasse para o destinatário
                process_relay(username, packet, raw_data)

            else:
                print(f"[SERVER] Tipo desconhecido de {username}: {msg_type}")

    except ssl.SSLError as e:
        print(f"[SERVER LOG] {username} desconectou (SSL finalizado).")
    except Exception as e:
        print(f"[SERVER] Erro genérico com {username}: {e}")
    finally:
        handle_disconnect(username, conn)

def handle_disconnect(username, conn):
    """Remove usuário e avisa outros, MAS SÓ SE for a conexão atual."""
    should_broadcast = False
    
    with lock:
        # verifica se a conexão q está saindo é realmente a que está no dicionário de usuarios online
        # fizemos isso para n dar conflito na hora de desconectar e conectar novamente
        if username in online_users and online_users[username] == conn:
            del online_users[username]
            should_broadcast = True
        
        # iterar sem travar o lock
        active_peers = list(online_users.items())

    
    try: 
        conn.close()
    except: 
        pass

    if should_broadcast:
        print_system_info(f"Usuário desconectado (Clean Exit): {username}")
        # avisa os outros que ele saiu
        for peer_name, peer_sock in active_peers:
            if peer_name != username:
                try:
                    exit_packet = {
                        "type": "EXIT",
                        "sender": username,
                        "receiver": peer_name
                    }
                    send_packet(peer_sock, json.dumps(exit_packet).encode('utf-8'))
                except: pass
    else:
        print_system_info(f"Sessão antiga de {username} encerrada (Substituída).")

def process_list_request(conn):
    """Responde ao cliente com a lista de usuários online."""
    with lock:
        users = list(online_users.keys())
    
    response = {
        "type": "LIST_RESP",
        "sender": "SERVER",
        "users": users
    }
    # envia de volta a lista
    send_packet(conn, json.dumps(response).encode('utf-8'))

def process_relay(sender, packet, raw_bytes):
    """Encaminha a mensagem para o destinatário correto."""
    destination = packet.get("receiver")
    
    with lock:
        target_socket = online_users.get(destination)
    
    if target_socket:
        # repassa exatamente o que recebeu (preservando assinaturas/cripto)
        send_packet(target_socket, raw_bytes)
        print(f"[RELAY] {sender} -> {destination} ({packet['type']})")
    else:
        print(f"[FALHA] {sender} tentou enviar para {destination} (Offline)")

def start_server():
    """Inicializa o socket seguro e aceita conexões."""
    # inicializa o contexto ssl definido em network.py
    context = create_server_ssl_context(
        f"{CERTS_DIR}/server.crt",
        f"{CERTS_DIR}/server.key",
        f"{CERTS_DIR}/ca.crt"
    )

    # cria socket TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5) # Fila de até 5 pendentes

    print_system_info(f"Servidor Seguro rodando em {HOST}:{PORT}")
    print_system_info("Aguardando conexões mTLS...")

    try:
        while True:
            client_sock, addr = sock.accept()
            
            try:
                ssl_conn = context.wrap_socket(client_sock, server_side=True)
                # cria uma thread para não travar o servidor principal, que vai lidar com as conexões de cliente
                thread = threading.Thread(target=handle_client_connection, args=(ssl_conn, addr))
                thread.daemon = True # mata a thread se o servidor cair
                thread.start()
            except ssl.SSLError as e:
                print(f"[SSL ERRO] Falha no Handshake com {addr}: {e}")
                client_sock.close()

    except KeyboardInterrupt:
        print("\n[SERVER] Encerrando...")
    
    finally:
        sock.close()

if __name__ == "__main__":
    start_server()