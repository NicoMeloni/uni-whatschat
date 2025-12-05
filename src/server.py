import socket
import threading
import ssl
from network import create_server_ssl_context
from protocol import parse_packet, send_packet, recv_packet, create_message_packet
from utils import print_system_info

# Configurações
HOST = '0.0.0.0' # Aceita conexões de qualquer interface
PORT = 8443
CERTS_DIR = "../certs"

# Estado Global (Dicionário de usuários online)
# Formato: {'Alice': socket_obj, 'Bob': socket_obj}
online_users = {} 
lock = threading.Lock() # Para evitar conflito se dois entrarem ao mesmo tempo

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

    # 1. Login: Registrar usuário na memória
    with lock:
        online_users[username] = conn
    
    print_system_info(f"Usuário conectado: {username} {addr}")
    
    try:
        while True:
            # 2. Loop de Recebimento
            raw_data = recv_packet(conn)
            if not raw_data:
                break # Cliente desconectou
            
            packet = parse_packet(raw_data)
            msg_type = packet.get("type")

            # 3. Lógica de Roteamento (Switch case)
            if msg_type == "LIST":
                process_list_request(conn)
            
            elif msg_type in ["MSG", "DH_EXCHANGE"]:
                # Repasse (Relay) para o destinatário
                process_relay(username, packet, raw_data)
                
            else:
                print(f"[SERVER] Tipo desconhecido de {username}: {msg_type}")

    except Exception as e:
        print(f"[SERVER] Erro com {username}: {e}")
    finally:
        # 4. Logout: Remover da memória
        with lock:
            if username in online_users:
                del online_users[username]
        conn.close()
        print_system_info(f"Usuário desconectado: {username}")

def process_list_request(conn):
    """Responde ao cliente com a lista de usuários online."""
    with lock:
        users = list(online_users.keys())
    
    # Cria um pacote especial do sistema
    response = {
        "type": "LIST_RESP",
        "sender": "SERVER",
        "users": users
    }
    # Envia de volta (precisamos serializar manual pois não é MSG nem DH)
    import json
    send_packet(conn, json.dumps(response).encode('utf-8'))

def process_relay(sender, packet, raw_bytes):
    """Encaminha a mensagem para o destinatário correto."""
    destination = packet.get("receiver")
    
    with lock:
        target_socket = online_users.get(destination)
    
    if target_socket:
        # Repassa exatamente o que recebeu (preservando assinaturas/cripto)
        send_packet(target_socket, raw_bytes)
        print(f"[RELAY] {sender} -> {destination} ({packet['type']})")
    else:
        print(f"[FALHA] {sender} tentou enviar para {destination} (Offline)")
        # Opcional: Avisar o remetente que falhou

def start_server():
    """Inicializa o socket seguro e aceita conexões."""
    # Usa a função modular do network.py
    context = create_server_ssl_context(
        f"{CERTS_DIR}/server.crt",
        f"{CERTS_DIR}/server.key",
        f"{CERTS_DIR}/ca.crt"
    )

    # Cria socket TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5) # Fila de até 5 pendentes

    print_system_info(f"Servidor Seguro rodando em {HOST}:{PORT}")
    print_system_info("Aguardando conexões mTLS...")

    try:
        while True:
            # Aceita conexão TCP pura
            client_sock, addr = sock.accept()
            
            # Envelopa com SSL (mTLS Handshake acontece aqui)
            try:
                ssl_conn = context.wrap_socket(client_sock, server_side=True)
                # Cria uma thread para não travar o servidor principal
                thread = threading.Thread(target=handle_client_connection, args=(ssl_conn, addr))
                thread.daemon = True # Mata a thread se o servidor cair
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