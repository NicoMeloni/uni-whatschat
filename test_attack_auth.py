import socket
import ssl
HOST = '127.0.0.1'
PORT = 8443

def test_unauthorized_connection():
    print("--- TESTE DE ATAQUE: CONEXÃO NÃO AUTORIZADA ---")
    
    # Ataque 1: Conexão "Crua" (Sem SSL)
    print("\n[ATAQUE 1] Tentando conectar sem SSL (TCP puro)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((HOST, PORT))
        sock.send(b"Ola servidor")
        data = sock.recv(1024)
        print(f"[FALHA] O servidor respondeu algo: {data}")
    except Exception as e:
        print(f"[SUCESSO] Conexão rejeitada/fechada pelo servidor: {e}")
    finally:
        sock.close()

    # Ataque 2: Conexão SSL sem certificado de cliente
    print("\n[ATAQUE 2] Tentando SSL sem certificado de cliente...")
    try:
        # Contexto vazio (sem load_cert_chain)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE # Ignora validação do server, mas não manda cert
        
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname="localhost")
        ssl_sock.settimeout(2)
        
        ssl_sock.connect((HOST, PORT))
        print("[FALHA] O servidor aceitou o handshake SSL sem certificado!")
        ssl_sock.close()
    except ssl.SSLError as e:
        print(f"[SUCESSO] O Handshake TLS falhou (O servidor exigiu certificado): {e}")
    except Exception as e:
        print(f"[SUCESSO] Erro de conexão: {e}")

if __name__ == "__main__":
    test_unauthorized_connection()