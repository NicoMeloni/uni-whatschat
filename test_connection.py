import socket
import threading
import time
import ssl
import sys

# Importa sua implementação de rede
from src.network import create_server_ssl_context, create_client_ssl_context

# Configurações de Rede
HOST = '127.0.0.1'
PORT = 8443

# Caminhos dos Certificados (ajuste se necessário)
CERTS_DIR = "certs"
CA_CRT = f"{CERTS_DIR}/ca.crt"

SERVER_CRT = f"{CERTS_DIR}/server.crt"
SERVER_KEY = f"{CERTS_DIR}/server.key"

CLIENT_CRT = f"{CERTS_DIR}/alice.crt"
CLIENT_KEY = f"{CERTS_DIR}/alice.key"

def run_server_test():
    """Função que simula o servidor rodando em background"""
    try:
        context = create_server_ssl_context(SERVER_CRT, SERVER_KEY, CA_CRT)
        
        # Cria socket TCP puro
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((HOST, PORT))
            sock.listen(1)
            print(f"\n[SERVER] Ouvindo na porta {PORT}...")

            # Envelopa com SSL (Aqui acontece a mágica do mTLS)
            with context.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
                print(f"[SERVER] Conexão aceita de: {addr}")
                
                # VERIFICAÇÃO DE IDENTIDADE
                # O servidor extrai quem é o cliente do certificado
                cert = conn.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject.get('commonName')
                
                print(f"[SERVER] ✨ Identidade do Cliente Verificada: {common_name}")
                
                # Envia mensagem segura
                conn.send(b"Ola Alice, aqui eh o Servidor Seguro!")
                conn.close()
                
    except Exception as e:
        print(f"[SERVER ERROR]: {e}")

def run_client_test():
    """Função que simula a Alice tentando conectar"""
    # Espera um pouco pro servidor subir
    time.sleep(1) 
    print("\n[CLIENT] Tentando conectar...")

    try:
        context = create_client_ssl_context(CLIENT_CRT, CLIENT_KEY, CA_CRT)
        
        # Cria socket TCP puro
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Envelopa com SSL
            # server_hostname='localhost' é crucial para validar o cert do servidor
            with context.wrap_socket(sock, server_side=False, server_hostname='localhost') as ssock:
                ssock.connect((HOST, PORT))
                print("[CLIENT] ✅ Handshake TLS completo! Conexão Segura estabelecida.")
                
                # Recebe dados
                data = ssock.recv(1024)
                print(f"[CLIENT] Recebido do servidor: {data.decode()}")

    except ssl.SSLCertVerificationError as e:
        print(f"[CLIENT FALHA DE SEGURANÇA]: Certificado inválido! {e}")
    except Exception as e:
        print(f"[CLIENT ERROR]: {e}")

if __name__ == "__main__":
    # Inicia o servidor em uma thread separada
    server_thread = threading.Thread(target=run_server_test)
    server_thread.start()

    # Roda o cliente na thread principal
    run_client_test()

    # Garante que o servidor termine
    server_thread.join()
    print("\n--- Teste Finalizado ---") 