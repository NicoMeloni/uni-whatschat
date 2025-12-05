#!/usr/bin/env python3
"""
Servidor do Uni-WhatsChat
Implementa um servidor de chat seguro com:
- Autenticação mútua via mTLS
- Troca de chaves Diffie-Hellman
- Verificação de integridade via HMAC
"""

import socket
import ssl
import threading
import json
import sys
import os
from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric import dh

from src.network import create_server_ssl_context
from src.crypto import generate_dh_parameters, generate_dh_keys, compute_shared_secret, verify_hmac
from src.protocol import parse_packet, create_message_packet
from src.utils import print_system_info, print_security_alert, print_verified_message

# Configurações
HOST = '127.0.0.1'
PORT = 8443
CERTS_DIR = "certs"
CA_CRT = os.path.join(CERTS_DIR, "ca.crt")
SERVER_CRT = os.path.join(CERTS_DIR, "server.crt")
SERVER_KEY = os.path.join(CERTS_DIR, "server.key")

class ChatServer:
    def __init__(self):
        self.clients: Dict[str, dict] = {}  # {username: {socket, shared_key, dh_private_key}}
        self.dh_parameters = generate_dh_parameters()
        self.lock = threading.Lock()
        
    def get_client_username(self, conn: ssl.SSLSocket) -> Optional[str]:
        """Extrai o username do certificado do cliente"""
        try:
            cert = conn.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert['subject'])
                return subject.get('commonName')
        except Exception as e:
            print_security_alert(f"Erro ao extrair username do certificado: {e}")
        return None
    
    def handle_key_exchange(self, client_socket: ssl.SSLSocket, username: str, packet: dict):
        """Processa a troca de chaves Diffie-Hellman"""
        try:
            import base64
            client_public_key_b64 = packet.get('public_key')
            if not client_public_key_b64:
                print_security_alert(f"Pacote KEY_EXCHANGE sem chave pública de {username}")
                return
            
            client_public_key = base64.b64decode(client_public_key_b64)
            
            # Gera chaves DH do servidor
            server_private_key, server_public_key = generate_dh_keys(self.dh_parameters)
            
            # Calcula segredo compartilhado
            shared_secret = compute_shared_secret(server_private_key, client_public_key)
            
            # Envia chave pública do servidor
            from src.protocol import create_key_exchange_packet
            response = create_key_exchange_packet("server", server_public_key)
            client_socket.send(response + b'\n')
            
            # Armazena informações do cliente
            with self.lock:
                if username not in self.clients:
                    self.clients[username] = {}
                self.clients[username]['shared_key'] = shared_secret
                self.clients[username]['dh_private_key'] = server_private_key
            
            print_system_info(f"Troca de chaves concluída com {username}")
            
        except Exception as e:
            print_security_alert(f"Erro na troca de chaves com {username}: {e}")
    
    def broadcast_message(self, sender: str, message: str, hmac_sig: str):
        """Envia mensagem para todos os clientes conectados"""
        packet = create_message_packet(sender, message, hmac_sig)
        
        with self.lock:
            for username, client_info in self.clients.items():
                if username != sender and 'socket' in client_info:
                    try:
                        client_info['socket'].send(packet + b'\n')
                    except Exception as e:
                        print_security_alert(f"Erro ao enviar mensagem para {username}: {e}")
    
    def handle_client_message(self, client_socket: ssl.SSLSocket, username: str, packet: dict):
        """Processa mensagem recebida de um cliente"""
        try:
            sender = packet.get('sender')
            content = packet.get('content')
            received_hmac = packet.get('hmac')
            
            if not all([sender, content, received_hmac]):
                print_security_alert(f"Mensagem malformada de {username}")
                return
            
            # Verifica se o cliente tem chave compartilhada
            with self.lock:
                if username not in self.clients or 'shared_key' not in self.clients[username]:
                    print_security_alert(f"Cliente {username} não possui chave compartilhada")
                    return
                
                shared_key = self.clients[username]['shared_key']
            
            # Verifica integridade da mensagem
            if verify_hmac(shared_key, content, received_hmac):
                print_verified_message(sender, content)
                # Reenvia para outros clientes
                self.broadcast_message(sender, content, received_hmac)
            else:
                print_security_alert(f"Mensagem de {username} falhou na verificação de integridade!")
                
        except Exception as e:
            print_security_alert(f"Erro ao processar mensagem de {username}: {e}")
    
    def handle_client(self, client_socket: ssl.SSLSocket, addr):
        """Gerencia a conexão de um cliente"""
        username = None
        try:
            username = self.get_client_username(client_socket)
            if not username:
                print_security_alert(f"Não foi possível identificar o cliente de {addr}")
                client_socket.close()
                return
            
            print_system_info(f"Cliente {username} conectado de {addr}")
            
            # Armazena socket do cliente
            with self.lock:
                if username not in self.clients:
                    self.clients[username] = {}
                self.clients[username]['socket'] = client_socket
            
            # Loop principal de comunicação
            buffer = b''
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Processa linhas completas
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    if line:
                        try:
                            packet = parse_packet(line)
                            packet_type = packet.get('type')
                            
                            if packet_type == 'KEY_EXCHANGE':
                                self.handle_key_exchange(client_socket, username, packet)
                            elif packet_type == 'MSG':
                                self.handle_client_message(client_socket, username, packet)
                            else:
                                print_security_alert(f"Tipo de pacote desconhecido: {packet_type}")
                        except Exception as e:
                            print_security_alert(f"Erro ao processar pacote de {username}: {e}")
                            
        except ssl.SSLError as e:
            print_security_alert(f"Erro SSL com {username}: {e}")
        except Exception as e:
            print_security_alert(f"Erro na conexão com {username}: {e}")
        finally:
            if username:
                print_system_info(f"Cliente {username} desconectado")
                with self.lock:
                    if username in self.clients:
                        try:
                            self.clients[username]['socket'].close()
                        except:
                            pass
                        del self.clients[username]
            client_socket.close()
    
    def start(self):
        """Inicia o servidor"""
        try:
            # Cria contexto SSL
            context = create_server_ssl_context(SERVER_CRT, SERVER_KEY, CA_CRT)
            
            # Cria socket TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((HOST, PORT))
                sock.listen(5)
                
                print_system_info(f"Servidor iniciado em {HOST}:{PORT}")
                print_system_info("Aguardando conexões...")
                
                while True:
                    conn, addr = sock.accept()
                    
                    # Envolve com SSL
                    try:
                        ssl_conn = context.wrap_socket(conn, server_side=True)
                        
                        # Cria thread para cada cliente
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(ssl_conn, addr),
                            daemon=True
                        )
                        client_thread.start()
                    except ssl.SSLError as e:
                        print_security_alert(f"Erro SSL ao aceitar conexão de {addr}: {e}")
                        conn.close()
                        
        except KeyboardInterrupt:
            print_system_info("\nServidor encerrando...")
        except Exception as e:
            print_security_alert(f"Erro fatal no servidor: {e}")
            sys.exit(1)

def main():
    # Verifica se os certificados existem
    if not all(os.path.exists(f) for f in [CA_CRT, SERVER_CRT, SERVER_KEY]):
        print_security_alert("Certificados não encontrados! Execute setup_certs.py primeiro.")
        sys.exit(1)
    
    server = ChatServer()
    server.start()

if __name__ == "__main__":
    main()

