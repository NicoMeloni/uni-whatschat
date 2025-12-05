#!/usr/bin/env python3
"""
Cliente do Uni-WhatsChat
Implementa um cliente de chat seguro com:
- Autenticação mútua via mTLS
- Troca de chaves Diffie-Hellman
- Verificação de integridade via HMAC
"""

import socket
import ssl
import threading
import sys
import os
import time
from typing import Optional

from src.network import create_client_ssl_context
from src.crypto import generate_dh_keys, compute_shared_secret, generate_hmac
from src.protocol import parse_packet, create_message_packet, create_key_exchange_packet
from src.utils import print_system_info, print_security_alert, print_verified_message

# Configurações
HOST = '127.0.0.1'
PORT = 8443
CERTS_DIR = "certs"
CA_CRT = os.path.join(CERTS_DIR, "ca.crt")

class ChatClient:
    def __init__(self, username: str):
        self.username = username
        self.client_crt = os.path.join(CERTS_DIR, f"{username}.crt")
        self.client_key = os.path.join(CERTS_DIR, f"{username}.key")
        self.socket: Optional[ssl.SSLSocket] = None
        self.shared_key: Optional[bytes] = None
        self.dh_parameters = None
        self.dh_private_key = None
        self.connected = False
        
    def connect(self):
        """Conecta ao servidor"""
        try:
            # Verifica certificados
            if not all(os.path.exists(f) for f in [CA_CRT, self.client_crt, self.client_key]):
                print_security_alert(f"Certificados não encontrados para {self.username}!")
                print_system_info("Execute: python create_user.py " + self.username)
                return False
            
            # Cria contexto SSL
            context = create_client_ssl_context(self.client_crt, self.client_key, CA_CRT)
            
            # Cria socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Envolve com SSL
            self.socket = context.wrap_socket(sock, server_side=False, server_hostname='localhost')
            self.socket.connect((HOST, PORT))
            
            print_system_info(f"Conectado ao servidor {HOST}:{PORT}")
            self.connected = True
            
            # Inicia thread para receber mensagens
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
            # Aguarda um pouco antes de iniciar troca de chaves
            time.sleep(0.5)
            
            # Inicia troca de chaves
            self.initiate_key_exchange()
            
            return True
            
        except ssl.SSLCertVerificationError as e:
            print_security_alert(f"Erro de verificação de certificado: {e}")
            return False
        except Exception as e:
            print_security_alert(f"Erro ao conectar: {e}")
            return False
    
    def initiate_key_exchange(self):
        """Inicia a troca de chaves Diffie-Hellman"""
        try:
            # Gera parâmetros DH localmente
            # Nota: Em produção, o servidor deveria enviar os parâmetros
            # Para este trabalho, ambos geram parâmetros separadamente
            # Isso funciona porque ambos usam os mesmos valores padrão (gerador=2, key_size=2048)
            from src.crypto import generate_dh_parameters
            self.dh_parameters = generate_dh_parameters()
            
            # Gera chaves DH
            self.dh_private_key, public_key = generate_dh_keys(self.dh_parameters)
            
            # Envia chave pública
            packet = create_key_exchange_packet(self.username, public_key)
            self.socket.send(packet + b'\n')
            
            print_system_info("Troca de chaves iniciada...")
            
        except Exception as e:
            print_security_alert(f"Erro ao iniciar troca de chaves: {e}")
    
    def handle_key_exchange(self, packet: dict):
        """Processa resposta da troca de chaves"""
        try:
            import base64
            sender = packet.get('sender')
            public_key_b64 = packet.get('public_key')
            
            if sender != 'server' or not public_key_b64:
                print_security_alert("Pacote KEY_EXCHANGE inválido")
                return
            
            server_public_key = base64.b64decode(public_key_b64)
            
            # Calcula segredo compartilhado
            self.shared_key = compute_shared_secret(self.dh_private_key, server_public_key)
            
            print_system_info("Troca de chaves concluída! Comunicação segura estabelecida.")
            
        except Exception as e:
            print_security_alert(f"Erro ao processar troca de chaves: {e}")
    
    def send_message(self, message: str):
        """Envia mensagem para o servidor"""
        if not self.connected or not self.socket:
            print_security_alert("Não conectado ao servidor!")
            return
        
        if not self.shared_key:
            print_security_alert("Chave compartilhada não estabelecida! Aguarde...")
            return
        
        try:
            # Gera HMAC da mensagem
            hmac_sig = generate_hmac(self.shared_key, message)
            
            # Cria e envia pacote
            packet = create_message_packet(self.username, message, hmac_sig)
            self.socket.send(packet + b'\n')
            
        except Exception as e:
            print_security_alert(f"Erro ao enviar mensagem: {e}")
    
    def receive_messages(self):
        """Recebe mensagens do servidor"""
        buffer = b''
        try:
            while self.connected:
                data = self.socket.recv(4096)
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
                                self.handle_key_exchange(packet)
                            elif packet_type == 'MSG':
                                self.handle_message(packet)
                            else:
                                print_security_alert(f"Tipo de pacote desconhecido: {packet_type}")
                                
                        except Exception as e:
                            print_security_alert(f"Erro ao processar pacote: {e}")
                            
        except Exception as e:
            if self.connected:
                print_security_alert(f"Erro ao receber mensagens: {e}")
        finally:
            self.connected = False
            print_system_info("Desconectado do servidor")
    
    def handle_message(self, packet: dict):
        """Processa mensagem recebida"""
        try:
            sender = packet.get('sender')
            content = packet.get('content')
            received_hmac = packet.get('hmac')
            
            if not all([sender, content, received_hmac]):
                print_security_alert("Mensagem malformada recebida")
                return
            
            # Verifica integridade se temos a chave compartilhada
            if self.shared_key:
                if verify_hmac(self.shared_key, content, received_hmac):
                    if sender != self.username:  # Não mostra mensagens próprias duplicadas
                        print_verified_message(sender, content)
                else:
                    print_security_alert(f"Mensagem de {sender} falhou na verificação de integridade!")
            else:
                # Se ainda não temos chave, apenas mostra a mensagem
                print(f"[{sender}]: {content}")
                
        except Exception as e:
            print_security_alert(f"Erro ao processar mensagem: {e}")
    
    def disconnect(self):
        """Desconecta do servidor"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

def main():
    if len(sys.argv) < 2:
        print("Uso: python -m src.client <username>")
        print("Exemplo: python -m src.client alice")
        sys.exit(1)
    
    username = sys.argv[1]
    client = ChatClient(username)
    
    if not client.connect():
        sys.exit(1)
    
    try:
        print_system_info(f"Bem-vindo, {username}!")
        print_system_info("Digite suas mensagens (ou 'quit' para sair):")
        print()
        
        while client.connected:
            message = input()
            if message.lower() in ['quit', 'exit', 'sair']:
                break
            if message.strip():
                client.send_message(message)
                
    except KeyboardInterrupt:
        print("\n")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()

