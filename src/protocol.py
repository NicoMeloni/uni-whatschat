# 3 FUNÇÕES:
# create_messagem_packet
# create_key_exchange_packet
# parse_packet

import struct
import json

# Funções auxiliares de rede (Framing) para garantir envio completo
def send_packet(sock, packet_bytes: bytes):
    """Envia o tamanho do pacote (4 bytes) seguido pelo pacote em si."""
    # !I significa: Inteiro Unsigned Big-Endian (padrão de rede)
    header = struct.pack('!I', len(packet_bytes))
    sock.sendall(header + packet_bytes)

def recv_packet(sock) -> bytes:
    """Lê exatamente um pacote completo baseado no cabeçalho de tamanho."""
    # 1. Ler os primeiros 4 bytes para saber o tamanho
    header = sock.recv(4)
    if not header:
        return None
    
    (length,) = struct.unpack('!I', header)
    
    # 2. Ler o conteúdo até completar o tamanho avisado
    data = b''
    while len(data) < length:
        # Lê o que falta ou no máximo 4096 bytes por vez
        to_read = length - len(data)
        chunk = sock.recv(min(to_read, 4096))
        if not chunk:
            return None
        data += chunk
        
    return data

def create_message_packet(sender: str, receiver: str, content: str, hmac_sig: str) -> bytes:
    """Empacota uma mensagem de chat normal."""
    packet = {
        "type": "MSG",
        "sender": sender,
        "receiver": receiver,
        "content": content,
        "hmac": hmac_sig
    }
    return json.dumps(packet).encode('utf-8')

def create_key_exchange_packet(sender: str, receiver: str, public_key: bytes) -> bytes:
    """Empacota uma chave pública para o handshake Diffie-Hellman."""
    packet = {
        "type": "DH_EXCHANGE",
        "sender": sender,
        "receiver": receiver,
        # Chaves PEM são bytes, precisamos converter para string para o JSON aceitar
        "public_key": public_key.decode('utf-8')
    }
    return json.dumps(packet).encode('utf-8')

def parse_packet(data: bytes) -> dict:
    """Transforma bytes recebidos de volta em dicionário."""
    try:
        if not data:
            return {}
        return json.loads(data.decode('utf-8'))
    except Exception as e:
        print(f"[PROTOCOLO ERROR] Pacote inválido: {e}")
        return {}