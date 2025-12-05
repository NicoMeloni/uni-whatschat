# 3 FUNÇÕES:
# create_messagem_packet
# create_key_exchange_packet
# parse_packet

import json
import base64
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def create_message_packet(sender: str, content: str, hmac_sig: str) -> bytes:
    """
    Empacota a mensagem em JSON e codifica para bytes.
    Estrutura sugerida:
    {
        "type": "MSG",
        "sender": sender,
        "content": content,
        "hmac": hmac_sig
    }
    """
    packet = {
        "type": "MSG",
        "sender": sender,
        "content": content,
        "hmac": hmac_sig
    }
    return json.dumps(packet).encode('utf-8')

def create_key_exchange_packet(sender: str, public_key: bytes) -> bytes:
    """
    Pacote específico para troca de chaves DH.
    A chave pública deve ser enviada, talvez codificada em Hex ou Base64 dentro do JSON.
    """
    # Codifica a chave pública em base64 para envio seguro
    public_key_b64 = base64.b64encode(public_key).decode('utf-8')
    packet = {
        "type": "KEY_EXCHANGE",
        "sender": sender,
        "public_key": public_key_b64
    }
    return json.dumps(packet).encode('utf-8')

def create_dh_params_packet(parameters_bytes: bytes) -> bytes:
    """
    Cria pacote para envio de parâmetros DH.
    """
    params_b64 = base64.b64encode(parameters_bytes).decode('utf-8')
    packet = {
        "type": "DH_PARAMS",
        "parameters": params_b64
    }
    return json.dumps(packet).encode('utf-8')

def parse_packet(data: bytes) -> dict:
    """
    Recebe bytes da rede e transforma de volta em dicionário Python.
    """
    try:
        return json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Erro ao fazer parse do pacote: {e}")