# 3 FUNÇÕES:
# create_messagem_packet
# create_key_exchange_packet
# parse_packet

import json

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
    # TODO: Implementar montagem do dicionário e json.dumps
    pass

def create_key_exchange_packet(sender: str, public_key: bytes) -> bytes:
    """
    Pacote específico para troca de chaves DH.
    A chave pública deve ser enviada, talvez codificada em Hex ou Base64 dentro do JSON.
    """
    # TODO: Implementar
    pass

def parse_packet(data: bytes) -> dict:
    """
    Recebe bytes da rede e transforma de volta em dicionário Python.
    """
    # TODO: Implementar json.loads
    pass