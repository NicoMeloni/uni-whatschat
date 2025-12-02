import hmac
import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

# Tipos para ajudar na leitura
PublicKey = bytes
PrivateKey = dh.DHPrivateKey
SharedKey = bytes

def generate_dh_parameters() -> dh.DHParameters:
    """
    Gera os parâmetros p e g do Diffie-Hellman.
    Idealmente, o servidor gera isso uma vez e compartilha com todos,
    ou usa-se um padrão (RFC 3526).
    """
    print("[CRYPTO] Gerando parâmetros Diffie-Hellman (isso pode demorar um pouco)...")
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_dh_keys(parameters: dh.DHParameters) -> tuple[PrivateKey, PublicKey]:
    """
    Gera o par de chaves (Privada, Pública) para um usuário.
    Retorna a chave privada (objeto) e a pública serializada em bytes (para envio).
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # Serializa a pública para enviar pela rede (formato PEM)
    public_key_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key_bytes

def compute_shared_secret(my_private_key: PrivateKey, peer_public_key_bytes: bytes) -> SharedKey:
    """
    Calcula o segredo compartilhado usando a chave privada local e a pública do outro.
    Deve retornar uma chave derivada (ex: usando HKDF) pronta para uso no HMAC.
    """
    # Desserializa a chave pública do colega (de bytes PEM para objeto)
    peer_public_key = load_pem_public_key(peer_public_key_bytes)
    
    # Realiza o cálculo matemático do DH (troca)
    shared_secret = my_private_key.exchange(peer_public_key)
    
    # Derivação de chave (HKDF) para transformar o segredo matemático em bytes uniformes
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None, # Nenhum salt por enquanto
        info=b'whatschat handshake',
    ).derive(shared_secret)
    
    return derived_key

def generate_hmac(key: SharedKey, message: str) -> str:
    """
    Cria uma assinatura HMAC-SHA256 para a mensagem.
    Retorna a assinatura em formato Hexadecimal (string).
    """
    h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

def verify_hmac(key: SharedKey, message: str, received_mac: str) -> bool:
    """
    Verifica se o HMAC recebido bate com o cálculo local.
    Retorna True se íntegro, False se violado.
    """
    expected_mac = generate_hmac(key, message)
    # compare_digest evita ataques de tempo (timing attacks)
    return hmac.compare_digest(expected_mac, received_mac)