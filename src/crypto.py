import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    # TODO: Implementar geração de parâmetros (geralmente grupo 14 ou 2048-bit)
    pass

def generate_dh_keys(parameters: dh.DHParameters) -> tuple[PrivateKey, PublicKey]:
    """
    Gera o par de chaves (Privada, Pública) para um usuário.
    Retorna a chave privada (objeto) e a pública serializada em bytes (para envio).
    """
    # TODO: Implementar geração de chaves
    pass

def compute_shared_secret(my_private_key: PrivateKey, peer_public_key_bytes: bytes) -> SharedKey:
    """
    Calcula o segredo compartilhado usando a chave privada local e a pública do outro.
    Deve retornar uma chave derivada (ex: usando HKDF) pronta para uso no HMAC.
    """
    # TODO: Implementar exchange e derivação de chave
    pass

def generate_hmac(key: SharedKey, message: str) -> str:
    """
    Cria uma assinatura HMAC-SHA256 para a mensagem.
    Retorna a assinatura em formato Hexadecimal (string).
    """
    # TODO: Implementar hmac.new().hexdigest()
    pass

def verify_hmac(key: SharedKey, message: str, received_mac: str) -> bool:
    """
    Verifica se o HMAC recebido bate com o cálculo local.
    Retorna True se íntegro, False se violado.
    """
    # TODO: Implementar comparação segura (hmac.compare_digest)
    pass