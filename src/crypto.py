import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

# tipos
PublicKey = bytes
PrivateKey = dh.DHPrivateKey
SharedKey = bytes

def generate_dh_parameters() -> dh.DHParameters:
    #Gera os parâmetros p (primo) e g (gerador) do Diffie-Hellman
    
    print("[CRYPTO] Gerando parâmetros Diffie-Hellman (isso pode demorar um pouco)...")
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_dh_keys(parameters: dh.DHParameters) -> tuple[PrivateKey, PublicKey]:
    """
    Gera o par de chaves (pk, sk) para um usuário.
    Retorna a chave privada e a pública serializada em bytes.
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # serializa a pública para enviar pela rede (formato PEM)
    public_key_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key_bytes

def compute_shared_secret(my_private_key: PrivateKey, peer_public_key_bytes: bytes) -> SharedKey:
    """
    Calcula o segredo compartilhado usando a chave privada local e a pública do outro.
    Retorna uma chave derivada pronta para uso no HMAC.
    """
    # desserializa a chave pública (de bytes para objeto)
    peer_public_key = load_pem_public_key(peer_public_key_bytes)
    
    # realiza o cálculo do DH (troca de chaves)
    shared_secret = my_private_key.exchange(peer_public_key)
    
    # derivação de chave para transformar o segredo em bytes
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None, # nenhum salt por enquanto (pra sempre k)
        info=b'whatschat handshake',
    ).derive(shared_secret)
    
    return derived_key

def generate_hmac(key: SharedKey, message: str) -> str:
    """
    Cria uma assinatura HMAC-SHA256 para a mensagem.
    Retorna a assinatura em formato hexadecimal.
    """
    h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

def verify_hmac(key: SharedKey, message: str, received_mac: str) -> bool:
    """
    Verifica se o HMAC recebido bate com o cálculo que foi feito.
    Retorna True se certo, False se violado.
    """
    expected_mac = generate_hmac(key, message)
    return hmac.compare_digest(expected_mac, received_mac)