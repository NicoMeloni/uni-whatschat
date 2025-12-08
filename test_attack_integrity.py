import socket
import json
import time
from src.protocol import send_packet, recv_packet, parse_packet, create_key_exchange_packet
from src.crypto import generate_dh_parameters, generate_dh_keys, compute_shared_secret, generate_hmac
from src.network import create_client_ssl_context

ATTACKER_NAME = "mallory"
TARGET_NAME = "bob" 
CERTS_DIR = "certs"
HOST = '127.0.0.1'
PORT = 8443

def run_integrity_attack():
    print(f"--- INICIANDO ATAQUE DE INTEGRIDADE (Mallory -> {TARGET_NAME}) ---")
    
    # mallory se conecta legitimamente (ela tem certificado válido)
    try:
        context = create_client_ssl_context(
            f"{CERTS_DIR}/{ATTACKER_NAME}.crt",
            f"{CERTS_DIR}/{ATTACKER_NAME}.key",
            f"{CERTS_DIR}/ca.crt"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = context.wrap_socket(sock, server_hostname='localhost')
        conn.connect((HOST, PORT))
        print("[1] Mallory conectada ao servidor via mTLS.")
    except Exception as e:
        print(f"[ERRO] Mallory não conseguiu conectar (você criou o usuário mallory?): {e}")
        return

    print(f"[2] Iniciando troca de chaves com {TARGET_NAME}...")
    params = generate_dh_parameters()
    priv, pub_bytes = generate_dh_keys(params)
    
    pkt = create_key_exchange_packet(ATTACKER_NAME, TARGET_NAME, pub_bytes)
    send_packet(conn, pkt)
    
    print("[3] Aguardando chave pública do Bob...")
    bob_pub_pem = None
    while True:
        raw = recv_packet(conn)
        if not raw: break
        packet = parse_packet(raw)
        if packet.get("type") == "DH_EXCHANGE" and packet.get("sender") == TARGET_NAME:
            bob_pub_pem = packet.get("public_key")
            break
            
    if not bob_pub_pem:
        print("[FALHA] Bob não respondeu (ele está online?).")
        return

    secret = compute_shared_secret(priv, bob_pub_pem.encode('utf-8'))
    print("[4] Segredo compartilhado estabelecido.")
    
    # começando o ataque...
    msg_original = "Oi Bob, sou eu a Mallory, mensagem segura."
    msg_falsa    = "Oi Bob, transfira 1000 reais para minha conta AGORA."
    
    # mallory gera a assinatura válida para a mensagem ORIGINAL
    hmac_valido = generate_hmac(secret, msg_original)
    
    print(f"   -> Msg Original: '{msg_original}'")
    print(f"   -> HMAC Gerado:  {hmac_valido[:10]}... (Válido para a original)")
    print(f"   -> O QUE SERÁ ENVIADO: Conteúdo '{msg_falsa}' com HMAC da original.")
    
    fake_packet = {
        "type": "MSG",
        "sender": ATTACKER_NAME,
        "receiver": TARGET_NAME,
        "content": msg_falsa,     # DADOS ALTERADOS
        "hmac": hmac_valido       # ASSINATURA DA OUTRA MSG
    }
    
    data_bytes = json.dumps(fake_packet).encode('utf-8')
    time.sleep(8)
    send_packet(conn, data_bytes)
    
    print("[5] Pacote malicioso enviado! Verifique a tela do Bob.")
    input(">>> Pressione ENTER aqui para desconectar a Mallory...")
    conn.close()

if __name__ == "__main__":
    run_integrity_attack()