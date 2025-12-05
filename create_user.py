import os
import subprocess
import sys

CERTS_DIR = "certs"
CA_CRT = os.path.join(CERTS_DIR, "ca.crt")
CA_KEY = os.path.join(CERTS_DIR, "ca.key")

SUBJ_BASE = "/C=BR/ST=DF/L=Brasilia/O=UNB/OU=Seguranca/CN="

def create_user(username):
    username = username.lower()
    print(f"[*] Criando credenciais para: {username}")
    
    key_path = os.path.join(CERTS_DIR, f"{username}.key")
    csr_path = os.path.join(CERTS_DIR, f"{username}.csr")
    crt_path = os.path.join(CERTS_DIR, f"{username}.crt")

    # Gerar Chave Privada
    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)

    # Gerar CSR (Requisição)
    subj = f"{SUBJ_BASE}{username}"
    subprocess.run([
        "openssl", "req", "-new", "-key", key_path, "-out", csr_path, "-subj", subj
    ], check=True)

    # Assinar com a CA (Gerar CRT)
    subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path, 
        "-CA", CA_CRT, "-CAkey", CA_KEY, "-CAcreateserial",
        "-out", crt_path, "-days", "365", "-sha256"
    ], check=True)

    # Limpeza
    if os.path.exists(csr_path):
        os.remove(csr_path)

    print(f"[OK] Usuário {username} criado com sucesso em {CERTS_DIR}/")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python create_user.py [nome_do_usuario]")
    else:
        create_user(sys.argv[1])