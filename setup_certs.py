#!/usr/bin/env python3
"""
Script para gerar certificados CA e do servidor
"""

import os
import subprocess
import sys

CERTS_DIR = "certs"
CA_CRT = os.path.join(CERTS_DIR, "ca.crt")
CA_KEY = os.path.join(CERTS_DIR, "ca.key")
SERVER_CRT = os.path.join(CERTS_DIR, "server.crt")
SERVER_KEY = os.path.join(CERTS_DIR, "server.key")

def run_command(cmd, check=True):
    """Executa um comando e trata erros"""
    try:
        result = subprocess.run(cmd, check=check, capture_output=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando: {' '.join(cmd)}")
        print(f"Erro: {e.stderr}")
        return None

def create_ca():
    """Cria a Autoridade Certificadora (CA)"""
    print("[*] Criando Autoridade Certificadora (CA)...")
    
    # Cria diretório se não existir
    os.makedirs(CERTS_DIR, exist_ok=True)
    
    # Gera chave privada da CA
    if not os.path.exists(CA_KEY):
        run_command([
            "openssl", "genrsa", "-out", CA_KEY, "2048"
        ])
        print("[OK] Chave privada da CA criada")
    else:
        print("[*] Chave privada da CA já existe")
    
    # Gera certificado auto-assinado da CA
    if not os.path.exists(CA_CRT):
        run_command([
            "openssl", "req", "-new", "-x509", "-days", "3650",
            "-key", CA_KEY, "-out", CA_CRT,
            "-subj", "/C=BR/ST=DF/L=Brasilia/O=UNB/OU=Seguranca/CN=CA"
        ])
        print("[OK] Certificado da CA criado")
    else:
        print("[*] Certificado da CA já existe")

def create_server_cert():
    """Cria certificado do servidor"""
    print("[*] Criando certificado do servidor...")
    
    # Gera chave privada do servidor
    if not os.path.exists(SERVER_KEY):
        run_command([
            "openssl", "genrsa", "-out", SERVER_KEY, "2048"
        ])
        print("[OK] Chave privada do servidor criada")
    else:
        print("[*] Chave privada do servidor já existe")
    
    # Cria CSR (Certificate Signing Request)
    csr_path = os.path.join(CERTS_DIR, "server.csr")
    if not os.path.exists(SERVER_CRT):
        run_command([
            "openssl", "req", "-new", "-key", SERVER_KEY,
            "-out", csr_path,
            "-subj", "/C=BR/ST=DF/L=Brasilia/O=UNB/OU=Seguranca/CN=localhost"
        ])
        
        # Assina com a CA
        run_command([
            "openssl", "x509", "-req", "-days", "365",
            "-in", csr_path, "-CA", CA_CRT, "-CAkey", CA_KEY,
            "-CAcreateserial", "-out", SERVER_CRT, "-sha256"
        ])
        
        # Remove CSR
        if os.path.exists(csr_path):
            os.remove(csr_path)
        
        print("[OK] Certificado do servidor criado")
    else:
        print("[*] Certificado do servidor já existe")

def main():
    print("=" * 50)
    print("Configuração de Certificados - Uni-WhatsChat")
    print("=" * 50)
    print()
    
    # Verifica se openssl está instalado
    result = run_command(["openssl", "version"], check=False)
    if result is None or result.returncode != 0:
        print("ERRO: OpenSSL não encontrado!")
        print("Por favor, instale o OpenSSL:")
        print("  - Windows: https://slproweb.com/products/Win32OpenSSL.html")
        print("  - Linux: sudo apt-get install openssl")
        print("  - macOS: brew install openssl")
        sys.exit(1)
    
    create_ca()
    print()
    create_server_cert()
    print()
    print("=" * 50)
    print("Configuração concluída!")
    print("=" * 50)
    print()
    print("Próximos passos:")
    print("1. Crie usuários com: python create_user.py <username>")
    print("2. Inicie o servidor com: python -m src.server")
    print("3. Conecte clientes com: python -m src.client <username>")

if __name__ == "__main__":
    main()


