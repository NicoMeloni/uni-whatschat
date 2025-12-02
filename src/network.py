import ssl

def create_server_ssl_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """
    Cria o contexto SSL para o SERVIDOR.
    - Deve exigir certificado do cliente (CERT_REQUIRED).
    - Deve carregar a CA para verificar os clientes.
    """
    # Cria contexto configurado para quem VAI AUTENTICAR clientes
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # 1. Carrega a identidade do Servidor (Para o cliente saber que é o server certo)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    # 2. Carrega a CA (Para o servidor saber validar o crachá da Alice)
    context.load_verify_locations(cafile=ca_path)
    
    # 3. FORÇA o mTLS: O servidor rejeitará conexões sem certificado (Requisito de Autenticidade)
    context.verify_mode = ssl.CERT_REQUIRED    
    
    return context

def create_client_ssl_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """
    Cria o contexto SSL para o CLIENTE.
    - Deve carregar o certificado do próprio cliente (para se autenticar no server).
    - Deve carregar a CA (para confiar no server).
    """
    # Cria contexto configurado para quem VAI SE CONECTAR a um servidor
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # 1. Carrega a CA (Para o cliente validar que o servidor é confiável)
    context.load_verify_locations(cafile=ca_path)
    
    # 2. Carrega a identidade do Cliente (Para o mTLS: Alice prova quem é)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    # context.check_hostname = False
    return context