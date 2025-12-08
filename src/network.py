import ssl

def create_server_ssl_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """
    Cria o contexto SSL para o SERVIDOR.
    - Deve exigir certificado do cliente (CERT_REQUIRED).
    - Deve carregar a CA para verificar os clientes.
    """
    # cria contexto configurado para quem VAI AUTENTICAR clientes
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # carrega a identidade do servidor
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    # carrega a CA
    context.load_verify_locations(cafile=ca_path)
    
    # FORÇA o mTLS: O servidor rejeitará conexões sem certificado (autenticidade)
    context.verify_mode = ssl.CERT_REQUIRED    
    
    return context

def create_client_ssl_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """
    Cria o contexto SSL para o CLIENTE.
    - Deve carregar o certificado do próprio cliente (para se autenticar no server).
    - Deve carregar a CA (para confiar no server).
    """
    #cria contexto configurado para quem VAI SE CONECTAR a um servidor
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # carrega a CA
    context.load_verify_locations(cafile=ca_path)
    
    # carrega a identidade do cliente
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    # context.check_hostname = False
    return context