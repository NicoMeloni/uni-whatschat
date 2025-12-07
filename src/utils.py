from colorama import Fore, Style, init

init(autoreset=True)

def print_security_alert(msg: str):
    """Exibe alerta vermelho piscante ou destacado"""
    print(f"{Fore.RED}{Style.BRIGHT}[ALERTA DE SEGURANÇA]: {msg}{Style.RESET_ALL}")

def print_verified_message(sender: str, msg: str):
    """Exibe mensagem verde indicando integridade verificada"""
    print(f"{Fore.GREEN}[{sender} (Verificado)]: {msg}{Style.RESET_ALL}")

def print_system_info(msg: str):
    """Mensagens de sistema (conexão, troca de chaves) em amarelo/azul"""
    print(f"{Fore.CYAN}[SISTEMA]: {msg}{Style.RESET_ALL}")