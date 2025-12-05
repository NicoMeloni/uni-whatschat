import socket
import threading
import sys
import os
import time
import curses
from collections import defaultdict
from datetime import datetime

from network import create_client_ssl_context
from protocol import (
    send_packet, recv_packet, parse_packet,
    create_message_packet, create_key_exchange_packet, create_exit_packet
)
from crypto import (
    generate_dh_parameters, generate_dh_keys, 
    compute_shared_secret, generate_hmac, verify_hmac,
    load_pem_public_key
)

HOST = '127.0.0.1'
PORT = 8443
CERTS_DIR = "../certs"
CA_PATH = f"{CERTS_DIR}/ca.crt"

ui_lock = threading.Lock()

class ChatClientApp:
    """
    Decidimos fazer um app de terminal utilizando o curses.
    """
    def __init__(self, username):
        self.username = username.lower()
        self.display_name = username
        self.sock = None
        self.running = True
        # lista de usuarios online
        self.online_users = []
        # aqui temos as chaves de sessão conectadas no servidor
        self.session_keys = {}          
        # armazena chaves privadas temporárias enquanto aguarda a resposta da troca de chaves
        self.temp_private_keys = {}     
        # historico do chat para quando sair e entrar novamente de um chat de conexão ativa, o chat não se apagar
        self.history = defaultdict(list)
        self.current_screen = "HOME"
        self.selected_user_index = 0
        self.chat_target = None
        self.input_buffer = ""
        self.system_msg = "Bem-vindo ao WhatsChat!"

    def connect(self):
        my_cert = f"{CERTS_DIR}/{self.display_name}.crt"
        my_key = f"{CERTS_DIR}/{self.display_name}.key"
        if not os.path.exists(my_cert) or not os.path.exists(my_key):
            return False, f"Certificados de {self.display_name} não encontrados."
        try:
            # carrega o contexto mTLS com o certificado do cliente (para provar identidade) e a CA (para confiar no servidor)
            context = create_client_ssl_context(my_cert, my_key, CA_PATH)
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # envelopa o socket com o TLS e valida se o certificado do servidor bate com localhost
            self.sock = context.wrap_socket(raw_sock, server_hostname='localhost')
            self.sock.connect((HOST, PORT))
            return True, "Conectado."
        except Exception as e:
            return False, str(e)

    def network_loop(self):
        while self.running:
            try:
                raw_data = recv_packet(self.sock)
                if not raw_data:
                    self.system_msg = "Desconectado do servidor."
                    self.running = False
                    break
                packet = parse_packet(raw_data)
                self.process_packet(packet)
                with ui_lock:
                    self.draw_screen()
            except Exception as e:
                self.system_msg = f"Erro de rede: {e}"
                break

    def process_packet(self, packet):
        msg_type = packet.get("type")
        sender = packet.get("sender", "").lower()

        if msg_type == "LIST_RESP":
            users = packet.get("users", [])
            self.online_users = [u for u in users if u.lower() != self.username]
            if self.selected_user_index >= len(self.online_users):
                self.selected_user_index = max(0, len(self.online_users) - 1)
        elif msg_type == "DH_EXCHANGE":
            self.handle_dh(sender, packet)
        elif msg_type == "MSG":
            self.handle_msg(sender, packet)
        elif msg_type == "EXIT":
            self.handle_exit_notification(sender)

    def handle_exit_notification(self, sender):
        """O outro usuário encerrou o chat."""
        # 1. Remove a chave imediatamente (Status na Home vira branco)
        if sender in self.session_keys:
            del self.session_keys[sender]
        
        # 2. Avisa no chat atual
        timestamp = datetime.now().strftime("%H:%M")
        msg = f"🚫 O usuário {sender} desconectou. Pressione ESC para sair."
        self.history[sender].append(("sys", msg, timestamp))
        self.system_msg = f"{sender} encerrou a conexão."

    def handle_dh(self, sender, packet):
        peer_pub_pem = packet.get("public_key")
        if not peer_pub_pem: return
        peer_bytes = peer_pub_pem.encode('utf-8')
        timestamp = datetime.now().strftime("%H:%M")

        if sender not in self.temp_private_keys: # Receptor
            self.system_msg = f"Recebendo conexão de {sender}..."
            peer_obj = load_pem_public_key(peer_bytes)
            params = peer_obj.parameters()
            my_priv, my_pub_bytes = generate_dh_keys(params)
            secret = compute_shared_secret(my_priv, peer_bytes)
            self.session_keys[sender] = secret
            pkt = create_key_exchange_packet(self.username, sender, my_pub_bytes)
            send_packet(self.sock, pkt)
            self.history[sender].append(("sys", "🔒 Canal Seguro DH estabelecido!", timestamp))
        else: # Iniciador
            my_priv = self.temp_private_keys.pop(sender)
            secret = compute_shared_secret(my_priv, peer_bytes)
            self.session_keys[sender] = secret
            self.history[sender].append(("sys", "🔒 Canal Seguro DH estabelecido!", timestamp))

    def handle_msg(self, sender, packet):
        content = packet.get("content")
        hmac_sig = packet.get("hmac")
        timestamp = datetime.now().strftime("%H:%M")
        
        if sender not in self.session_keys:
            # Se chegou msg mas chave foi apagada, ignora ou avisa erro
            return

        secret = self.session_keys[sender]
        if verify_hmac(secret, content, hmac_sig):
            self.history[sender].append(("recv", content, timestamp))
        else:
            self.history[sender].append(("sys", "ALERTA: INTEGRIDADE FALHOU", timestamp))

    def start_chat_with(self, target):
        target = target.lower()
        if target in self.session_keys:
            self.chat_target = target
            self.current_screen = "CHAT"
            self.input_buffer = ""
            if hasattr(self, 'stdscr'): self.stdscr.clear()
            return

        # Inicia negociação
        self.system_msg = f"Negociando com {target}..."
        params = generate_dh_parameters()
        my_priv, my_pub_bytes = generate_dh_keys(params)
        self.temp_private_keys[target] = my_priv
        
        pkt = create_key_exchange_packet(self.username, target, my_pub_bytes)
        send_packet(self.sock, pkt)
        
        # Limpa histórico antigo se for conexão nova
        self.history[target] = []
        
        self.chat_target = target
        self.current_screen = "CHAT"
        self.input_buffer = ""
        if hasattr(self, 'stdscr'): self.stdscr.clear()

    def send_chat_message(self):
        msg = self.input_buffer.strip()
        target = self.chat_target
        if not msg: return

        if msg == "/exit":
            self.close_current_chat(notify_peer=True)
            return

        if target not in self.session_keys:
            self.history[target].append(("sys", "Erro: Sem conexão segura.", datetime.now().strftime("%H:%M")))
            return

        secret = self.session_keys[target]
        hmac_sig = generate_hmac(secret, msg)
        pkt_bytes = create_message_packet(self.username, target, msg, hmac_sig)
        send_packet(self.sock, pkt_bytes)
        
        self.history[target].append(("sent", msg, datetime.now().strftime("%H:%M")))
        self.input_buffer = ""

    def close_current_chat(self, notify_peer=False):
        target = self.chat_target
        if notify_peer and target:
            pkt = create_exit_packet(self.username, target)
            send_packet(self.sock, pkt)

        # Apaga TUDO (chaves e histórico) pois fui EU que saí
        if target in self.session_keys: del self.session_keys[target]
        if target in self.history: del self.history[target]
        
        self.chat_target = None
        self.current_screen = "HOME"
        self.input_buffer = ""
        if hasattr(self, 'stdscr'): self.stdscr.clear()
        self.system_msg = f"Chat encerrado."

    def refresh_user_list(self):
        import json
        pkt = {"type": "LIST", "sender": self.username}
        send_packet(self.sock, json.dumps(pkt).encode('utf-8'))

    # --- VISUAL ---
    def draw_screen(self):
        if not hasattr(self, 'stdscr') or self.stdscr is None:
            return
        
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        # Cores: 1=Cyan(Status), 2=Green(Ok/Msg), 3=Red(Alert), 4=Yellow(Select)
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)

        if self.current_screen == "HOME": self.draw_home(h, w)
        elif self.current_screen == "CHAT": self.draw_chat(h, w)
        
        try: self.stdscr.addstr(h-1, 0, f"STATUS: {self.system_msg}"[:w-1], curses.color_pair(1))
        except: pass
        self.stdscr.refresh()

    def draw_home(self, h, w):
        title = r"""
 __      __  .__            __         _________ .__            __   
/  \    /  \ |  |__ _____ _/  |_  _____\_   ___ \|  |__ _____ _/  |_ 
\   \/\/   / |  |  \\__  \\   __\/  ___/    \  \/|  |  \\__  \\   __\
 \        /  |   Y  \/ __ \|  |  \___ \ \     \___|   Y  \/ __ \|  |  
  \__/\  /   |___|  (____  /__| /____  > \______  /___|  (____  /__|  
       \/         \/     \/          \/         \/     \/     \/      """
        y = 0
        for line in title.split('\n'):
            if y < h:
                self.stdscr.addstr(y, 0, line, curses.color_pair(2))
                y += 1
        
        self.stdscr.addstr(y, 2, f"Logado como: {self.display_name}", curses.color_pair(1)|curses.A_BOLD)
        y += 2
        self.stdscr.addstr(y, 2, "--- USUÁRIOS ONLINE ---")
        y += 2

        if not self.online_users:
            self.stdscr.addstr(y, 4, "Aguardando usuários...", curses.color_pair(5))
        
        for idx, user in enumerate(self.online_users):
            if y >= h-2: break
            is_connected = user.lower() in self.session_keys
            style = curses.color_pair(2) if is_connected else curses.color_pair(5)
            status_txt = " [CONECTADO]" if is_connected else ""
            prefix = " > " if idx == self.selected_user_index else "   "
            final_style = (curses.color_pair(4)|curses.A_REVERSE) if idx == self.selected_user_index else style
            
            self.stdscr.addstr(y, 4, f"{prefix}{user}{status_txt}", final_style)
            y += 1

    def draw_chat(self, h, w):
        is_conn = self.chat_target in self.session_keys
        status_txt = "[CONECTADO]" if is_conn else "[DESCONECTADO]"
        color = curses.color_pair(2) if is_conn else curses.color_pair(3)
        header = f"<- ESC (Voltar) | Chat: {self.chat_target} {status_txt} | /exit (Encerrar)"
        self.stdscr.addstr(0, 0, header, color | curses.A_REVERSE)
        
        history = self.history[self.chat_target]
        msg_area_h = h - 4 
        msgs = history[-msg_area_h:]
        
        for i, (kind, txt, tm) in enumerate(msgs):
            y = 2 + i
            try:
                if kind == "sent": self.stdscr.addstr(y, 1, f"[{tm}] Eu: {txt}", curses.color_pair(2))
                elif kind == "recv": self.stdscr.addstr(y, 1, f"[{tm}] {self.chat_target}: {txt}", curses.color_pair(5))
                elif kind == "sys": self.stdscr.addstr(y, 1, f"! {txt}", curses.color_pair(3)|curses.A_BOLD)
            except: pass

        self.stdscr.addstr(h-3, 0, "-" * (w-1))
        prompt = f"Msg > {self.input_buffer}"
        if len(prompt) > w-1: prompt = prompt[-(w-1):]
        # Se desconectado, input fica vermelho
        input_color = curses.color_pair(5) if is_conn else curses.color_pair(3)
        try: self.stdscr.addstr(h-2, 0, prompt, input_color|curses.A_BOLD)
        except: pass

    def run_curses(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(1)
        self.stdscr.nodelay(True)
        curses.start_color()
        curses.use_default_colors()
        self.refresh_user_list()
        last_refresh = time.time()

        while self.running:
            with ui_lock: self.draw_screen()
            try: key = self.stdscr.getch()
            except: key = -1

            if key != -1: self.handle_input(key)
            
            if self.current_screen == "HOME" and (time.time()-last_refresh > 2):
                self.refresh_user_list()
                last_refresh = time.time()
            time.sleep(0.03)

    def handle_input(self, key):
        if self.current_screen == "HOME":
            if key == curses.KEY_UP: self.selected_user_index = max(0, self.selected_user_index - 1)
            elif key == curses.KEY_DOWN: self.selected_user_index = min(len(self.online_users) - 1, self.selected_user_index + 1)
            elif key == 10:
                if self.online_users: self.start_chat_with(self.online_users[self.selected_user_index])
            elif key == 27: self.running = False

        elif self.current_screen == "CHAT":
            if key == 27: # ESC
                # FIX: Se a conexão morreu (chave deletada pelo Exit do outro), APAGA O HISTÓRICO ao sair
                if self.chat_target not in self.session_keys:
                    self.history[self.chat_target] = []
                
                self.current_screen = "HOME"
                self.input_buffer = ""
                self.refresh_user_list()
                if hasattr(self, 'stdscr'): self.stdscr.clear()

            elif key == 10: self.send_chat_message()
            elif key in [127, 263, 8]: self.input_buffer = self.input_buffer[:-1]
            elif 32 <= key <= 126: self.input_buffer += chr(key)
    
    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except:
                pass

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 src/client.py <username>")
        return
    username = sys.argv[1]
    app = ChatClientApp(username)
    ok, msg = app.connect()
    if not ok:
        print(f"Erro: {msg}"); return
    t = threading.Thread(target=app.network_loop, daemon=True)
    t.start()
    try: 
        curses.wrapper(app.run_curses)
    except KeyboardInterrupt: 
        pass
    finally: 
        app.running = False
        app.close()
        print("Saindo...")

if __name__ == "__main__":
    main()