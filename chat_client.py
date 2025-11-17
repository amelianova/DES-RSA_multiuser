import socket
import threading
import secrets
import time
from DES import encrypt_message, decrypt_message
import rsa

SERVER_IP = None
SERVER_PORT = 55555

def ask_server_ip():
    ip = input("Server IP (misal 127.0.0.1): ").strip()
    return ip if ip else '127.0.0.1'

def ask_server_port(default=55555):
    try:
        p = input(f"Server port [{default}]: ").strip()
        return int(p) if p else default
    except:
        return default

def random_des_key_hex():
    return secrets.token_hex(8).upper()

def recv_loop(sock, priv_n, priv_d, state):
    try:
        buffer = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                print("[Connection closed by server]")
                break
            buffer += chunk
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                handle_server_line(line.decode('utf-8').strip(), sock, priv_n, priv_d, state)
    except Exception as e:
        print(f"[Receive error] {e}")

def handle_server_line(line, sock, priv_n, priv_d, state):
    parts = line.split('|', 3)
    typ = parts[0]
    if typ == 'OK':
        print("[Server] OK:", parts[1] if len(parts) > 1 else '')
        return

    if typ == 'PUB':
        # PUB|peer|n:e[|INIT]
        peername = parts[1]
        n_e = parts[2]
        flag = None
        if len(parts) >= 4 and parts[3]:
            flag = parts[3].strip()
        n_str, e_str = n_e.split(':')
        state['peer'] = {'name': peername, 'n': int(n_str), 'e': int(e_str)}
        print(f"[Server] Received PUB for {peername}. flag={flag}")
        print(f"  peer n bits ~ {int(n_str).bit_length()} e={e_str}")

        # If server marked INIT, this client is initiator -> send DES key once
        if flag == 'INIT' and not state['initiator_done']:
            time.sleep(0.2)
            des_key = random_des_key_hex()
            state['secret_key'] = des_key
            m_int = rsa.hexstr_to_int(des_key)
            c_int = rsa.rsa_encrypt_int(m_int, state['peer']['n'], state['peer']['e'])
            c_hex = format(c_int, 'x')
            send_line(sock, f"KEY|{c_hex}")
            state['initiator_done'] = True
            print(f"[Key exchange - initiator] Generated and sent DES key: {des_key}")
        return

    if typ == 'KEY':
        sender = parts[1]
        cipher_hex = parts[2]
        try:
            c_int = int(cipher_hex, 16)
            m_int = rsa.rsa_decrypt_int(c_int, priv_n, priv_d)
            des_key_hex = format(m_int, 'x').upper()
            if len(des_key_hex) < 16:
                des_key_hex = des_key_hex.rjust(16, '0')
            state['secret_key'] = des_key_hex
            print(f"[Key exchange] Received DES key from {sender}: {des_key_hex}")
        except Exception as e:
            print("[Key decrypt error]", e)
        return

    if typ == 'MSG':
        sender = parts[1]
        cipher_hex = parts[2]
        print(f"\n<< Ciphertext diterima dari {sender}: {cipher_hex} >>")
        if state.get('secret_key'):
            try:
                plaintext = decrypt_message(cipher_hex, state['secret_key'])
                # Show both raw repr and cleaned
                print(f"{sender} (decrypted): {plaintext!r}")
                # If plaintext is empty string or only whitespace, dump debug info
                if plaintext.strip() == '':
                    print("DEBUG: plaintext empty/whitespace. Will show additional debug info:")
                    # Try decrypt per-block to show what each block yields
                    blocks = [cipher_hex[i:i+16] for i in range(0, len(cipher_hex), 16)]
                    for idx, bhex in enumerate(blocks):
                        try:
                            p = decrypt_message(bhex, state['secret_key'])
                            print(f"  block[{idx}] -> {p!r}")
                        except Exception as ex:
                            print(f"  block[{idx}] decrypt error: {ex}")
            except Exception as e:
                print("[Decrypt error]", e)
        else:
            print("[Belum punya DES key untuk decrypt]")
        return

    if typ == 'ERROR':
        print("[SERVER ERROR]", parts[1] if len(parts)>1 else '')
        return
    if typ == 'INFO':
        print("[INFO]", parts[1] if len(parts)>1 else '')
        return

    print("[Unknown server message]", line)

def send_line(sock, text):
    try:
        sock.sendall((text + '\n').encode('utf-8'))
    except Exception as e:
        print("[Send error]", e)

def input_loop(sock, state):
    try:
        while True:
            msg = input()
            if msg.lower() == 'exit':
                send_line(sock, "EXIT|")
                break
            if not state.get('secret_key'):
                print("[Belum ada DES key. Tunggu key exchange berlangsung.]")
                continue
            try:
                cipher = encrypt_message(msg, state['secret_key'])
                print(f"<< Ciphertext terkirim: {cipher} >>")
                print(f"[DEBUG] using secret_key = {state.get('secret_key')}")
                send_line(sock, f"MSG|{cipher}")
            except Exception as e:
                print("[Encrypt error]", e)
    except (KeyboardInterrupt, EOFError):
        send_line(sock, "EXIT|")

def main():
    global SERVER_IP, SERVER_PORT
    print("=== Secure Chat Client (RSA + DES) - DEBUG ===")
    SERVER_IP = ask_server_ip()
    SERVER_PORT = ask_server_port()
    name = input("Your name (unique): ").strip()
    if not name:
        print("Name required"); return
    print("[*] Generating RSA keypair...")
    n, e, d = rsa.generate_rsa_keypair(bits=768)
    print(f"[RSA] Keypair OK. n bits = {n.bit_length()}")
    state = {'secret_key': None, 'peer': None, 'initiator_done': False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        send_line(sock, f"REGISTER|{name}|{n}|{e}")
        threading.Thread(target=recv_loop, args=(sock, n, d, state), daemon=True).start()
        print("Tunggu hingga peer terkoneksi...")
        print("Ketik pesan untuk mulai mengirim (setelah key exchange). Ketik 'exit' untuk keluar.")
        input_loop(sock, state)
    except Exception as ex:
        print("[Connection error]", ex)
    finally:
        try: sock.close()
        except: pass

if __name__ == '__main__':
    main()
