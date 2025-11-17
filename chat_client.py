# chat_client.py
import socket
import threading
import secrets
import time
from DES import encrypt_message, decrypt_message
import rsa  # our rsa.py

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
    # DES key requirement in your DES.py: 16 hex chars (64-bit)
    return secrets.token_hex(8).upper()

def recv_loop(sock, priv_n, priv_d, state):
    try:
        buffer = b''
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                print("[Connection closed by server]")
                break
            buffer += chunk
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                line = line.decode('utf-8').strip()
                handle_server_line(line, sock, priv_n, priv_d, state)
    except Exception as e:
        print(f"[Receive error] {e}")

def handle_server_line(line, sock, priv_n, priv_d, state):
    # server messages: OK|..., PUB|<peername>|<n:e>, KEY|from|<cipher>, MSG|from|<cipher>, ERROR|..., INFO|...
    parts = line.split('|', 2)
    typ = parts[0]
    if typ == 'OK':
        print("[Server] OK:", parts[1] if len(parts) > 1 else '')
    elif typ == 'PUB':
        # PUB|peername|n:e
        peername = parts[1]
        n_e = parts[2]
        n, e = map(int, n_e.split(':'))
        state['peer'] = {'name': peername, 'n': n, 'e': e}
        print(f"[Server] Received peer public key: {peername}")
        print(f"  n (bits) ~ {n.bit_length()} | e = {e}")
        # Optionally initiate key exchange automatically if I'm the initiator
        if not state['initiator_done']:
            # small delay to offer chance for both clients ready
            time.sleep(0.5)
            # generate DES key and send encrypted to peer
            des_key = random_des_key_hex()
            state['secret_key'] = None  # until peer gets it back? actually we are initiator so we can use it
            enc_int = rsa.rsa_encrypt_int(rsa.hexstr_to_int(des_key), state['peer']['n'], state['peer']['e'])
            enc_hex = format(enc_int, 'x')
            # send KEY message
            send_line(sock, f"KEY|{enc_hex}")
            state['secret_key'] = des_key  # initiator sets secret key immediately for own use
            state['initiator_done'] = True
            print(f"[Key exchange] Sent RSA-encrypted DES key to {peername}. DES key = {des_key}")
            print("You can now send messages; they will be encrypted with DES.")
    elif typ == 'KEY':
        # KEY|from|cipher_hex
        from_name = parts[1]
        cipher_hex = parts[2]
        c_int = int(cipher_hex, 16)
        m_int = rsa.rsa_decrypt_int(c_int, priv_n, priv_d)
        des_key_hex = format(m_int, 'x').upper()
        # ensure 16 hex chars (pad if necessary)
        if len(des_key_hex) % 2 == 1:
            des_key_hex = '0' + des_key_hex
        if len(des_key_hex) < 16:
            des_key_hex = des_key_hex.rjust(16, '0')
        state['secret_key'] = des_key_hex.upper()
        print(f"[Key exchange] Received DES key from {from_name}: {state['secret_key']}")
        print("You can now send messages; they will be encrypted with DES.")
    elif typ == 'MSG':
        # MSG|from|ciphertext_hex
        from_name = parts[1]
        cipher = parts[2]
        print(f"\n<< Ciphertext diterima dari {from_name}: {cipher} >>")
        if state.get('secret_key'):
            try:
                pt = decrypt_message(cipher, state['secret_key'])
                print(f"{from_name} (decrypted): {pt}")
            except Exception as e:
                print(f"[Error dekripsi DES] {e}")
        else:
            print("[Belum punya DES key untuk dekripsi]")
    elif typ == 'ERROR':
        print("[SERVER ERROR]", parts[1] if len(parts) > 1 else '')
    elif typ == 'INFO':
        print("[INFO]", parts[1] if len(parts) > 1 else '')
    else:
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
                send_line(sock, 'EXIT|')
                break
            if not state.get('secret_key'):
                print("[Belum ada DES key. Tunggu key exchange (atau Anda bisa mengirim 'KEYSEND' untuk mengirim key jika peer public key tersedia).]")
                if msg.strip().upper() == 'KEYSEND' and state.get('peer'):
                    # generate and send DES key
                    des_key = random_des_key_hex()
                    enc_int = rsa.rsa_encrypt_int(rsa.hexstr_to_int(des_key), state['peer']['n'], state['peer']['e'])
                    enc_hex = format(enc_int, 'x')
                    send_line(sock, f"KEY|{enc_hex}")
                    state['secret_key'] = des_key
                    state['initiator_done'] = True
                    print(f"[Key sent] DES key = {des_key}")
                continue
            # encrypt with DES and send as MSG
            try:
                ciphertext_hex = encrypt_message(msg, state['secret_key'])
                print(f"<< Ciphertext terkirim: {ciphertext_hex} >>")
                send_line(sock, f"MSG|{ciphertext_hex}")
            except Exception as e:
                print("[Encrypt error]", e)
    except (KeyboardInterrupt, EOFError):
        send_line(sock, 'EXIT|')

def main():
    global SERVER_IP, SERVER_PORT
    print("=== Secure Chat Client (RSA + DES) ===")
    SERVER_IP = ask_server_ip()
    SERVER_PORT = ask_server_port()
    name = input("Your name (unique): ").strip()
    if not name:
        print("Name required")
        return

    print("[*] Generating RSA keypair (this may take a few seconds)...")
    n, e, d = rsa.generate_rsa_keypair(bits=768)  # use 768 or 1024 depending on speed; 768 faster for tests
    print(f"[RSA] Generated keypair. n bits = {n.bit_length()}, e = {e}")

    state = {'secret_key': None, 'peer': None, 'initiator_done': False}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        # send REGISTER|name|n|e
        send_line(sock, f"REGISTER|{name}|{n}|{e}")
        # start receiver thread
        threading.Thread(target=recv_loop, args=(sock, n, d, state), daemon=True).start()
        print("Tunggu hingga peer terkoneksi dan public key didistribusikan...")
        print("Ketik pesan lalu Enter untuk mengirim (setelah key exchange). Ketik 'KEYSEND' untuk manual mengirim DES key (jika peer pubkey tersedia). Ketik 'exit' untuk keluar.")
        input_loop(sock, state)
    except Exception as ex:
        print("[Connection error]", ex)
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == '__main__':
    main()
