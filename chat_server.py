# chat_server_fixed.py
import socket
import threading
from typing import Dict

HOST = '192.168.100.163'
PORT = 55555

clients: Dict[str, dict] = {}
clients_lock = threading.Lock()
registration_order = []  # keep order of registration

def recv_line(conn):
    data = b''
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            return None
        data += chunk
        if b'\n' in chunk:
            break
    return data.decode('utf-8').strip()

def send_line(conn, text):
    try:
        conn.sendall((text + '\n').encode('utf-8'))
    except:
        pass

def handle_client(conn, addr):
    try:
        line = recv_line(conn)
        if not line:
            conn.close()
            return
        parts = line.split('|')
        if len(parts) != 4 or parts[0] != 'REGISTER':
            send_line(conn, "ERROR|Invalid registration format. Use REGISTER|<name>|<n>|<e>")
            conn.close()
            return
        _, name, n_str, e_str = parts
        with clients_lock:
            if name in clients:
                send_line(conn, "ERROR|Name already taken")
                conn.close()
                return
            clients[name] = {'conn': conn, 'addr': addr, 'pub': (int(n_str), int(e_str))}
            registration_order.append(name)
        print(f"[SERVER] Registered client '{name}' from {addr}.")
        send_line(conn, "OK|Registered")
        distribute_public_keys_if_ready()
        while True:
            line = recv_line(conn)
            if not line:
                print(f"[SERVER] Connection lost from {name}")
                break
            parts = line.split('|', 2)
            typ = parts[0]
            if typ == 'EXIT':
                break
            elif typ in ('KEY', 'MSG'):
                with clients_lock:
                    other_names = [k for k in clients.keys() if k != name]
                    if not other_names:
                        send_line(conn, "ERROR|No peer connected yet")
                        continue
                    other = other_names[0]
                    other_conn = clients[other]['conn']
                send_line(other_conn, f"{typ}|{name}|{parts[1]}")
                print(f"[SERVER] Forwarded {typ} from {name} -> {other}")
            else:
                send_line(conn, "ERROR|Unknown message type")
    except Exception as e:
        print(f"[SERVER] Error in client handler: {e}")
    finally:
        with clients_lock:
            to_remove = None
            for k, v in list(clients.items()):
                if v['conn'] == conn:
                    to_remove = k
            if to_remove:
                del clients[to_remove]
                try:
                    registration_order.remove(to_remove)
                except:
                    pass
                print(f"[SERVER] Client '{to_remove}' disconnected and removed")
                for rem in clients.values():
                    try:
                        send_line(rem['conn'], f"INFO|Peer {to_remove} disconnected")
                    except:
                        pass
        try:
            conn.close()
        except:
            pass

def distribute_public_keys_if_ready():
    with clients_lock:
        if len(clients) < 2:
            return
        # pick two in registration order to keep determinism
        a, b = registration_order[0], registration_order[1]
        na, ea = clients[a]['pub']
        nb, eb = clients[b]['pub']
        # Send B's pubkey to A; mark A as INIT (initiator)
        send_line(clients[a]['conn'], f"PUB|{b}|{nb}:{eb}|INIT")
        # Send A's pubkey to B; B will not be initiator
        send_line(clients[b]['conn'], f"PUB|{a}|{na}:{ea}")
        print(f"[SERVER] Distributed public keys: {a} (initiator) <-> {b}")

def main():
    print("=== PK-Authority + Relay Chat Server (fixed) ===")
    print(f"Listening on {HOST}:{PORT}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down")
    finally:
        srv.close()

if __name__ == '__main__':
    main()
