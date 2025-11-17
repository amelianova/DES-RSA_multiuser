# chat_server.py (WITH FULL LOGGING)
import socket
import threading
from typing import Dict

HOST = input("Server IP [localhost]: ").strip() or 'localhost'
PORT = 55555

clients: Dict[str, dict] = {}
order = []


def recv_line(c):
    d = b""
    while True:
        x = c.recv(1024)
        if not x:
            return None
        d += x
        if b"\n" in x:
            break
    return d.decode().strip()


def send(c, t):
    try:
        c.sendall((t + "\n").encode())
    except:
        pass


def handle(conn, addr):
    name = None
    try:
        # REGISTER|name|n|e
        line = recv_line(conn)
        if not line:
            conn.close()
            return

        p = line.split("|")
        if len(p) != 4 or p[0] != "REGISTER":
            send(conn, "ERROR|Format salah")
            conn.close()
            return

        name = p[1]
        n = int(p[2])
        e = int(p[3])

        if name in clients:
            send(conn, "ERROR|Nama sudah dipakai")
            return

        clients[name] = {"conn": conn, "pub": (n, e)}
        order.append(name)

        print(f"[SERVER] Registered {name} from {addr}")
        print(f"[LOG] PUBKEY {name}: n_bits={n.bit_length()} e={e}")

        send(conn, "OK|Registered")

        distribute_keys()

        while True:
            line = recv_line(conn)
            if not line:
                break

            parts = line.split("|", 2)
            typ = parts[0]

            # ==========================
            #  LOG client raw message
            # ==========================
            print(f"[RAW] From {name}")

            if typ == "EXIT":
                print(f"[LOG] {name} disconnected")
                break

            # ==========================
            # KEY exchange forwarding
            # ==========================
            elif typ == "KEY":
                others = [k for k in clients.keys() if k != name]
                if not others:
                    send(conn, "ERROR|Belum ada peer")
                    continue

                target = others[0]
                cipher_hex = parts[1]
                print(f"[LOG] KEY from {name} -> {target}: {cipher_hex}")

                send(clients[target]["conn"], f"KEY|{name}|{cipher_hex}")

            # ==========================
            # MESSAGE forwarding
            # ==========================
            elif typ == "MSG":
                others = [k for k in clients.keys() if k != name]
                if not others:
                    send(conn, "ERROR|Belum ada peer")
                    continue

                target = others[0]
                cipher_hex = parts[1]

                print(f"[LOG] MSG from {name} -> {target}")

                send(clients[target]["conn"], f"MSG|{name}|{cipher_hex}")

            else:
                send(conn, "ERROR|Unknown type")

    except Exception as err:
        print("[SERVER ERROR]", err)

    finally:
        if name in clients:
            print(f"[SERVER] Removing {name}")
            del clients[name]
            if name in order:
                order.remove(name)
        try:
            conn.close()
        except:
            pass


def distribute_keys():
    if len(order) < 2:
        return

    a = order[0]
    b = order[1]

    na, ea = clients[a]["pub"]
    nb, eb = clients[b]["pub"]

    print(f"[SERVER] Distributing pubkeys between {a} and {b}")
    print(f"[LOG] Send PUB to {a}: {b} {nb}:{eb} (initiator)")
    print(f"[LOG] Send PUB to {b}: {a} {na}:{ea}")

    # Initiator = client pertama
    send(clients[a]["conn"], f"PUB|{b}|{nb}:{eb}|INIT")
    send(clients[b]["conn"], f"PUB|{a}|{na}:{ea}")


def main():
    print("Server running...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # FIX: Windows friendly
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.bind((HOST, PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
