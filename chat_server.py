# chat_server.py
import socket
import threading
from typing import Dict

HOST = '0.0.0.0'
PORT = 55555

clients: Dict[str, dict] = {}
order = []

def recv_line(c):
    d=b''
    while True:
        x=c.recv(1024)
        if not x:
            return None
        d+=x
        if b'\n' in x:
            break
    return d.decode().strip()

def send(c,t):
    try: c.sendall((t+'\n').encode())
    except: pass

def handle(conn,addr):
    try:
        line=recv_line(conn)
        if not line:
            conn.close();return
        p=line.split('|')
        if len(p)!=4 or p[0]!="REGISTER":
            send(conn,"ERROR|Format salah")
            conn.close();return
        name=p[1]; n=p[2]; e=p[3]
        if name in clients:
            send(conn,"ERROR|Nama sudah dipakai");return

        clients[name]={"conn":conn,"pub":(int(n),int(e))}
        order.append(name)
        print(f"[SERVER] Registered {name}")
        send(conn,"OK|Registered")

        distribute()

        while True:
            line=recv_line(conn)
            if not line:
                break
            s=line.split("|",2)
            typ=s[0]
            if typ=="EXIT": break
            if typ in ("KEY","MSG"):
                other=[k for k in clients.keys() if k!=name]
                if not other:
                    send(conn,"ERROR|No peer");continue
                o=other[0]
                send(clients[o]["conn"],f"{typ}|{name}|{s[1]}")
    except: pass
    finally:
        if name in clients:
            del clients[name]
            order.remove(name)
        try: conn.close()
        except: pass

def distribute():
    if len(order)<2: return
    a,b=order[0],order[1]
    na,ea=clients[a]['pub']
    nb,eb=clients[b]['pub']
    send(clients[a]['conn'],f"PUB|{b}|{nb}:{eb}|INIT")
    send(clients[b]['conn'],f"PUB|{a}|{na}:{ea}")
    print(f"[SERVER] Distributed keys: {a}(INIT) <-> {b}")

def main():
    print("Server running...")
    s=socket.socket()
    s.setsockopt(1,2,1)
    s.bind((HOST,PORT))
    s.listen(5)
    while True:
        c,a=s.accept()
        threading.Thread(target=handle,args=(c,a),daemon=True).start()

if __name__=="__main__":
    main()
