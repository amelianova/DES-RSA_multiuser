# chat_client.py
import socket, threading, time, secrets
from DES import encrypt_message, decrypt_message
import rsa

def ask_ip(): return input("Server IP: ").strip()
def ask_port(): 
    p=input("Port [55555]: ").strip()
    return int(p) if p else 55555

def random_des_key(): return secrets.token_hex(8).upper()

def send(sock,msg): sock.sendall((msg+"\n").encode())

def recv_loop(sock,n,d,state):
    buf=b''
    while True:
        x=sock.recv(4096)
        if not x: break
        buf+=x
        while b'\n' in buf:
            line,buf=buf.split(b'\n',1)
            handle(line.decode().strip(),sock,n,d,state)

def handle(line,sock,n,d,state):
    p=line.split('|',3)
    typ=p[0]

    if typ=="OK":
        print("[Server]",p[1]);return

    if typ=="PUB":
        peer=p[1]
        ne=p[2]
        flag=p[3] if len(p)>3 else None
        n2,e2=ne.split(':')
        state['peer']={'name':peer,'n':int(n2),'e':int(e2)}
        print(f"[Server] PUB from {peer}, INIT={flag}")

        if flag=="INIT":
            time.sleep(0.3)
            key=random_des_key()
            state['secret']=key
            m=rsa.hexstr_to_int(key)
            c=rsa.rsa_encrypt_int(m,int(n2),int(e2))
            send(sock,f"KEY|{format(c,'x')}")
            state['initiator']=True
            print(f"[INITIATOR] Sent DES key: {key}")
        return

    if typ=="KEY":
        sender=p[1]
        c=int(p[2],16)
        m=rsa.rsa_decrypt_int(c,n,d)
        key=format(m,'x').upper().rjust(16,'0')
        state['secret']=key
        print(f"[KEY RECEIVED] {sender}: {key}")
        return

    if typ=="MSG":
        sender=p[1]; ch=p[2]
        print(f"\n<< From {sender}: {ch} >>")
        if not state['secret']:
            print("No DES key!");return
        try:
            pt=decrypt_message(ch,state['secret'])
            print(f"{sender}(dec): {pt}")
        except Exception as e:
            print("[Decrypt ERROR]",e)
        return

def input_loop(sock,state):
    while True:
        msg=input()
        if msg=="exit":
            send(sock,"EXIT|")
            break
        if not state['secret']:
            print("Belum ada DES key.");continue
        try:
            c=encrypt_message(msg,state['secret'])
            print(f"<< Sent ciphertext: {c} >>")
            send(sock,f"MSG|{c}")
        except Exception as e:
            print("[Encrypt ERROR]",e)

def main():
    ip=ask_ip(); port=ask_port()
    name=input("Your name: ").strip()
    print("[*] Generating RSA key...")
    n,e,d=rsa.generate_rsa_keypair(768)

    state={'secret':None,'peer':None,'initiator':False}

    sock=socket.socket()
    sock.connect((ip,port))

    send(sock,f"REGISTER|{name}|{n}|{e}")
    threading.Thread(target=recv_loop,args=(sock,n,d,state),daemon=True).start()

    print("Tunggu public key peer...")
    input_loop(sock,state)

if __name__=="__main__":
    main()
