import socket
import select
import requests
import threading
import re
import time
import struct
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOCKS_VERSION = 5
client1 = None
username = "username"
password = "password"

def handle_client(connection):
    version, nmethods = connection.recv(2)
    methods = get_available_methods(nmethods, connection)
    if 2 not in set(methods):
        connection.close()
        return
    connection.sendall(bytes([SOCKS_VERSION, 2]))
    if not verify_credentials(connection):
        return
    version, cmd, _, address_type = connection.recv(4)
    if address_type == 1:
        address = socket.inet_ntoa(connection.recv(4))
    elif address_type == 3:
        domain_length = connection.recv(1)[0]
        address = connection.recv(domain_length)
        address = socket.gethostbyname(address)
    port = int.from_bytes(connection.recv(2), 'big', signed=False)
    try:
        if cmd == 1:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()
        else:
            connection.close()
            return
        addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
        port = bind_address[1]
        port2 = port
        reply = b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(1).to_bytes(1, 'big'),
            addr.to_bytes(4, 'big'),
            port.to_bytes(2, 'big')
        ])
    except Exception as e:
        reply = generate_failed_reply(address_type, 5)
    connection.sendall(reply)
    if reply[1] == 0 and cmd == 1:
        exchange_loop(connection, remote, port2)
    connection.close()

def exchange_loop(client, remote, port):
    global client1
    while True:
        r, w, e = select.select([client, remote], [], [])
        if port = 36999:
            client1 = client
        if client in r:
            dataC = client.recv(4096)
            if remote.send(dataC) <= 0:
                break
        if remote in r:
            data = remote.recv(4096)
            if b"/HELP" in dataS:
                id = dataS.hex()[12:22]
                dor = "050000002008*100520162a1408*109e84bbb1032a0608*"
                raks = dor.replace('*', id)
                client1.send(bytes.fromhex(raks))
            if client.send(data) <= 0:
                break
def generate_failed_reply(address_type, error_number):
    return b''.join([
        SOCKS_VERSION.to_bytes(1, 'big'),
        error_number.to_bytes(1, 'big'),
        int(0).to_bytes(1, 'big'),
        address_type.to_bytes(1, 'big'),
        int(0).to_bytes(4, 'big'),
        int(0).to_bytes(4, 'big')
    ])

def verify_credentials(connection):
    version = connection.recv(1)[0]
    username_len = connection.recv(1)[0]
    username = connection.recv(username_len).decode('utf-8')
    password_len = connection.recv(1)[0]
    password = connection.recv(password_len).decode('utf-8')
    if username == username and password == password:
        response = bytes([version, 0])
        connection.sendall(response)
        return True
    else:
        response = bytes([version, 0])
        connection.sendall(response)
        return True

def get_available_methods(nmethods, connection):
    methods = []
    for _ in range(nmethods):
        methods.append(connection.recv(1)[0])
    return methods
def run(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen()
    print(f"* Socks5 proxy server is running on {ip}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()
def start_bot():
    run("127.0.0.1", 3000)

if __name__ == "__main__":
    start_bot()
