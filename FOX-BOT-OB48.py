import socket
import select
import requests
import threading
import re
import time
import struct
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables
Ghost = False
back = False
enc_client_id = None
inviteD = False
SOCKS_VERSION = 5
invit_spam = False

username = "username"
password = "password"
website = "https://api-ghost.vercel.app/FFcrypto/{id}"
last_check_time = 0  # وقت آخر تحقق

def spam_invite(data, remote):
    global invit_spam
    while invit_spam:
        try:
            for _ in range(5):
                remote.send(data)
                time.sleep(0.04)
            time.sleep(0.2)
        except:
            pass

def fake_friend(client, id: str):
    if len(id) == 8:
        packet = '060000007708d4d7faba1d100620022a6b08cec2f1051a1b5b3030464630305d2b2b2020202047484f53545b3030464630305d32024d454049b00101b801e807d801d4d8d0ad03e001b2dd8dae03ea011eefbca8efbca5efbcb2efbcafefbcb3efbca8efbca9efbcadefbca1efa3bf8002fd98a8dd03900201d00201'
        packet = re.sub(r'cec2f105', id, packet)
        client.send(bytes.fromhex(packet))
    elif len(id) == 10:
        packet = '060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d2b2be385a447484f535420205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221'
        packet = re.sub(r'fb9db9ae06', id, packet)
        client.send(bytes.fromhex(packet))
    else:
        print(id)

def encrypt_id(id):
    api_url = website.format(id=id)

    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            return response.text
        else:
            print("&#1601;&#1588;&#1604; &#1601;&#1610; &#1580;&#1604;&#1576; &#1575;&#1604;&#1576;&#1610;&#1575;&#1606;&#1575;&#1578;. &#1585;&#1605;&#1586; &#1575;&#1604;&#1581;&#1575;&#1604;&#1577;:", response.status_code)
            return None
    except requests.RequestException as e:
        print("&#1601;&#1588;&#1604; &#1575;&#1604;&#1591;&#1604;&#1576;:", e)
        return None

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
        exchange_loop(connection, remote)
    connection.close()

def gen_squad5(sock0500, EncryptedPlayerid):
    ent_packet = f"050000030608{EncryptedPlayerid}100520082af90508{EncryptedPlayerid}1af00508{EncryptedPlayerid}12024d451801200432f50408{EncryptedPlayerid}1211e385a4e1b49ce1b498e385a4e1afa4ccb81a024d4520a4fda7b40628423084cbd13042188993e660c0bcce64e796a361fb9ae061948b8866e8b6ce64480150d70158851568e4b58fae037a0a9cd2cab00392d0f2b20382012608efdaf1eb04120cd8afd98ad8b1d8acd8a7d985180720f087d4f0042a0808ca9d85f304100392010b010307090a0b12191a1e209801dd01a0017fba010b08d6f9e6a202100118d702c00101e80105f0010e880203920208ae2d8d15ba29b810aa0208080110cc3a18a01faa0208080210f02e188827aa020a080f108e781888272001aa0205081710a14faa0205081810df31aa0205081c108f31aa0205082010c430aa0205082110cb30aa0205082210dd31aa0205082b10f02eaa0205083110f02eaa0205084910f936aa0205081a108e78aa02050823108e78aa02050839108e78aa0205083d108e78aa02050841108e78aa0205084d10e432aa0205081b108e78aa02050834108e78aa0205082810e432aa0205082910e432c2026012031a01011a3f084812110104050607f1a802f4a802f2a802f3a8021a0d08f1a802100318ec0220c3ca011a0d08f2a802100318940320a3e8041a0a08f3a802100220fec2011a0508501201631a060851120265662209120765890eed0ed904d802a8a38daf03ea020410011801f2020b0883cab5ee0110b00218018a030092032a0a13080310f906180f201528f0bbacb40632024d450a13080610a50e180f200a28f0bbacb40632024d459803fdb4b4b20ba203044d454523a80368b00302b80301c203080828100118032001c20308081a100f1803200cca030a0801109b85b5b4061801ca030a080910abf6b0b4061801d003013a011a403e50056801721e313732303331393634393738313931313136365f616471383367366864717801820103303b30880180e0aee990ede78e19a20100b00114ea010449444331fa011e313732303331393634393738313931353431355f317475736c316869396a"
    sock0500.send(bytes.fromhex(ent_packet))

def invisible1(sock0500, EncryptedPlayerid):
    ent_packet = f" 050000030d08{EncryptedPlayerid}1005203a2a800608{EncryptedPlayerid}12024d4518012005328c0508{EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885e29a91efbca7efbca8efbcafefbcb3efbcb41a024d4520de90ebb80628443087cbd1303832421883938866ddcea561a6c2e860f4bece64f39ae0619cb9ce64480150dc0158e21c60998fd3ad0368f4dc8dae037a05b092c5b00382012708dbdaf1eb04120d7be28886c2a9cf80c2a9c2ae7d180720e187d4f0042a0808c89d85f30410038801c2ffc4b00392010c0107090a0b120e16191a1e209801d401a0012ca80185fff5b103c00101d001b6cb8aaf03e80101880203920207c205b60969a926aa0207080110dc3d2004aa0205080210a038aa0208080f10d63618904eaa0205081710aa51aa02050818108242aa0205081a10b836aa0205081b10d636aa0205081c109a42aa0205082010da3daa0205082110f02eaa0205082210c935aa0205082310eb2faa0205082b10862faa0205083110f02eaa0205083910f95daa0205084910fa33aa0205083d10d636aa0205084110d636aa0205084d10e432aa0205083410d636aa0205082810e432aa0205082910e432c202a90112031a01011a6f0848121001040506070203f1a802f4a802f2a8021a0b0806100118880420a48e1c1a0b0801100318810320f0a0031a0b0802100418fb0620e7f4041a0b0803100418ef0520ddbb0b1a0b0807100118ff0120c589051a0d08f1a802100318cd0320dc81051a0908f3a802100120b14d1a1208501201631a0b0863100a18940720d3d90c1a100851120265661a08086620c81528d407220b120965890eed0ed904ad02d802a8a38daf03ea020410011801f202090882cab5ee0110b0088a0300920300a80366b00301c2030a081c100f180220022801ca030a0806108b99fab8061801ca030a0802108b99fab8061801e203014fea03003a011a403e50056801721e313732393830383339323636343834313338335f6d7531726c6835303164880180909baef882c1d519a20100b001e201ea010449444332fa011e313732393830383339323636343834343134335f6a336d347a7972303337"
    sock0500.send(bytes.fromhex(ent_packet))

def gen_squad6(sock0500, EncryptedPlayerid):
    ent_packet = f"050000030d08{EncryptedPlayerid}1005203a2a800608{EncryptedPlayerid}12024d4518012005328c0508{EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885e29a91efbca7efbca8efbcafefbcb3efbcb41a024d4520de90ebb80628443087cbd1303832421883938866ddcea561a6c2e860f4bece64f39ae0619cb9ce64480150dc0158e21c60998fd3ad0368f4dc8dae037a05b092c5b00382012708dbdaf1eb04120d7be28886c2a9cf80c2a9c2ae7d180720e187d4f0042a0808c89d85f30410038801c2ffc4b00392010c0107090a0b120e16191a1e209801d401a0012ca80185fff5b103c00101d001b6cb8aaf03e80101880203920207c205b60969a926aa0207080110dc3d2004aa0205080210a038aa0208080f10d63618904eaa0205081710aa51aa02050818108242aa0205081a10b836aa0205081b10d636aa0205081c109a42aa0205082010da3daa0205082110f02eaa0205082210c935aa0205082310eb2faa0205082b10862faa0205083110f02eaa0205083910f95daa0205084910fa33aa0205083d10d636aa0205084110d636aa0205084d10e432aa0205083410d636aa0205082810e432aa0205082910e432c202a90112031a01011a6f0848121001040506070203f1a802f4a802f2a8021a0b0806100118880420a48e1c1a0b0801100318810320f0a0031a0b0802100418fb0620e7f4041a0b0803100418ef0520ddbb0b1a0b0807100118ff0120c589051a0d08f1a802100318cd0320dc81051a0908f3a802100120b14d1a1208501201631a0b0863100a18940720d3d90c1a100851120265661a08086620c81528d407220b120965890eed0ed904ad02d802a8a38daf03ea020410011801f202090882cab5ee0110b0088a0300920300a80366b00301c2030a081c100f180220022801ca030a0806108b99fab8061801ca030a0802108b99fab8061801e203014fea03003a011a403e50056801721e313732393830383339323636343834313338335f6d7531726c6835303164880180909baef882c1d519a20100b001e201ea010449444332fa011e313732393830383339323636343834343134335f6a336d347a7972303337"
    sock0500.send(bytes.fromhex(ent_packet))

def gen_squad8(sock0500, EncryptedPlayerid):
    ent_packet = f"05000004d908{EncryptedPlayerid}100520062acc0908{EncryptedPlayerid}12024d451801200332ef0408{EncryptedPlayerid}1221e28094cd9ecd9fcd9ee29885efbca8efbcafefbcb3efbcb3efbca1efbcadefbca51a024d4520d4f4babc0628443087cbd13038324218869be06183938866a9b7d0649cb9ce64ddcea561a6c2e860480150cf0158900d60c5d8d0ad0368f9db8dae037a05b092c5b003820121089fdaf1eb041207247b7a61796e7d180720a387d4f0042a0808c29d85f30410038801c2ffc4b00392010c010407090a0b120e16191a209801cf01a00118a80185fff5b103c00101e80101880203920208c205a92df9038a07aa0207080110e4322004aa0205080210a038aa0208080f10853218904eaa0205081710aa51aa02050818108242aa0205081a10b836aa0205081b108532aa0205081c109a42aa0205082010da3daa0205082110f02eaa0205082210c935aa0205082310eb2faa0205082b10f02eaa0205083110f02eaa0205083910f95daa0205084910fa33aa0205083d108532aa02050841108532aa0205084d10e432aa02050834108532aa0205082810f02eaa0205082910e432c202a90112031a01011a6f0848121001040506070203f1a802f4a802f2a8021a0b0806100118880420a48e1c1a0b0801100318810320f0a0031a0b0802100418fb0620e7f4041a0b0803100418ef0520ddbb0b1a0b0807100118ff0120c589051a0d08f1a802100318cd0320dc81051a0908f3a802100120b14d1a1208501201631a0b0863100a18940720d3d90c1a100851120265661a08086620c81528d407220b120965890eed0ed904ad02d802a8a38daf03ea020410011801f202090885cab5ee0110a8018a0300920300a80366c2030a081d100f180220012801e203014fea0300f2030080045f90040232e403089bc68ad21f1224efb5bcefb5afefb5bcefb5afefb5bcefb5afefb5bcefb5afefb5bcefbca8efbca5efbcb81a024d4520d9f4babc0628073087cbd13038324218ab94e660d19ce261d2c385669fbace64e996a3619ebace64480150c90158e80760868fd3ad0368c79390ae037a05b59dc5b00382011808b3daf1eb04180420b487d4f0042a0808c49d85f304100392010a0107090a120e16191a209801c901a00101c00101e80101880203920205c205000000aa0207080110e4322001aa0208080f10a63118904eaa0205081710ee32aa0205082b10f02eaa0205080210e432aa0205081810a631aa0205081a10a631aa0205081c10a631aa0205082010a631aa0205082210a631aa0205082110a631aa0205082310a631aa0205083110f02eaa0205083910a631aa0205083d10a631aa0205084110a631aa0205084910d836aa0205084d10e432aa0205081b10a631aa0205083410a631aa0205082810904eaa0205082910e432b00201c2022812041a0201041a0f0848120b0104050607f1a802f4a8021a0508501201631a060851120265662200d802c5d8a5af03ea0204100118018a03009203009803ddb6b2ab0ba2031eefbca8efbca5efbcb8e385a4e29cbfe385a4efbcb4efbca5efbca1efbcade203024f52ea0300f203008004649004023a01014001500260016801721e313733373430373036303733303437383236375f74776168373565767a7688018090fbf3dcd68f8e1aa20100b001e301ea010449444332fa011e313733373430373036303733303438313336305f6172397538656a793571"
    sock0500.send(bytes.fromhex(ent_packet))
def exchange_loop(client, remote):
    global inviteD
    global back
    global Ghost
    global encid
    global enc_id
    while True:
        r, w, e = select.select([client, remote], [], [])
        if client in r:
            dataC = client.recv(4096)
            if remote.send(dataC) <= 0:
                break
        if remote in r:
            data = remote.recv(4096)
            if '1200' in data.hex()[0:4] and b'/5' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.gen_squad5).start()
                
            if client.send(data) <= 0:
                break              
#################################### 
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
def fetch_data_from_url():
    data_url = "http://botv61gsh.atwebpages.com/data.txt"
    try:
        response = requests.get(data_url, verify=False)
        if response.status_code == 200:
            return response.text
        else:
            print("Failed to fetch external data. Status code:", response.status_code)
            return None
    except requests.RequestException as e:
        print("Failed to connect to external data source:", e)
        return None
def start_bot():
    run("127.0.0.1", 3000)

if __name__ == "__main__":
    start_bot()
