import socket
import select
import requests
import threading
import re
import time
import struct
import os
import codecs
import random,string

Besto = False
back = False
enc_client_id = None
SOCKS_VERSION = 5
inviteD = False
back = False
invit_spam = False
Si_Zbi = False
Spy = False

def Besto_Msg(id, msg):
    url = f"https://besto-api-msg.vercel.app/Besto-Msg?Id={id}&Msg={msg}&Key=C4-BESTO-AK8L"
    response = requests.get(url)    
    if response.status_code == 200:
        packet = response.text
        return packet
    else:
        return f" - Error: {response.status_code}"


def destroy(remote,dataC):
    for i in range(50):
    	 time.sleep(0.010)
    	 for i in range(25):
    	     remote.send(dataC)
    time.sleep(0.5)

def enc(id):
    url = "https://besto-api-enc.vercel.app/Enc/12345678?Key=Besto-K7J9"
    response = requests.get(url)
    if response.status_code == 200:
        match = re.search(r"EncryPted Id : (\S+)", response.text)
        if match:
            Enc_Iddd = match.group(1)
            return Enc_Iddd
    return " - Besto Off The Server !"
    
def Enc_ID(id):
    url = f"https://besto-enc-id.vercel.app/Enc/{id}?Key=C4-Besto-K6JK"
    response = requests.get(url)
    if response.status_code == 200:
        match = re.search(r"EncryPted Id : (\S+)", response.text)
        if match:
            Enc_Iddd = match.group(1)
            return Enc_Iddd
    return " - Besto Off The Server !"
    
def Dec_ID(id):
    url = f"https://besto-dec-id.vercel.app/Dec/{id}?Key=C4-Besto-K6PJ"
    response = requests.get(url)
    if response.status_code == 200:
        match = re.search(r"DecryPted Id : (\S+)", response.text)
        if match:
            Dec_Iddd = match.group(1)
            return Dec_Iddd
    return " - Besto Off The Server !"
    
    
def get_status(Iddd):
    cookies = {
    '_ga_KE3SY7MRSD': 'GS1.1.1725471621.1.1.1725471621.0.0.0',
    '_ga_RF9R6YT614': 'GS1.1.1725471621.1.0.1725471621.0.0.0',
    '_ga': 'GA1.2.729761373.1725471621',
    '_gid': 'GA1.2.1093335350.1725471622',
    '_gat_gtag_UA_207309476_25': '1',
}
    headers = {
    'authority': 'ff.garena.com',
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9',
    'referer': 'https://ff.garena.com/en/support/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
    'x-requested-with': 'B6FksShzIgjfrYImLpTsadjS86sddhFH',
}

    params = {
    'lang': 'en',
    'uid': Iddd,
}

    response = requests.get('https://ff.garena.com/api/antihack/check_banned', params=params, cookies=cookies, headers=headers)

    if '1' in response.text:
    	return 'Banned!'
    else:
    	return 'Not Banned'
    	
def Get_Name(iddd):
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{iddd}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("Erorr!")
    except:
        return("No Name!")	   
        
def color():
    Bestoo_Co = ['[ff4500]', '[ffd700]', '[32cd32]', '[87ceeb]', '[9370db]', '[ff69b4]', '[8a2be2]', '[00bfff]', '[1e90ff]', '[20b2aa]', 
'[00fa9a]', '[008000]', '[ffff00]', '[ff8c00]', '[dc143c]', '[ff6347]', '[ffa07a]', '[ffdab9]', '[cd853f]', '[d2691e]', 
'[bc8f8f]', '[f0e68c]', '[556b2f]', '[808000]', '[4682b4]', '[6a5acd]', '[7b68ee]', '[8b4513]', '[c71585]', '[4b0082]', 
'[b22222]', '[228b22]', '[8b008b]', '[483d8b]', '[556b2f]', '[800000]', '[008080]', '[000080]', '[800080]', '[808080]', 
'[a9a9a9]', '[d3d3d3]', '[f0f0f0]']
    Besto_Collor = random.choice(Bestoo_Co)
    return Besto_Collor
                                 	                     	
def gen_squad(clisocks, packet: str):
        header = packet[0:62]
        lastpacket = packet[64:]
        squadcount = "04"
        NewSquadData = header + squadcount + lastpacket
        clisocks.send(bytes.fromhex(NewSquadData))
        
def gen_msg4(packet, content):
        content = content.encode("utf-8")
        content = content.hex()
        header = packet[0:8]
        packetLength = packet[8:10]
        packetBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2 = packet[34:62]
        pyloadlength = packet[62:64]
        pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+64):]
        NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
        NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
        NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
        return str(NewMsgPacket)
        
def gen_msgv3(packet , replay):
        replay = replay.encode('utf-8')
        replay = replay.hex()
        hedar = packet[0:8]
        packetLength = packet[8:10]
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2= packet[34:60]
        pyloadlength = packet[60:62]
        pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+62):]
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]
        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        return str(finallyPacket)    
          
def Clan(replay,packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    if "googleusercontent" in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    else:
        pyloadlength = packet[64:66]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+66):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket

def send_msg_friends(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10]
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2 = packet[34:60]
	pyloadlength = packet[60:62]
	pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
	Tipy = packet[int(int(len(pyloadtext))+62):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	Nepalh = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
	Nepylh = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
	st_pack = hd + Nepalh + paketBody + Nepylh + pyloadbody2 + NewTextLength + replay + Tipy
	return st_pack

def send_msg_clan(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]#
	pyloadbody2 = packet[34:64]
	if "googleusercontent" in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
	elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
		print(bytes.fromhex(pyloadlength))
	else:
		pyloadlength = packet[64:66]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+66):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
	st_pack = hd + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + Tipy
	return st_pack
	        
def send_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(gen_msg4(packet, content)))  
                sock.send(bytes.fromhex(Clan(packet, content)))
                sock.send(bytes.fromhex(gen_msgv3(packet, content)))
        except Exception as e:
                pass

def Fr(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(send_msg_friends(packet, content)))  
        except Exception as e:
                pass                                
                
def Clan_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(Clan(packet, content)))
        except Exception as e:
                pass   
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text

def dance(id):
    Besto_Dances = [f"050000002008{id}100520162a1408{id}1084fbb8b1032a0608{id}", f"050000002008{id}100520162a1408{id}10a2fbb8b1032a0608{id}", f"050000002008{id}100520162a1408{id}10edbabbb1032a0608{id}", f"050000002008{id}100520162a1408{id}10d6c2bbb1032a0608{id}", f"050000002008{id}100520162a1408{id}109684bbb1032a0608{id}", f"050000002008{id}100520162a1408{id}109e84bbb1032a0608{id}", f"050000002008{id}100520162a1408{id}10ca9bbbb1032a0608{id}", f"050000002008{id}100520162a1408{id}10b9cabbb1032a0608{id}", f"050000002008{id}100520162a1408{id}108bfbb8b1032a0608{id}", f"050000002008{id}100520162a1408{id}10fffab8b1032a0608{id}", f"050000002008{id}100520162a1408{id}10ff8bbbb1032a0608{id}"]
    sex1 = random.choice(Besto_Dances)
    return sex1
                                                                         	                                 
class Proxy:
    def __init__(self):
        self.username = "username"
        self.password = "password"
        self.website = f"https://besto-api-enc.vercel.app/Enc/{id}?Key=Besto-K7J9"
        self.Beston = False
        self.Server = False
#
    def fake_friend(self, client, id: str):
        if len(id) == 8:
            packet = '060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d4334e385a44641434b4520205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221'
            packet = re.sub(r'cec2f105', id, packet)
            client.send(bytes.fromhex(packet))
        elif len(id) == 10:            
            packet = '060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d4334e385a44641434b4520205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221'
            packet = re.sub(r'fb9db9ae06', id, packet)
            client.send(bytes.fromhex(packet))
        else:
            print(id)

    def Encrypt_ID(self, id):
        try:
            response = requests.get(f'https://besto-api-enc.vercel.app/Enc/{id}?Key=Besto-K7J9')
            if response.status_code == 200:
                match = re.search(r"EncryPted Id : (\S+)", response.text)
                if match:
                	Enc_Iddd = match.group(1)
                	return Enc_Iddd                	
            else:
                print("فشل في جلب البيانات. رمز الحالة:", response.status_code)
                return None
        except requests.RequestException as e:
            print("فشل الطلب:", e)
            return None
            
    def handle_client(self, connection):
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS_VERSION, 2]))
        if not self.verify_credentials(connection):
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
            reply = self.generate_failed_reply(address_type, 5)
        connection.sendall(reply)
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote,port)
        connection.close()
        
    def help(self):
        zby = f"120000018d08{self.EncryptedPlayerid}101220022a800308{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22d2015b625d5b635d5b6161656430655d2d2057656c636f6d6520546f205b4646423733325d435b4646434135355d345b4646443936465d20425b4646453538365d4f5b4646454439435d545b4646463542315d20565b4646464243435d5b4646464243435d325b6637656435635d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(zby))
        
    def help01(self):
        zby = f"120000018d08{self.EncryptedPlayerid}101220022a800308{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22d2015b625d5b635d5b6637656435635d0aefbba3d980efbaaeefbaa3d980efba92efba8e20efba91efbb9a20efbb93efbbb220d8a7efbb9fefba92efbbaed8aa20d8a7efbb9fefbaa8efba8ed8b520efba91efbba8efba8e20d8a7efbbb3efbbacefba8e20d8a7efbb9fefbba4efbab4efba98efbaa8efbaaad98520d89b20efbba7efbaa4efbba620efbab3efbb8cefbbb4efbaaad988d98620d98420d8a7efbab3efba98efbaa8efbaaad8a7efbba3efbb9a20d8a7efbb9fefba92efbbaed8aa20d8a7efbb9fefbaa8efba8ed8b520efba91ef28f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(zby))
           
   
    def help1(self):  
        Hakim_Packets = f"120000018d08{self.EncryptedPlayerid}101220022a800308{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22d2015b625d5b635d4d656e752031203a200a202020200a5b6161656430655d2d202f3573203e203520496e2053716975640a2d202f3673203e203620496e2053716975640a2d202f796f7574203e20596f7554756265727320496e20467265696e64200a2d202f6c696b655b69645d203e2053656e64204c696b65730a2d202f696e666f5b69645d203e2047657420496e666f204f66204964000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(Hakim_Packets))

    def help2(self):        
        Hakim_Packets = f"120000018d08{self.EncryptedPlayerid}101220022a800308{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22d2015b625d5b635d4d656e752032203a200a0a5b6666343537615d2d202f6164645b69645d203e204661636b20467265696e640a2d202f70635b69645d203e204c6f676f2050630a2d202f6765745b69645d203e20476574205371756964204c65616465720a2d202f6b69636b203e20537079202d20416e74694b69636b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(Hakim_Packets))
        
    def help3(self):        
        Hakim_Packets = f"120000018d08{self.EncryptedPlayerid}101220022a800308{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22d2015b625d5b635d4d656e752033203a200a202020200a5b3532346666665d2d202f73706d5b6d73675d203e205370616d204d657373616765730a2d202f696e76203e205370616d20496e76697465730a2d202f656d6f746573203e204d656e7520456d6f7465730a2d202f636f6465203e20526f6f6d20436f64650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(Hakim_Packets))
        
    def help4(self):        
        Hakim_Packets = f'120000018d08{self.EncryptedPlayerid}101220022a800308{self.EncryptedPlayerid}10{self.EncryptedPlayerid}22d2015b625d5b635d4d656e752034203a200a5b6666363334375d0a2d202f646e203e204765742044616e63650a2d202f64735b69645d203e2044616e636520506c61796572204964200a2d202f7370616d5b69645d203e205370616d2052657175657374730a2d202f433469203e20496e666f204f6620596f7572204163630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200'
        self.sock1200.send(bytes.fromhex(Hakim_Packets))
                
    def gen_squad6(self):        
        Besto_Packets = f'050000032708{self.EncryptedPlayerid}100520082a9a0608dbdcd7cb251a910608{self.EncryptedPlayerid}12024d4518012005329d0508{self.EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d050000031e08{self.EncryptedPlayerid}1005203a2a910608{self.EncryptedPlayerid}12024d4518012005329d0508{self.EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d'   
        self.sock0500.send(bytes.fromhex(Besto_Packets))  
               
    def gen_squad5(self):        
        Besto_Packets = f"050000030608{self.squad_gen}100520082af90508{self.squad_gen}1af00508{self.EncryptedPlayerid}12024d451801200432f50408{self.EncryptedPlayerid}1211e385a4e1b49ce1b498e385a4e1afa4ccb81a024d4520a4fda7b40628423084cbd13042188993e660c0bcce64e796a361fb9ae061948b8866e8b6ce64480150d70158851568e4b58fae037a0a9cd2cab00392d0f2b20382012608efdaf1eb04120cd8afd98ad8b1d8acd8a7d985180720f087d4f0042a0808ca9d85f304100392010b010307090a0b12191a1e209801dd01a0017fba010b08d6f9e6a202100118d702c00101e80105f0010e880203920208ae2d8d15ba29b810aa0208080110cc3a18a01faa0208080210f02e188827aa020a080f108e781888272001aa0205081710a14faa0205081810df31aa0205081c108f31aa0205082010c430aa0205082110cb30aa0205082210dd31aa0205082b10f02eaa0205083110f02eaa0205084910f936aa0205081a108e78aa02050823108e78aa02050839108e78aa0205083d108e78aa02050841108e78aa0205084d10e432aa0205081b108e78aa02050834108e78aa0205082810e432aa0205082910e432c2026012031a01011a3f084812110104050607f1a802f4a802f2a802f3a8021a0d08f1a802100318ec0220c3ca011a0d08f2a802100318940320a3e8041a0a08f3a802100220fec2011a0508501201631a060851120265662209120765890eed0ed904d802a8a38daf03ea020410011801f2020b0883cab5ee0110b00218018a030092032a0a13080310f906180f201528f0bbacb40632024d450a13080610a50e180f200a28f0bbacb40632024d459803fdb4b4b20ba203044d454523a80368b00302b80301c203080828100118032001c20308081a100f1803200cca030a0801109b85b5b4061801ca030a080910abf6b0b4061801d003013a011a403e50056801721e313732303331393634393738313931313136365f616471383367366864717801820103303b30880180e0aee990ede78e19a20100b00114ea010449444331fa011e313732303331393634393738313931353431355f317475736c316869396a"
        self.sock0500.send(bytes.fromhex(Besto_Packets))

    def garinafreefire(self):
        ent_packet = f"050000036c08{self.EncryptedPlayerid}100520062adf0608{self.EncryptedPlayerid}12024d4518012003328b0308{self.EncryptedPlayerid}1221e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e28c9a1a024d4520b893b5b5062805308fcbd13038324218c091e6608096a361c09ae06180a89763c0b5ce6480c38566480150c90158e80782011808b3daf1eb04180120b387d4f0042a0808c49d85f304100392010c010307090a0b1216191a1e209801c901c00101e8010188020b9202029e11aa020a08011090351880642002aa0208080f10e43218904eaa0205082b10bd32aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205083110bd32aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910d836aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022712031a01001a0f0848120b0104050607f1a802f4a8021a0508501201631a060851120265662200ea0204100118018a0302080192030032dd0208{self.squad}12104334e385a45445414de385a4424f54001a024d4520c493b5b50628013085cbd130383242188096a361c0b5ce6480a89763c091e66080c38566c09ae061480150c90158e80792010c010507090a0b12191a1e20239801c901c00101e801018802089202029603aa0208080110e43218807daa0209080f10e43218f0ab01aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022812041a0201041a0f0848120b0104050607f1a802f4a8021a0508501201631a060851120265662200ea0204100118018a03009203003a0101400150016801721e313732323633323633323338363436363831365f377466376a616f627736880180e0ae83d2d785a019a20100b001e201ea010449444332fa011e313732323633323633323338363437303439315f62713876386c38686276"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def exchange_loop(self, client, remote,port):
        global inviteD
        global back
        global Besto
        global encid
        global enc_id
        global Si_Zbi
        global Spy
        global romcode
        while True:
            r, w, e = select.select([client, remote], [], [])
            if client in r:
                dataC = client.recv(4096)
                #dataS = remote.recv(4096)
                if "39698" in str(port):
                	Bestoni = remote 
                if "39699" in str(remote):
                    self.op = remote
                    clientC = client
                if "39801" in str(remote):
                    self.xz = remote
                #dataS = remote.recv(999999)

                if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 820 and inviteD == True:
                            threading.Thread(target=destroy, args=(remote,dataC)).start()

                	
                if '0e00' in dataC.hex()[0:4]:
                           for i in range(10):
                               pattern = fr"x0{str(i)}(\d+)Z"
                               match = re.search(pattern, str(dataC))
                               if match:
                                   number = match.group(1)
                                   global romcode
                                   romcode = number

                if remote.send(dataC) <= 0:
                    break
            if remote in r:
                data = remote.recv(4096)
                if '1200' in data.hex()[0:4] and b'GroupID' not in data:                   
                    start_marker = "08"
                    end_marker = "10"
                    start_index = data.hex().find(start_marker) + len(start_marker)
                    end_index = data.hex().find(end_marker, start_index)                    
                    if start_index != -1 and end_index != -1:
                        enc_client_id = data.hex()[start_index:end_index]
                        if len(enc_client_id) % 2 != 0:
                            enc_client_id = '0' + enc_client_id             
                        if '1200' in data.hex()[0:4] and b'/id' in data:
                        	time.sleep(0.5)
                        	msg = f'[b][i][c] - Your Id : {enc_client_id}'
                        	Besto_PackEt = Besto_Msg(enc_client_id,msg)
                        	client.send(bytes.fromhex(Besto_PackEt))
                        	time.sleep(0.3)
                        	threading.Thread(target=send_msg, args=(client, data.hex(), f"[b][c] - Please Call Admin For Register", 0.2)).start()
                        	time.sleep(0.5)
                        	                      
                        self.EncryptedPlayerid = enc_client_id     
#print(self.EncryptedPlayerid)                 
                        self.squad_gen = self.Encrypt_ID(9939518820)
                        self.squad_gen5 = self.Encrypt_ID(9939518820)
                        self.squad = self.Encrypt_ID(9939518820)
                        	#self.Beston = True
                        #else:self.Beston = False
                        	                       
                if "0500" in data.hex()[:4]:
                    self.sock0500 = client     
                if "1200" in data.hex()[:4]:
                    self.sock1200 = client
                if '0e00' in data.hex()[0:4]:
                           for i in range(10):
                               pattern = fr"x0{str(i)}(\d+)Z"
                               match = re.search(pattern, str(data))
                               if match:
                                   number = match.group(1)                                   
                                   romcode = number
                yout1 = b"\x06\x00\x00\x00{\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*o\x08\x81\x80\x83\xb6\x01\x1a)[f50057]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf\xe3\x85\xa4\xd8\xa7\xd9\x84\xd8\xa8\xd9\x87\xd8\xa7\xd8\xa6\xd9\x85[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xdc)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\tAO'-'TEAM\xf0\x01\x01\xf8\x01\xdc\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02F";yout2 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xd6\xd1\xb9(\x1a![f50057]\xef\xbc\xa8\xef\xbc\xac\xe3\x85\xa4Hassone.[f50057]2\x02ME@G\xb0\x01\x13\xb8\x01\xcf\x1e\xd8\x01\xcc\xd6\xd0\xad\x03\xe0\x01\xed\xdc\x8d\xae\x03\xea\x01\x1d\xef\xbc\xb4\xef\xbc\xa8\xef\xbc\xa5\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xac\xe0\xbf\x90\xc2\xb9\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout3 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xe9\xa7\xe9\x1b\x1a [ff00ff]DS\xe3\x85\xa4WAJIHANO\xe3\x85\xa4[ff00ff]2\x02ME@Q\xb0\x01\x14\xb8\x01\xca2\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x10.DICTATORS\xe3\x85\xa4\xe2\x88\x9a\xf0\x01\x01\xf8\x01\xc4\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+';yout4 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[f50057]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[f50057]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03';yout5 = b"\x06\x00\x00\x00\x84\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*x\x08\xb6\xc0\xf1\xcc\x01\x1a'[f50057]\xd9\x85\xd9\x84\xd9\x83\xd8\xa9*\xd9\x84\xd9\x85\xd8\xb9\xd9\x88\xd9\x82\xd9\x8a\xd9\x86[f50057]2\x02ME@G\xb0\x01\x05\xb8\x01\x82\x0b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x15\xe9\xbf\x84\xef\xbc\xac\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xa4\xef\xbc\xb3\xe9\xbf\x84\xf0\x01\x01\xf8\x01>\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x05\xd8\x02\x0e";yout6 = b'\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xeb\x98\x88\x8e\x01\x1a"[f50057]OP\xe3\x85\xa4BNL\xe3\x85\xa4\xe2\x9a\xa1\xe3\x85\xa4*[f50057]2\x02ME@R\xb0\x01\x10\xb8\x01\xce\x16\xd8\x01\x84\xf0\xd2\xad\x03\xe0\x01\xa8\xdb\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x8f\xe1\xb4\xa0\xe1\xb4\x87\xca\x80\xe3\x85\xa4\xe1\xb4\x98\xe1\xb4\x8f\xe1\xb4\xa1\xe1\xb4\x87\xca\x80\xe2\x9a\xa1\xf0\x01\x01\xf8\x01A\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01\xe0\x02\xf3\x94\xf6\xb1\x03';yout7 = b"\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xb0\xa4\xdb\x80\x01\x1a'[f50057]\xd9\x85\xd9\x83\xd8\xa7\xd9\x81\xd8\xad\xd8\xa9.\xe2\x84\x93\xca\x99\xe3\x80\xb5..[f50057]2\x02ME@T\xb0\x01\x13\xb8\x01\xfc$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x1d\xef\xbc\xad\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa1\xe3\x85\xa4\xe2\x8e\xb0\xe2\x84\x93\xca\x99\xe2\x8e\xb1\xf0\x01\x01\xf8\x01\xdb\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0f\xd8\x02>";yout8 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xfd\x8a\xde\xb4\x02\x1a\x1f[f50057]ITZ\xe4\xb8\xb6MOHA\xe3\x85\xa42M[f50057]2\x02ME@C\xb0\x01\n\xb8\x01\xdf\x0f\xd8\x01\xac\xd8\xd0\xad\x03\xe0\x01\xf2\xdc\x8d\xae\x03\xea\x01\x15\xe3\x80\x9dITZ\xe3\x80\x9e\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf8\x01\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x026';yout9 = b'\x06\x00\x00\x00w\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*k\x08\xc6\x99\xddp\x1a\x1b[f50057]HEROSHIIMA1[f50057]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xb2\xef\xbc\xaf\xef\xbc\xb3\xef\xbc\xa8\xef\xbc\xa9\xef\xbc\xad\xef\xbc\xa1\xef\xa3\xbf\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout10 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[f50057]SH\xe3\x85\xa4SHIMA|M[f50057]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03';yout11 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[f50057]2JZ\xe3\x85\xa4POWER[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03';yout12 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[f50057]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[f50057]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03';yout13 = b'\x06\x00\x00\x00`\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*T\x08\xd2\xbc\xae\x07\x1a%[f50057]SYBLUS\xe3\x85\xa4\xe4\xba\x97\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4[f50057]2\x02ME@E\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout14 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[f50057]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[f50057]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03';yout15 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\x90\xf6\x87\x15\x1a"[f50057]V4\xe3\x85\xa4RIO\xe3\x85\xa46%\xe3\x85\xa4zt[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\x95&\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x0e\xe1\xb4\xa0\xe1\xb4\x80\xe1\xb4\x8d\xe1\xb4\x8f\xd1\x95\xf0\x01\x01\xf8\x01\xe2\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02^\xe0\x02\x85\xff\xf5\xb1\x03';yout16 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[f50057]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 ';yout17 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[f50057]SVG.NINJA\xe2\xbc\xbd[f50057]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?';yout18 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[f50057]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03";yout19 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[f50057]FARAMAWY_1M.[f50057]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout20 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[f50057]SH\xe3\x85\xa4SHIMA|M[f50057]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03';yout21 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[f50057]2JZ\xe3\x85\xa4POWER[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03';yout22 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[f50057]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[f50057]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03';yout23 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[f50057]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[f50057]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03';yout24 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[f50057]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 ';yout25 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[f50057]SVG.NINJA\xe2\xbc\xbd[f50057]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?';yout26 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[f50057]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03";yout27 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[f50057]FARAMAWY_1M.[f50057]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout28 = b"\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xaa\xdd\xf1'\x1a\x1d[f50057]BM\xe3\x85\xa4ABDOU_YT[f50057]2\x02ME@G\xb0\x01\x13\xb8\x01\xd4$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1d\xe2\x80\xa2\xc9\xae\xe1\xb4\x87\xca\x9f\xca\x9f\xe1\xb4\x80\xca\x8d\xe1\xb4\x80\xd2\x93\xc9\xaa\xe1\xb4\x80\xc2\xb0\xf0\x01\x01\xf8\x01\x8e\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x07\xd8\x02\x16";yout29 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9a\xd6\xdcL\x1a-[f50057]\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa4\xef\xbc\xa9[f50057]2\x02ME@H\xb0\x01\x01\xb8\x01\xe8\x07\xea\x01\x15\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xc9\xb4\xef\xbd\x93\xe1\xb4\x9b\xe1\xb4\x87\xca\x80\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout30 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb6\x92\xa9\xc8\x01\x1a [f50057]\xef\xbc\xaa\xef\xbc\xad\xef\xbc\xb2\xe3\x85\xa4200K[f50057]2\x02ME@R\xb0\x01\x13\xb8\x01\xc3(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\n3KASH-TEAM\xf8\x012\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x06\xd8\x02\x13\xe0\x02\x89\xa0\xf8\xb1\x03';yout31 = b"\x06\x00\x00\x00\x92\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x85\x01\x08\xa2\xd3\xf4\x81\x07\x1a'[f50057]\xd8\xb3\xd9\x80\xd9\x86\xd9\x80\xd8\xaf\xd8\xb1\xd9\x8a\xd9\x84\xd8\xa71M\xe3\x85\xa4[f50057]2\x02ME@K\xb0\x01\x13\xb8\x01\xc1 \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xad\xef\xbc\xa6\xef\xbc\x95\xef\xbc\xb2\xef\xbc\xa8\xe3\x85\xa4\xe1\xb4\xa0\xc9\xaa\xe1\xb4\x98\xf0\x01\x01\xf8\x01\x8c\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x024\xe0\x02\x87\xff\xf5\xb1\x03";yout32 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xe0\xe1\xdeu\x1a\x1a[f50057]P1\xe3\x85\xa4Fahad[f50057]2\x02ME@N\xb0\x01\x13\xb8\x01\xd0&\xd8\x01\xea\xd6\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xe3\x85\xa4\xef\xbc\xb0\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xa5\xef\xbc\xae\xef\xbc\xa9\xef\xbc\xb8\xc2\xb9\xf0\x01\x01\xf8\x01\x9e\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02*';yout33 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[f50057]@EL9YSAR[f50057]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03';yout34 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xa9\x81\xe6^\x1a\x1e[f50057]STRONG\xe3\x85\xa4CRONA[f50057]2\x02ME@J\xb0\x01\x13\xb8\x01\xd8$\xd8\x01\xd8\xd6\xd0\xad\x03\xe0\x01\x92\xdb\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xbc\x01';yout35 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xeb\x8d\x97\xec\x01\x1a&[f50057]\xd8\xb9\xd9\x80\xd9\x85\xd9\x80\xd8\xaf\xd9\x86\xd9\x8a\xd9\x80\xd8\xaa\xd9\x80\xd9\x88[f50057]2\x02ME@F\xb0\x01\x13\xb8\x01\xd3\x1a\xd8\x01\xaf\xd7\xd0\xad\x03\xe0\x01\xf4\xdc\x8d\xae\x03\xea\x01\rOSIRIS\xe3\x85\xa4MASR\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02\\\xe0\x02\xf4\x94\xf6\xb1\x03';yout36 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xb4\xff\xa3\xef\x01\x1a\x1c[f50057]ZAIN_YT_500K[f50057]2\x02ME@K\xb0\x01\x13\xb8\x01\xa3#\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\xbb\xdb\x8d\xae\x03\xea\x01\x1b\xe1\xb6\xbb\xe1\xb5\x83\xe1\xb6\xa4\xe1\xb6\xb0\xe3\x85\xa4\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\\\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02(';yout37 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\x86\xa7\x9e\xa7\x0b\x1a([f50057]\xe2\x80\x94\xcd\x9e\xcd\x9f\xcd\x9e\xe2\x98\x85\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8[f50057]2\x02ME@d\xb0\x01\x13\xb8\x01\xe3\x1c\xe0\x01\xf2\x83\x90\xae\x03\xea\x01!\xe3\x85\xa4\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf8\x01u\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Y\xe0\x02\xc1\xb7\xf8\xb1\x03';yout38 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xc3\xcf\xe5H\x1a([f50057]\xe3\x85\xa4BEE\xe2\x9c\xbfSTO\xe3\x85\xa4\xe1\xb5\x80\xe1\xb4\xb5\xe1\xb4\xb7[f50057]2\x02ME@Q\xb0\x01\x14\xb8\x01\xffP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x15TIK\xe2\x9c\xbfTOK\xe1\xb5\x80\xe1\xb4\xb1\xe1\xb4\xac\xe1\xb4\xb9\xf0\x01\x01\xf8\x01\xc8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02q';yout39 = b'\x06\x00\x00\x00\x94\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x87\x01\x08\x97\xd5\x9a.\x1a%[f50057]\xd8\xb9\xd9\x86\xd9\x83\xd9\x88\xd8\xb4\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe3\x85\xa4[f50057]2\x02ME@P\xb0\x01\x13\xb8\x01\xe8(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe1\xb4\x9c\xea\x9c\xb1\xca\x9c\xe3\x85\xa4\xe1\xb4\x9b\xe1\xb4\x87\xe1\xb4\x80\xe1\xb4\x8d\xf0\x01\x01\xf8\x01\xb6\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02"\xe0\x02\xf2\x94\xf6\xb1\x03';yout40 = b'\x06\x00\x00\x00\x8a\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*~\x08\xf7\xdf\xda\\\x1a/[f50057]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xad\xef\xbc\xb3\xef\xbc\xa9_\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93[f50057]2\x02ME@P\xb0\x01\x13\xb8\x01\xb9*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\x8e\x0e\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02S\xe0\x02\xc3\xb7\xf8\xb1\x03';yout41 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xb5\xdd\xec\x8e\x01\x1a%[f50057]\xd8\xa7\xd9\x88\xd9\x81\xe3\x80\x80\xd9\x85\xd9\x86\xd9\x83\xe3\x85\xa4\xe2\x9c\x93[f50057]2\x02ME@K\xb0\x01\x13\xb8\x01\xdd#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x18\xef\xbc\xaf\xef\xbc\xa6\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf0\x01\x01\xf8\x01\xe8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Q';yout42 = b'\x06\x00\x00\x00\x8b\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x7f\x08\x81\xf4\xba\xf8\x01\x1a%[f50057]\xef\xbc\xa7\xef\xbc\xa2\xe3\x85\xa4\xef\xbc\xae\xef\xbc\xaf\xef\xbc\x91\xe3\x81\x95[f50057]2\x02ME@N\xb0\x01\x0c\xb8\x01\xbd\x11\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xa7\xef\xbc\xb2\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xb4__\xef\xbc\xa2\xef\xbc\xaf\xef\xbc\xb9\xf8\x018\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02-\xe0\x02\x85\xff\xf5\xb1\x03';yout43 = b'\x06\x00\x00\x00o\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*c\x08\xfb\x9d\xb9\xae\x06\x1a\x1c[f50057]BT\xe3\x85\xa4BadroTV[f50057]2\x02ME@@\xb0\x01\x13\xb8\x01\xe7\x1c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x91\xdb\x8d\xae\x03\xea\x01\nBadro_TV_F\xf0\x01\x01\xf8\x01\x91\x1a\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02!';yout44 = b"\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xc4\xe5\xe1>\x1a'[f50057]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf~\xd8\xa7\xd9\x84\xd8\xba\xd9\x86\xd8\xa7\xd8\xa6\xd9\x85[f50057]2\x02ME@J\xb0\x01\x14\xb8\x01\xceP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x03Z7F\xf0\x01\x01\xf8\x01\xd0\x19\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\x9c\x01";yout45 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xfd\xa4\xa6i\x1a$[f50057]\xd8\xb2\xd9\x8a\xd9\x80\xd8\xb1\xc9\xb4\xcc\xb67\xcc\xb6\xca\x80\xe3\x85\xa4[f50057]2\x02ME@M\xb0\x01\x13\xb8\x01\xe1(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x19\xc2\xb7\xe3\x85\xa4\xe3\x85\xa4N\xe3\x85\xa47\xe3\x85\xa4R\xe3\x85\xa4\xe3\x85\xa4\xc2\xb7\xf0\x01\x01\xf8\x01\x8f\t\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02k';yout46 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xcc\xb9\xcc\xd4\x06\x1a"[f50057]\xd8\xa8\xd9\x88\xd8\xad\xd8\xa7\xd9\x83\xd9\x80\xd9\x80\xd9\x80\xd9\x85[f50057]2\x02ME@9\xb0\x01\x07\xb8\x01\xca\x0c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x11*\xef\xbc\x97\xef\xbc\xaf\xef\xbc\xab\xef\xbc\xa1\xef\xbc\xad*\xf0\x01\x01\xf8\x01\xad\x05\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01';yout47 = b'\x06\x00\x00\x00e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*Y\x08\xe8\xbd\xc9b\x1a [f50057]\xe3\x80\x8cvip\xe3\x80\x8dDR999FF[f50057]2\x02ME@Q\xb0\x01\x10\xb8\x01\x94\x16\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xf0\x01\x01\xf8\x01\xa0\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+';yout48 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\x86\xb7\x84\xf1\x01\x1a&[f50057]\xd8\xa2\xd9\x86\xd9\x8a\xd9\x80\xd9\x80\xd9\x84\xd8\xa7\xce\x92\xe2\x92\x91\xe3\x85\xa4[f50057]2\x02ME@Q\xb0\x01\x13\xb8\x01\x82)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x13\xce\x92\xe2\x92\x91\xe3\x85\xa4MAFIA\xe3\x85\xa4\xef\xa3\xbf\xf0\x01\x01\xf8\x01\x95\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W';yout49 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [f50057]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[f50057]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{';yout50 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [f50057]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[f50057]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
                yout_list = [yout1,yout2,yout3,yout4,yout5,yout6,yout7,yout8,yout9,yout10,yout11,yout12,yout13,yout14,yout15,yout16,yout17,yout18,yout19,yout20,yout21,yout22,yout23,yout24,yout25,yout26,yout27,yout28,yout29,yout30,yout31,yout32,yout33,yout34,yout35,yout36,yout37,yout38,yout39,yout40,yout41,yout42,yout43,yout44,yout45,yout46,yout47,yout48,yout49,yout50]


                if self.Beston == True:
                    if '1200' in data.hex()[0:4] and b'/help' in data and self.Beston == True:
                    	try:
                    		
                    		threading.Thread(target=self.help).start()
                    		time.sleep(0.3)
                    	#	threading.Thread(target=self.help01).start()
                    	#	time.sleep(0.3)            		
                    		threading.Thread(target=self.help1).start()
                    		time.sleep(0.3)                 		
                    		threading.Thread(target=self.help2).start()
                    		time.sleep(0.3)                    		
                    		threading.Thread(target=self.help3).start()
                    		time.sleep(0.3)
                    		threading.Thread(target=self.help4).start()
                    		
                    		time.sleep(0.3)                    				
                    	except Exception as e:
                    		pass

                                                                
                    if '1200' in data.hex()[0:4] and b'/5s' in data and self.Beston == True:
                    	time.sleep(0.5)
                    	msg = "[b][i][c][7cfc00] - 5 In Sqiud On !\n - Enjoy ! \n - By : C4 Team"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt))
                    	threading.Thread(target=self.gen_squad5).start()
                    	
                    if '1200' in data.hex()[0:4] and b'/6s' in data and self.Beston == True:
                    	time.sleep(0.5)
                    	msg = "[b][i][c][7cfc00] - 6 In Sqiud On !\n - Enjoy ! \n - By : C4 Team"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt))
                    	threading.Thread(target=self.gen_squad6).start()
                    	                  	
                    if '1200' in data.hex()[0:4] and b'/yout' in data and self.Beston == True:
                    	time.sleep(0.5)
                    	msg = "[b][i][c][7cfc00] - Done Add Yutubers In Your List Freinds !\n - Enjoy ! \n - By : C4 Team"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt))
                    	for h in yout_list:
                    		self.sock0500.send(h)  
                    		          
                    if '1200' in data.hex()[0:4] and b'/emotes' in data and self.Beston == True:
                         time.sleep(0.5)
                         threading.Thread(target=send_msg, args=(client, data.hex(), "[B][C][7CFC00] - Menu Emotes Normal New :", 0.2)).start()
                         time.sleep(0.5)
                         msg = """[b][i][c]
/em1
/em2
/em3
/em4
/em5
/em6"""
                         Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                         self.sock1200.send(bytes.fromhex(Besto_PackEt))
                         time.sleep(0.3)
                         msg = """[b][i][c]
/em7
/em8
/em9
/em10
/em11
/em12"""
                         Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                         self.sock1200.send(bytes.fromhex(Besto_PackEt))
                         threading.Thread(target=send_msg, args=(client, data.hex(), "[B][C][7CFC00] - Menu Emotes Evo Max :", 0.2)).start()
                         time.sleep(0.5)
                         msg = """[b][i][c]
/emx1
/emx2
/emx3
/emx4
/emx5
/emx6"""
                         Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                         self.sock1200.send(bytes.fromhex(Besto_PackEt))
                         time.sleep(0.5)
                                                 
                    if '1200' in data.hex()[0:4] and b'/em1' in data and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}1088b3bbb1032a0608{self.EncryptedPlayerid}"                        	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                         	time.sleep(0.5)
                    if '1200' in data.hex()[0:4] and b'/em2' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008c1ae939607100520162a1408{self.EncryptedPlayerid}10bdcabbb1032a0608{self.EncryptedPlayerid}"	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/em3' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109bfbb8b1032a0608{self.EncryptedPlayerid}"                        	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))  
                    if '1200' in data.hex()[0:4] and b'/em4' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10d2c2bbb1032a0608{self.EncryptedPlayerid}"                       
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/em5' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10dcc2bbb1032a0608{self.EncryptedPlayerid}"                      	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/em6' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008c1ae939607100520162a1408{self.EncryptedPlayerid}10818cbbb1032a0608{self.EncryptedPlayerid}"                         
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))  
                    if '1200' in data.hex()[0:4] and b'/em7' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109284bbb1032a0608{self.EncryptedPlayerid}"                        	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/em8' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10d6c2bbb1032a0608{self.EncryptedPlayerid}"                         	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/em9' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109684bbb1032a0608{self.EncryptedPlayerid}"                         	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/em10' in data and 700 > len(data.hex()) and self.Beston == True:
                    	ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109e84bbb1032a0608{self.EncryptedPlayerid}"
                    	self.sock0500.send(bytes.fromhex(ent_packet))  
                    if '1200' in data.hex()[0:4] and b'/em11' in data and 700 > len(data.hex()) and self.Beston == True:
                    	ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10b9cabbb1032a0608{self.EncryptedPlayerid}"
                    	self.sock0500.send(bytes.fromhex(ent_packet))        
                    if '1200' in data.hex()[0:4] and b'/em12' in data and 700 > len(data.hex()) and self.Beston == True:
                    	ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109cfbb8b1032a0608{self.EncryptedPlayerid}"
                    	self.sock0500.send(bytes.fromhex(ent_packet))              	                                   	                          	                          	
                    if '1200' in data.hex()[0:4] and b'/emx1' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10ff8bbbb1032a0608{self.EncryptedPlayerid}"                         	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/emx2' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f" 050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}108bfbb8b1032a0608{self.EncryptedPlayerid}"                         	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/emx3' in data and 700 > len(data.hex()) and self.Beston == True:
                    	ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10edbabbb1032a0608{self.EncryptedPlayerid}"
                    	self.sock0500.send(bytes.fromhex(ent_packet))  
                    if '1200' in data.hex()[0:4] and b'/emx4' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}1095fbb8b1032a0608{self.EncryptedPlayerid}"                         	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/emx5' in data and 700 > len(data.hex()) and self.Beston == True:
                         	Besto_Packets = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}1084fbb8b1032a0608{self.EncryptedPlayerid}"                         	
                         	self.sock0500.send(bytes.fromhex(Besto_Packets))
                    if '1200' in data.hex()[0:4] and b'/emx6' in data and 700 > len(data.hex()) and self.Beston == True:
                    	ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10fffab8b1032a0608{self.EncryptedPlayerid}"
                    	self.sock0500.send(bytes.fromhex(ent_packet))  
                         	                                                              
                    if '1200' in data.hex()[0:4] and b'/spm' in data and self.Beston == True:
                    	
                    	Besta = dataC
                    	for i in range(2):
                            for _ in range(10):
                                remote.send(Besta)
                                time.sleep(0.04)
                                time.sleep(0.2)       
                                                                    
                    	

                    if '1200' in data.hex()[0:4] and b'/inv' in data and 700 > len(data.hex()) and self.Beston == True:
                    	threading.Thread(target=send_msg, args=(client, data.hex(), "[B][C][7CFC00] - Spam Invite On ", 0.2)).start()
                    	inviteD =True
                    if '1200' in data.hex()[0:4] and b'/-inv' in data and 700 > len(data.hex()) and self.Beston == True:
                    	threading.Thread(target=send_msg, args=(client, data.hex(), "[B][C][FF0000] - Spam Invite Off ", 0.2)).start()
                    	inviteD = False                    	                      	
                         	                	
                    if '1200' in data.hex()[0:4] and b'/pc' in data and self.Beston == True:           
                        i = re.split('/pc', str(data))[1]
                        print(i)                        
                        if '***' in i:
                        	i = i.replace('***', '106')            	
                        iddd = str(i).split('(\\x')[0]   	            
                        id_admin = self.EncryptedPlayerid
                        name = Get_Name(iddd)
                        hex_name = name.encode('utf-8').hex()
                        hex_name = adjust_text_length(hex_name) 
                        my_id = self.EncryptedPlayerid
                        self.sock0500.send(bytes.fromhex(f'05000003ff08{my_id}100520062af20708{id_admin}12024d451801200332cc0408{id_admin}12134334e385a45445414de385a4424f54000000201a024d4520a6e38baa0628443087cbd13038324218e0f38766e796a3618994e660f39ae061e5b7d064bfb8ce64480150ce01588e0c60f5d7d0ad0368c2dc8dae037a05d7d0cab00382012b08b3daf1eb041211d8b2d98ad988d98ad986d983d983e29cbf180620b687d4f0042a0808c49d85f30410038801ed89c5b00392010b0107090a0b1216191a20239801cd01a00111a80185fff5b103c00101c80101d001bace89af03e80101880203920207c20500a606e532aa020a080110c03e18f0602002aa0205080210b232aa0205080310e432aa020a080f10918a0118a09c01aa0205081710e750aa0205081810b768aa0205081a10da74aa0206081b10918a01aa0206081c10958c01aa02050820108b79aa0205082110eb7aaa0205082210a275aa0206082310dc8701aa0205082b10f476aa0205083110f476aa0206083910918a01aa0206083d10918a01aa0206084110918a01aa0205084910e432aa0205084d10e432aa0206083410918a01aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea02520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3237373631373532363237343633352f706963747572653f77696474683d313630266865696768743d31363010011801f202090887cab5ee0110870a8a030808021003180528019203009803f3e78ea30ba20315e298afd986d8a7d8acd988d986d98ae298afe29c9432d00208{my_id}120b{hex_name}1a024d452096ed8baa0628043089cbd13038324214fa96e660b599a361c19de061aab9ce64abb9ce64480150c90158e80792010601090a1219209801c901c00101c80101e80101880204920206ee07ce010000aa0208080110ff34188064aa020b080f10fd3218b086012001aa0205080210e432aa0205081810fd32aa0205081a10fd32aa0205081c10fd32aa0205082010fd32aa0205082210fd32aa0205082110fd32aa0205081710e432aa0205082310fd32aa0205082b10fd32aa0205083110fd32aa0205083910fd32aa0205083d10fd32aa0205084110fd32aa0205084910d836aa0205084d10e432aa0205081b10fd32aa0205083410fd32aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea0204100118018a03009203003a0101400150016801721e313639383838363035353130343733333939355f6a67386c37333431646688018090aefec3978fef17a20100b001e001ea010449444331'))      
                        msg = "[b][i][c][7cfc00] - Done Get Logo Pc !\n - Enjoy With Logo Pc\n - By : C4 Team"
                        Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg) 
                        self.sock1200.send(bytes.fromhex(Besto_PackEt)) 
                             	    	                         	                       		               
                    if '1200' in data.hex()[0:4] and b'/get' in data and self.Beston == True:           
                        i = re.split('/get', str(data))[1]
                        print(i)                        
                        if '***' in i:
                        	i = i.replace('***', '106')            	
                        iddd = str(i).split('(\\x')[0]   	            
                        id_admin = self.EncryptedPlayerid
                        name = Get_Name(iddd)
                        hex_name = name.encode('utf-8').hex()
                        hex_name = adjust_text_length(hex_name) 
                        my_id = self.EncryptedPlayerid
                        self.sock0500.send(bytes.fromhex(f'05000003ff08{my_id}100520062af20708{id_admin}12024d451801200332cc0408{id_admin}12135b6564303930395d43342042e2808f4f5400201a024d4520a6e38baa0628443087cbd13038324218e0f38766e796a3618994e660f39ae061e5b7d064bfb8ce64480150ce01588e0c60f5d7d0ad0368c2dc8dae037a05d7d0cab00382012b08b3daf1eb041211d8b2d98ad988d98ad986d983d983e29cbf180620b687d4f0042a0808c49d85f30410038801ed89c5b00392010b0107090a0b1216191a20239801cd01a00111a80185fff5b103c00101c80101d001bace89af03e80101880203920207c20500a606e532aa020a080110c03e18f0602002aa0205080210b232aa0205080310e432aa020a080f10918a0118a09c01aa0205081710e750aa0205081810b768aa0205081a10da74aa0206081b10918a01aa0206081c10958c01aa02050820108b79aa0205082110eb7aaa0205082210a275aa0206082310dc8701aa0205082b10f476aa0205083110f476aa0206083910918a01aa0206083d10918a01aa0206084110918a01aa0205084910e432aa0205084d10e432aa0206083410918a01aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea02520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3237373631373532363237343633352f706963747572653f77696474683d313630266865696768743d31363010011801f202090887cab5ee0110870a8a030808021003180528019203009803f3e78ea30ba20315e298afd986d8a7d8acd988d986d98ae298afe29c9432d00208{my_id}120b{hex_name}1a024d452096ed8baa0628043089cbd13038324214fa96e660b599a361c19de061aab9ce64abb9ce64480150c90158e80792010601090a1219209801c901c00101c80101e80101880204920206ee07ce010000aa0208080110ff34188064aa020b080f10fd3218b086012001aa0205080210e432aa0205081810fd32aa0205081a10fd32aa0205081c10fd32aa0205082010fd32aa0205082210fd32aa0205082110fd32aa0205081710e432aa0205082310fd32aa0205082b10fd32aa0205083110fd32aa0205083910fd32aa0205083d10fd32aa0205084110fd32aa0205084910d836aa0205084d10e432aa0205081b10fd32aa0205083410fd32aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea0204100118018a03009203003a0101400150016801721e313639383838363035353130343733333939355f6a67386c37333431646688018090aefec3978fef17a20100b001e001ea010449444331'))      
                        msg = "[b][i][c][7cfc00] - Done Get Sqiud !\n - You Can Now Satrt Game !\n - By : C4 Team"
                        Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg) 
                        self.sock1200.send(bytes.fromhex(Besto_PackEt))                              	
                        
                    if '1200' in data.hex()[0:4] and b'/bot' in data and self.Beston == True:
                    	                        time.sleep(0.5)
                    	                        threading.Thread(target=self.garinafreefire).start()
                    	                        
                    if '1200' in data.hex()[0:4] and b'/add' in data and self.Beston == True:           
                        i = re.split('/add', str(data))[1]
                        print(i)                        
                        if '***' in i:
                        	i = i.replace('***', '106')            	
                        iddd = str(i).split('(\\x')[0]   	            
                        id = self.Encrypt_ID(iddd)
                        self.fake_friend(self.sock0500, id)
                        h1 = Get_Name(iddd)
                        msg = f"[b][i][c][eff213] - Done Add Player !\n - Id : {iddd}\n - Name : {h1}\n - By : C4 Team"
                        Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg) 
                        self.sock1200.send(bytes.fromhex(Besto_PackEt))                              	
                        	                                                
                    if '1200' in data.hex()[0:4] and b'/code' in data and 700 > len(data.hex()) and self.Beston == True:
                    	msg = f"[b][i][c][7cfc00] - Code Room : {romcode}\n By : C4 Team"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg) 
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt))      
                    if '1200' in data.hex()[0:4] and b'/kick' in data and 700 > len(data.hex()) and self.Beston == True:
                    	self.sock0500.send(bytes.fromhex("0515000000301a55e2c4e0bb2b3e02f11b4f9f9e0b55ec9b15af7b8eec4273c32c67be0cb9d2fe3d0b12b2064841ba21001df8665703")) 
                    	msg = "[b][i][c][7cfc00] - Spy | AntiKick On"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg)
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt)) 
                    	                    
                    		                                       		                 
                    if '1200' in data.hex()[0:4] and b'/besto' in data and 700 > len(data.hex()) and self.Beston == True:
                    	self.sock0500.send(bytes.fromhex(f"050000098a08{self.EncryptedPlayerid}100520062afd1208{self.EncryptedPlayerid}12024d451801200332e50508{self.EncryptedPlayerid}121feaa781e0a694e0a7a35ae18ea5e18f81e18eb6e18ebee0a694e0a7a3eaa7821a024d45208cf1dbb70628353087cbd13038324218e1cea56180a89763949be061b793e660e5bfce64b5c38566480150d60158f11368b7db8dae037a05ab93c5b00382012808fbdaf1eb04120ed8a7d984d985d8aad988d8add8b4180420e888d4f0042a0808d69d85f304100392010a0107090a0b12191a1e209801d901a00144a801e1d6f8b103ba010b08e4b793f803100118c701c00101d001ada48aaf03e80101880203920208c2058e0eae2dd628aa0205080110d442aa0208080210ea3018c413aa0208080f10903d188827aa0205081710ae33aa0205082b10e432aa0205083910a070aa0205083d10c16faa0205081810903daa0205081a10903daa0205081c10903daa0205082010903daa0205082210903daa0205082110903daa0205082310903daa0205083110e432aa0205084110903daa0205084910e432aa0205084d10e432aa0205081b10903daa0205083410903daa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202090885cab5ee01108d018a0300920300980383c6cda60ba2031befbca3efbc94e385a4e385a4efbcb4efbca5efbca1efbcade1b4bfa80368b00301c2030a081b100f180320022801ca030a0804108695e7b7061807ca030a080210ad8de6b7061801ca030a080b108695e7b7061807e203014fea030032bc040898dad8e00c120a374827275a4f524f27271a024d45209ef1dbb706283730a7cbd13038324218d697a361d598e660e2fdd06483a0e0618dcfd064d6c38566480150d301589f1060adb1d2ad0368e1b290ae0382011808efdaf1eb04180720f087d4f0042a0808ca9d85f304100392010a0107090a0b120e191e209801db01a00156a801b2e9f7b103c00101d001c69c8aaf03e80101880208920208a92daa26fe23ca13aa020708011084392003aa0208080210fa3318dc0baa020b080f10a03818d08c012003aa0205081710b633aa0205082110de2faa0205082210f02eaa0205082b10bb31aa0205083110f02eaa0205083910ec59aa0205083d10ea62aa0205084910ce31aa0205081810a038aa0205081a10a038aa0205081c10a038aa0205082010a038aa0205082310a038aa0205084110a038aa0205084d10e432aa0205081b10a038aa0205083410a038aa0205082810e432aa0205082910e432c202890112031a01011a5e08481213010405060702f1a802f4a802f2a802f3a802031a0b080110031893022086c2011a0d08f1a802100318d10320faa3051a0d08f2a802100318d50320cd9f061a0d08f3a802100318bd0420dda3051a0b0802100418ed0220cbb6041a0508501201631a060851120265662213121165ed0e890ed904ad029103f503f90abd05d802a6a38daf03ea020410011801f202090885cab5ee0110af038a03009203009803b7a4b3ac0ba20313e1b6a0e1b587cba1e385a4636f727361697273b00301c2030a081b100f180320062801ea030032830408{self.EncryptedPlayerid}12145876e385a441c9b4e29d80ca8fe1b48fe385a4211a024d4520a5f1dbb706283e308ccbd13038324214fb9ae061d596a361c4d48766fcd1e8608abace6450dd0158c81f60bdd8d0ad0368e6dc8dae037a059c9ac5b0038201220881daf1eb041208d983d988d8abd8b11806208287d4f0042a0808c89d85f304100388019dffc4b00392010b0107090a0b120f191a1e209801dd01a0018901ba010b089f969b9804100118a804c00101e801018802039202088619c2058a07f62eaa02070801109c312001aa02050802109633aa0207080f10ee3c2003aa0205081710de51aa0205081810bf3daa0205081a10e33eaa0205081b10ee3caa0205082010d73eaa0205082110a938aa0205082b10f02eaa0205083910ba4daa0205081c10ee3caa0205082210e33eaa0205082310ee3caa0205083110f02eaa0205083d10ee3caa0205084110ee3caa0205084910e432aa0205084d10e432aa0205083410ee3caa0205082810e432aa0205082910e432b00201c2022712031a01011a0f0848120b0104050607f1a802f4a8021a0508501201631a060851120265662200d802a9a38daf03ea020410011801f202090886cab5ee0110820b8a03009203009803b9b091b40ba20311e385a450617ae385a47856696461e385a4b00301c2030a081b100f180420012801ca030a080910d495eab7061801e203024f52ea030032d10308b4aa84be241209d988d98ad8aa2424401a024d4520c3f1dbb7062824309bcbd13038324218c09ae061b8aa8866c0b5ce6480a89763c091e6608096a361480150d601588a13608bb6d3ad0368cbba90ae037a058d9ac5b00382011808d1daf1eb04180420d287d4f0042a0808c49d85f304100392010801090a0b12191e209801db01a00152a801c1b7f8b103c00101e80101880208920209ee20ce0180ac01e532aa0207080110a6362005aa0207080f10fb312006aa0205082b109933aa0205080210e432aa0205081810fb31aa0205081a10fb31aa0205081c10fb31aa0205082010fb31aa0205082210fb31aa0205082110fb31aa0205081710e432aa0205082310fb31aa02050831109933aa0205083910fb31aa0205083d10fb31aa0205084110fb31aa0205084910e432aa0205084d10e432aa0205081b10fb31aa0205083410fb31aa0205082810e432aa0205082910e432c2022712031a01001a0508501201631a060851120265661a0f0848120b0104050607f1a802f4a8022200d802e6e5abaf03ea020410011801f2020a0884cab5ee01100618018a03009203009803a29e8eb50ba20306416d69783030b00301c2030a08291001180320022801c2030a081b100f1803200c2801ea03003a01014001500260016801721e313732373436313531363630383233303539345f6a63676e35666970656878d301820103303b30880180909bfe85ef82c419a20100b001d601ea010449444331fa011e313732373436313531363630383233333638345f616c6f6a636b33657368"))   
                    	   
                    if '1200' in data.hex()[0:4] and b'/ds' in data and 700 > len(data.hex()) and self.Beston == True:
                    	i = re.split('/ds', str(data))[1]                      
                    	if '***' in i:
                        	i = i.replace('***', '106')
                    	iddd = str(i).split('(\\x')[0]
                    	hoha = self.Encrypt_ID(iddd)
                    	Mibon = dance(hoha)
                    	self.sock0500.send(bytes.fromhex(Mibon))
                    	msg = f"[b][i][c][7cfc00] - Done Dance Id {iddd}"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg) 
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt))                                             	
                    if '1200' in data.hex()[0:4] and b'/dn' in data and 700 > len(data.hex()) and self.Beston == True:
                    	hoha = self.EncryptedPlayerid
                    	Mibon = dance(self.EncryptedPlayerid)
                    	self.sock0500.send(bytes.fromhex(Mibon))  
                    	msg = "[b][i][c][7cfc00] - Done Get Dance"
                    	Besto_PackEt = Besto_Msg(self.EncryptedPlayerid,msg) 
                    	self.sock1200.send(bytes.fromhex(Besto_PackEt))  	                 		                                        	                                         	
                if client.send(data) <= 0:
                    break
                              
    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        version = connection.recv(1)[0]
        username_len = connection.recv(1)[0]
        username = connection.recv(username_len).decode('utf-8')
        password_len = connection.recv(1)[0]
        password = connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        else:

            response = bytes([version, 0])
            connection.sendall(response)
            return True

    def get_available_methods(self, nmethods, connection):
        methods = []
        for _ in range(nmethods):
            methods.append(connection.recv(1)[0])
        return methods

    def run(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((ip, port))
        s.listen()
        print(f" - Socks5 proxy Server is running on {ip}:{port}\n - Dev : Besto !")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
            
def start_bot():
    proxy = Proxy()
    proxy.run("127.0.0.1", 3000)
start_bot()
