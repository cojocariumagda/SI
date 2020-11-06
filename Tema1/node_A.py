try:
    from . import criptosisteme
except:
    import criptosisteme
import socket
import json
import time
import os

HOST = '127.0.0.1'
PORT = 45431
PORT_KM = 45433
PORT_B = 45432


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((HOST, PORT_KM))
    print('Connected to node KM')
    mod_operare = str(input('Mod de operare dorit: (CFB sau CBC) '))
    while mod_operare not in ['CFB', 'CBC']:
        print('Nu ati introdus modul de operare valid')
        mod_operare = str(input('Mod de operare dorit: (CFB sau CBC) '))
    if mod_operare == 'CFB':
        functia_operare_encrypt = criptosisteme.encryption_CFB
        functia_operare_decrypt = criptosisteme.decryption_CFB
    else:
        functia_operare_encrypt = criptosisteme.encryption_CBC
        functia_operare_decrypt = criptosisteme.decryption_CBC

    s.sendall(criptosisteme.convert_string_to_bytes(mod_operare))
    confirmation = s.recv(1024)
    print('Am primit confirmarea de la KM: {}'.format(confirmation))

    encrypted_key = s.recv(1024)
    encrypted_iv = s.recv(1024)
    key, _ = criptosisteme.decryption_ECB(encrypted_key, criptosisteme.k3)
    iv, _ = criptosisteme.decryption_ECB(encrypted_iv, criptosisteme.k3)
    print("Am primit cheia: {}".format(key))
    print("Am primit IV: {}".format(iv))

    raspuns_criptat, _, _ = criptosisteme.encryption_ECB('Am primit cheia si iv - nod A', criptosisteme.k3)
    s.sendall(raspuns_criptat)

    confirmation = s.recv(1024)
    confirmation_decrypt, _ = criptosisteme.decryption_ECB(confirmation, criptosisteme.k3)

    print("Am primit confirmarea de la server: {}".format(confirmation_decrypt))

    if confirmation_decrypt == b"GO,GO,GO":
        print("Ready to talk")

        print("Waiting to connect to B")
        time.sleep(1)

        blocuri_criptate = 0
        blocuri_trimise = 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sB:
            sB.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sB.connect((HOST, PORT_B))
            print("Connected to B. Lucrez cu: {}, {}".format(functia_operare_encrypt, functia_operare_decrypt))
            file_name = str(input('Introdu numele fisierlui de trimis: '))
            while not os.path.exists(file_name):
                print("Fisierul introdus nu exista!")
                file_name = str(input('Introdu numele fisierlui de trimis: '))

            handler = open(file_name, "rb")
            content = handler.read(512)
            while content:
                content_criptat, _, nr_of_blocks = functia_operare_encrypt(content, key, iv)
                blocuri_criptate += nr_of_blocks
                blocuri_trimise += 1
                sB.sendall(content_criptat)
                time.sleep(0.5)
                content = handler.read(512)
            sB.sendall(b"FINAL")
            handler.close()


        result = {"criptate": blocuri_criptate, "trimise": blocuri_trimise}
        result = json.dumps(result)

        result_criptat, _, _ = criptosisteme.encryption_ECB(result, criptosisteme.k3)
        s.sendall(result_criptat)


