try:
    from . import criptosisteme
except:
    import criptosisteme
import socket
import json

HOST = '127.0.0.1'
PORT_A = 45431
PORT_KM = 45433
PORT = 45432


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((HOST, PORT_KM))
    print('Connected to node KM')

    mod_operare = s.recv(1024)
    print("Am primit modul de operare: {}".format(mod_operare))

    if mod_operare == 'CFB':
        functia_operare_encrypt = criptosisteme.encryption_CFB
        functia_operare_decrypt = criptosisteme.decryption_CFB
    else:
        functia_operare_encrypt = criptosisteme.encryption_CBC
        functia_operare_decrypt = criptosisteme.decryption_CBC

    encrypted_key = s.recv(1024)
    encrypted_iv = s.recv(1024)

    key, _ = criptosisteme.decryption_ECB(encrypted_key, criptosisteme.k3)
    iv, _ = criptosisteme.decryption_ECB(encrypted_iv, criptosisteme.k3)

    print("Am primit cheia: {}".format(key))
    print("Am primit IV: {}".format(iv))

    raspuns_criptat, _, _ = criptosisteme.encryption_ECB('Am primit cheia si iv - nod B', criptosisteme.k3)
    s.sendall(raspuns_criptat)

    confirmation = s.recv(1024)
    confirmation_decrypt, _ = criptosisteme.decryption_ECB(confirmation, criptosisteme.k3)

    print("Am primit confirmarea de la server: {}".format(confirmation_decrypt))

    if confirmation_decrypt == b"GO,GO,GO":
        print("Ready to talk")

        blocuri_decriptate = 0
        blocuri_primite = 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sS:
            sS.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sS.bind((HOST, PORT))

            sS.listen()

            connA, addrA = sS.accept()

            print("A accepted. Lucrez cu: {}, {}".format(functia_operare_encrypt, functia_operare_decrypt))
            content_primit = b""
            from_server_A = connA.recv(1024)
            while from_server_A != b'FINAL':
                c_decript, b_decript = functia_operare_decrypt(from_server_A, key, iv)
                blocuri_decriptate += b_decript
                blocuri_primite += 1
                content_primit += c_decript
                from_server_A = connA.recv(1024)

            print("Am primit de la serverul A: {}".format(content_primit))

        result = {"decriptate": blocuri_decriptate, "primite": blocuri_primite}
        result = json.dumps(result)

        result_criptat, _, _ = criptosisteme.encryption_ECB(result, criptosisteme.k3)
        s.sendall(result_criptat)
