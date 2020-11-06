try:
    from . import criptosisteme
except:
    import criptosisteme
from Crypto.Cipher import AES
from Crypto import Random
import socket
import json

HOST = '127.0.0.1'
PORT = 45433
PORT_A = 45431
PORT_B = 45432


init_vector = Random.get_random_bytes(AES.block_size)  # genereaza un string de 16 bytes random
k1 = "1cheiecomunicare"  # CBC A - B
k2 = "comunicare2cheie"  # CFB A - B
                         # k3 este pentru criptarea k1, k2 si init_vector
                         # k3 pentru KM - A, KM - B


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))

    s.listen()
    print('I am KM node. Waiting for comunication...')
    #while True:
    connA, addrA = s.accept()
    print("Connected by client A: {} Waiting for client B...".format(addrA))
    connB, addrB = s.accept()
    print("Connected by client B: {} Good to go...".format(addrB))

    data_A_recv = connA.recv(1024)
    data_A_to_send = "Am primit modul de operare {}".format(data_A_recv)
    connA.sendall(criptosisteme.convert_string_to_bytes(data_A_to_send))
    print("Am trimis catre nodul A: {}".format(data_A_to_send))

    connB.sendall(data_A_recv)
    print("Am trimis catre nodul B, algoritmul dorit: {}".format(data_A_recv))

    algorithm = str(data_A_recv)

    key_to_send = ""
    init_vector_to_send = init_vector

    if algorithm == "CFB":
        key_to_send = k1
    else:
        key_to_send = k2

    crypted_key_to_send, _, _ = criptosisteme.encryption_ECB(key_to_send, criptosisteme.k3)
    crypted_init_vector_to_send, _, _ = criptosisteme.encryption_ECB(init_vector_to_send, criptosisteme.k3)
    print('crypted_key_to_send', crypted_key_to_send)
    print('crypted_init_vector_to_send', crypted_init_vector_to_send)

    connA.sendall(crypted_key_to_send)
    connA.sendall(crypted_init_vector_to_send)

    connB.sendall(crypted_key_to_send)
    connB.sendall(crypted_init_vector_to_send)

    data_A_recv = connA.recv(1024)
    data_B_recv = connB.recv(1024)

    data_A_recv_decrypted, _ = criptosisteme.decryption_ECB(data_A_recv, criptosisteme.k3)
    data_B_recv_decrypted, _ = criptosisteme.decryption_ECB(data_B_recv, criptosisteme.k3)

    print('Am primit: {}'.format(data_A_recv_decrypted))
    print('Am primit: {}'.format(data_B_recv_decrypted))

    if b"Am primit" in data_A_recv_decrypted and b"Am primit" in data_B_recv_decrypted:
        to_send_message = "GO,GO,GO"
        encrypted_message, _, _ = criptosisteme.encryption_ECB(to_send_message, criptosisteme.k3)

        connA.sendall(encrypted_message)
        connB.sendall(encrypted_message)

        print("Am trimis confirmarile. I out of here. Good luck A, Good luck B, waiting for your results")

        results_A = connA.recv(1024)
        results_B = connB.recv(1024)

        results_A_recv_decrypted, _ = criptosisteme.decryption_ECB(results_A, criptosisteme.k3)
        results_B_recv_decrypted, _ = criptosisteme.decryption_ECB(results_B, criptosisteme.k3)

        results_A = json.loads(results_A_recv_decrypted)
        results_B = json.loads(results_B_recv_decrypted)

        if results_A["criptate"] != results_B["decriptate"] or results_A["trimise"] != results_B["primite"]:
            print("Oh, nooo, clientii au gresit... Ce s-a intamplat?")
            print("Results_A: {}".format(json.dumps(results_A)))
            print("Results_B: {}".format(json.dumps(results_B)))
        else:
            print("Greeeaaat! The clients did weeeelll!!")
            print("Results_A: {}".format(json.dumps(results_A)))
            print("Results_B: {}".format(json.dumps(results_B)))











