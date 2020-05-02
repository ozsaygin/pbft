import json
import os
import sys
import random
import requests
import time
import zmq


from multiprocessing import Process
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from pprint import pprint

n = 20
t = 100
API_URL = "http://0.0.0.0:5000"

base = 10000

def start(id: int):
    text = ''
    f = open('sample_election_' + str(id) + '.log', 'w+')
    port = base + id
    numbers = set()
    context = zmq.Context()
    pull_socket = context.socket(zmq.PULL)
    pull_socket.bind("tcp://127.0.0.1:" + str(port))
   

    # Generate ECC key pairs and signer
    sign_key = ECC.generate(curve="secp256r1")
    verify_key = sign_key.public_key()
    pubkey = verify_key.export_key(format='OpenSSH')
    signer = DSS.new(sign_key, 'fips-186-3')

    message = {"id": id, "port": port, "pubkey": pubkey}

    response = requests.post((API_URL+"/peers"), json=message)
    if response.status_code == 201:
        print('Process ' + str(os.getpid()) +
              ' has been registered successfully.')

    # Generate 256-bit random number
    r = random.getrandbits(256)
    numbers.add(r)



    # Wait a while for other processes to post
    time.sleep(5)

    # GET peer informations
    response = requests.get((API_URL + '/peers'))
    if response.status_code == 200:
        peer_infos = response.json()
        for peer in peer_infos:
            if peer["id"] != id:
                push_socket = context.socket(zmq.PUSH)
                push_socket.connect("tcp://127.0.0.1:" + str(peer['port']))
                push_socket.send_json({"r": r})
                print(str(id) + ' sent r to ' + str(peer['port']))

    print(str(id) + ' pushing finished')
    time.sleep(5)

    for _ in range(n-1):
        print(str(id) + ' : start pulling')
        data = pull_socket.recv_json()
        print(str(id) +': pulled ' + str(data['r']) )
        print(str(id) + ' : end pulling')
        numbers.add(data['r'])
    print(str(id) + ' : finished pulling')

    xor_result = 0
    numbers = sorted(numbers)


    for num in numbers:
        text += str(num) + '\n'
        xor_result = xor_result ^ num

    print(str(id) + ' :' + str(r))
    pprint(numbers)
    print('xor result: ', xor_result)

    digest = SHA3_256.new(xor_result.to_bytes(32, byteorder='big'))
    for i in range(t-1):
        digest = SHA3_256.new(digest.digest())
    leader = int.from_bytes(digest.digest(), 'big') % n
    print('leader: ', leader)
    text += str(leader) + '\n'

    
    h = SHA3_256.new(text.encode('utf-8'))
    signature = signer.sign(h)

    text += str(int.from_bytes(signature, "big")) + '\n'
    text += str(pubkey)
    f.write(text)
    f.close()




if __name__ == '__main__':

    processes = []
    for id in range(n):
        processes.append(Process(target=start, args=(id,)))
        processes[id].start()

    for id in range(n):
        processes[id].join()
