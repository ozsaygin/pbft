# Author: Oguz Ozsaygin

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

# n = 20
# t = 100
API_URL = "http://0.0.0.0:5000"

base = 10000


def start(id: int, n: int, t: int):
    text = ''

    port = base + id
    numbers = set()

    # Bind PULL socket
    context = zmq.Context()
    pull_socket = context.socket(zmq.PULL)
    pull_socket.bind("tcp://127.0.0.1:" + str(port))

    # Generate ECC key pairs and signer
    sign_key = ECC.generate(curve="secp256r1")
    verify_key = sign_key.public_key()
    pubkey = verify_key.export_key(format='OpenSSH')
    signer = DSS.new(sign_key, 'fips-186-3')

    # Publish peer info to server
    message = {"id": id, "port": port, "pubkey": pubkey}
    response = requests.post((API_URL+"/peers"), json=message)
    if response.status_code == 201:
        print('Process ' + str(os.getpid()) +
              ' has been registered to server successfully.')

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
                # Create a PUSH socket and send random number for other peers
                push_socket = context.socket(zmq.PUSH)
                push_socket.connect("tcp://127.0.0.1:" + str(peer['port']))
                push_socket.send_json({"r": r})
                # print(str(id) + ' sent r to ' + str(peer['port']))

    print('Node ' + str(id) + ' with pid ' +
          str(os.getpid()) + ' finished PUSH operations.')

    # Wait other peer to finish their jobs
    time.sleep(3)

    for _ in range(n-1):
        data = pull_socket.recv_json()
        numbers.add(data['r'])

    print('Node ' + str(id) + ' with pid ' +
          str(os.getpid()) + ' finished PULL operations.')

    xor_result = 0
    numbers = sorted(numbers)

    # XOR all random numbers
    for num in numbers:
        text += str(num) + '\n'
        xor_result = xor_result ^ num
    # print('Node ' + str(id) + ' XOR result: ' + str(xor_result))

    # Hash random numbers t-times
    digest = SHA3_256.new(xor_result.to_bytes(32, byteorder='big'))
    for i in range(t-1):
        digest = SHA3_256.new(digest.digest())
    leader = int.from_bytes(digest.digest(), 'big') % n
    print('Node ' + str(id) + ' announces leader: ' + str(leader))

    # Write results to file and sign random numbers
    FILENAME = 'election_' + str(id) + '.log'
    f = open(FILENAME, 'w+')
    text += str(leader) + '\n'
    h = SHA3_256.new(text.encode('utf-8'))
    signature = signer.sign(h)

    text += str(int.from_bytes(signature, "big")) + '\n'
    text += str(pubkey)
    f.write(text)
    f.close()


if __name__ == '__main__':

    args = sys.argv

    # Arguments
    # ['peer.py', '-n', '20', '-t', '100']
    if '-n' in args:
        n = int(args[args.index('-n') + 1])
    else: 
        raise Exception('n value is not set!')
    
    if '-t' in args:
        t = int(args[args.index('-t') + 1])
    else: 
        raise Exception('t value is not set!')


    processes = []
    for id in range(n):
        processes.append(Process(target=start, args=(id,n,t)))
        processes[id].start()

    for id in range(n):
        processes[id].join()
