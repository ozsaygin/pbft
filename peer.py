# Author: Oguz Ozsaygin

import json
import os
import sys
import random
import requests
import string
import sys
import time
import zmq

from enum import Enum, auto
from multiprocessing import Process
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

n = 5  # number of peers
t = 100  # number of hash operations
ell = 10  # number of transactions
r = 5  # number of rounds
k = 2  # degree of tolerance

API_URL = 'http://0.0.0.0:5000'
BASE_PORT = 10000


def succ(pids, x):
    pids.sort()
    for p in pids:
        if p > x:
            return p
    return pids[0]


def start(i: int, pid: int, n: int, t: int):
    '''
    % INIT PHASE %
    '''
    text = ''

    # Receiver port for zmq
    port = BASE_PORT + i
    numbers = set()
    node_pids = []
    peer_ports = []

    # Bind PULL socket
    context = zmq.Context()
    pull_socket = context.socket(zmq.PULL)
    pull_socket.bind("tcp://127.0.0.1:" + str(port))

    # Generate ECC key pairs, signer and verifier
    sign_key = ECC.generate(curve="secp256r1")
    verify_key = sign_key.public_key()
    pubkey = verify_key.export_key(format='OpenSSH')
    signer = DSS.new(sign_key, 'fips-186-3')

    # Publish peer info to server
    message = {"id": i, "pid": pid, "port": port, "pubkey": pubkey}
    response = requests.post((API_URL+"/peers"), json=message)
    if response.status_code == 201:
        print('Process ' + str(pid) +
              ' has been registered to server successfully.')
    else:
        raise Exception('Node with pid ' + str(pid) +
                        ' cannot registered to index server.')

    # Wait other nodes to register
    time.sleep(3)

    # Generate 256-bit random number
    r = random.getrandbits(256)
    numbers.add(r)

    # Get peer informations
    response = requests.get((API_URL + '/peers'))
    if response.status_code == 200:
        peer_infos = response.json()
        for peer in peer_infos:
            node_pids.append(peer['pid'])
            if peer["id"] != i:
                # Create a PUSH socket and send random number for other peers
                peer_ports.append(peer['port'])
                push_socket = context.socket(zmq.PUSH)
                push_socket.connect("tcp://127.0.0.1:" + str(peer['port']))
                push_socket.send_json({"r": r})
    else:
        print('Node ' + str(pid) + ' cannot retrive peer informations')

    print('Node ' + str(pid) + ' with pid ' +
          str(os.getpid()) + ' finished PUSH operations.')

    # Wait other peer to finish their jobs
    time.sleep(3)

    for _ in range(n-1):
        data = pull_socket.recv_json()
        numbers.add(data['r'])

    print('Node ' + str(pid) + ' with pid ' +
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

    result = int.from_bytes(digest.digest(), 'big') % n
    leader = succ(node_pids, result)
    print('Node ' + str(pid) + ' announces leader: ' + str(leader))

    # Write results to file and sign random numbers
    FILENAME = 'election_' + str(pid) + '.log'
    f = open(FILENAME, 'w+')
    text += str(leader) + '\n'
    h = SHA3_256.new(text.encode('utf-8'))
    signature = signer.sign(h)

    text += str(int.from_bytes(signature, "big")) + '\n'
    text += str(pubkey)
    f.write(text)
    f.close()

    if leader == pid:  # Node is the leader
        h_prev = SHA3_256.new("".encode('utf-8'))
        for j in range(0, r):
            block = ""
            for i in range(ell):
                tau = "".join([random.choice(string.ascii_letters + string.digits)
                               for n in range(64)])
                block += (tau + "\n")
            h = SHA3_256.new(block.encode('utf-8')+h_prev.digest())
            signature = signer.sign(h)

            for pp in peer_ports:
                push_socket = context.socket(zmq.PUSH)
                push_socket.connect("tcp://127.0.0.1:" + str(pp))
                message = {"block": block, "pid": pid,
                           "signature": str(int.from_bytes(signature, "big"))}
                push_socket.send_json(message)

            # wait for message propogation
            time.sleep(5)

            # receive signed blocks from validators
            num_verified = 0
            verified_signs = []
            verified_signs.append({'pid': pid, "signature": str(
                int.from_bytes(signature, "big"))})

            for _ in range(n-1):
                data = pull_socket.recv_json()
                response = requests.get((API_URL + '/peers/'+str(data['pid'])))
                if response.status_code == 200:
                    try:
                        peer_info = response.json()
                        h_val = SHA3_256.new(
                            data['block'].encode('utf-8')+h_prev.digest())
                        verify_key = ECC.import_key(peer_info['pubkey'])
                        verifier = DSS.new(verify_key, 'fips-186-3')
                        verifier.verify(h_val, int(
                            data['signature']).to_bytes(64, byteorder='big'))
                        if data['block'] == block:
                            num_verified += 1
                            verified_signs.append(
                                {'pid': data['pid'], 'signature': data['signature']})
                        else:
                            raise('Block is not same!!')
                            sys.exit()
                    except ValueError:
                        print("The signature of the peer DOES NOT verify " + str(pid))
                        sys.exit()
            if num_verified >= k:
                print('Block has been accepted')
                # Open the file (see the naming convention for the log file)
                f = open('block_'+str(pid)+"_"+str(j)+'.log', 'wt')
                # write the block first
                f.write(block)
                f.write(json.dumps(verified_signs))
                f.close()
            else:
                print('Block is declined')
            h_prev = h

    else:  # Node is a validator
        time.sleep(5)
        h_prev = SHA3_256.new("".encode('utf-8'))
        for j in range(0, r):  # execute rounds
            data = pull_socket.recv_json()
            num_verified = 0
            verified_signs = []
            response = requests.get((API_URL + '/peers/'+str(data['pid'])))
            if response.status_code == 200:
                try:
                    peer_info = response.json()
                    current_block = data['block']
                    h = SHA3_256.new(data['block'].encode(
                        'utf-8')+h_prev.digest())
                    verify_key = ECC.import_key(peer_info['pubkey'])
                    verifier = DSS.new(verify_key, 'fips-186-3')
                    verifier.verify(
                        h, int(data['signature']).to_bytes(64, byteorder='big'))
                    signature = signer.sign(h)     # sign the hash of the block

                    for pp in peer_ports:
                        push_socket = context.socket(zmq.PUSH)
                        push_socket.connect("tcp://127.0.0.1:" + str(pp))
                        push_socket.send_json({"block": data['block'], "pid": pid, "signature": str(
                            int.from_bytes(signature, "big"))})

                    time.sleep(5)

                    for _ in range(n-2):
                        data = pull_socket.recv_json()
                        response = requests.get(
                            (API_URL + '/peers/'+str(data['pid'])))
                        if response.status_code == 200:
                            try:
                                peer_info = response.json()
                                h_peer = SHA3_256.new(
                                    data['block'].encode('utf-8')+h_prev.digest())
                                verify_key = ECC.import_key(
                                    peer_info['pubkey'])
                                verifier = DSS.new(verify_key, 'fips-186-3')
                                verifier.verify(h_peer, int(
                                    data['signature']).to_bytes(64, byteorder='big'))
                                if current_block == data['block']:
                                    num_verified += 1
                                    verified_signs.append(
                                        {'pid': data['pid'], 'signature': data['signature']})
                            except ValueError:
                                print("The signature of the peer DOES NOT verify")
                                sys.exit()
                    if num_verified >= k:
                        print('Block has been accepted: ' + str(pid))
                        f = open('block_'+str(pid)+"_"+str(j)+'.log', 'wt')
                        f.write(data['block'])
                        f.write(json.dumps(verified_signs))
                        f.close()
                    else:
                        print('Block is declined')
                except ValueError:
                    print("The signature of the peer DOES NOT verify")
                    sys.exit()
            h_prev = h


if __name__ == '__main__':

    processes = []
    for i in range(n):
        pid = random.randint(0, 2**24-1)
        processes.append(Process(target=start, args=(i, pid, n, t)))
        processes[i].start()

    for i in range(n):
        processes[i].join()
