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

n = 7  # number of peers
t = 100  # number of hash operations
ell = 10  # number of transactions
r = 5  # number of rounds
tolerance = (n-1)//3  # degree of tolerance
k = tolerance
ScenarioNo =1 
API_URL = "http://0.0.0.0:5000"
BASE_PORT = 10000

def generate_block(ell):
    block = ""
    for i in range(ell):
        tau = "".join([random.choice(string.ascii_letters + string.digits)
                       for n in range(64)])
        block += (tau + "\n")
    return block


def send_message(peer_port, message):
    context = zmq.Context()
    push_socket = context.socket(zmq.PUSH)
    push_socket.connect("tcp://127.0.0.1:" + str(peer_port))
    push_socket.send_json(message)


def succ(pids, x):
    pids.sort()
    for p in pids:
        if p > x:
            return p
    return pids[0]


def start(i: int, pid: int, n: int, t: int):
    DirPrefix = "Sc"+str(ScenarioNo)+"_"+"Peer_"  + str(pid)  
    os.mkdir(DirPrefix)
    text = ""

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
    pubkey = verify_key.export_key(format="OpenSSH")
    signer = DSS.new(sign_key, "fips-186-3")

    # Publish peer info to server
    message = {"id": i, "pid": pid, "port": port, "pubkey": pubkey}
    response = requests.post((API_URL+"/peers"), json=message)
    if response.status_code == 201:
        print("Process " + str(pid) +
              " has been registered to server successfully.")
    else:
        raise Exception("Node with pid " + str(pid) +
                        " cannot registered to index server.")

    # Wait other nodes to register
    time.sleep(3)

    # Generate 256-bit random number
    randnum = random.getrandbits(256)
    numbers.add(r)

    # Get peer informations
    response = requests.get((API_URL + "/peers"))
    if response.status_code == 200:
        peer_infos = response.json()
        for peer in peer_infos:
            node_pids.append(peer["pid"])
            if peer["pid"] != pid:
                # Create a PUSH socket and send random number for other peers
                peer_ports.append(peer["port"])
                push_socket = context.socket(zmq.PUSH)
                push_socket.connect("tcp://127.0.0.1:" + str(peer["port"]))
                push_socket.send_json({"r": randnum})
    else:
        print("Node " + str(pid) + " cannot retrive peer informations")

    print("Node " + str(pid) + " with pid " +
          str(os.getpid()) + " finished PUSH operations.")

    # Wait other peer to finish their jobs
    time.sleep(3)

    for _ in range(n-1):
        data = pull_socket.recv_json()
        numbers.add(data["r"])

    print("Node " + str(pid) + " with pid " +
          str(os.getpid()) + " finished PULL operations.")

    xor_result = 0
    numbers = sorted(numbers)

    # XOR all random numbers
    for num in numbers:
        text += str(num) + "\n"
        xor_result = xor_result ^ num
    # print("Node " + str(id) + " XOR result: " + str(xor_result))

    # Hash random numbers t-times
    digest = SHA3_256.new(xor_result.to_bytes(32, byteorder="big"))
    for i in range(t-1):
        digest = SHA3_256.new(digest.digest())

    result = int.from_bytes(digest.digest(), "big") % n
    leader = succ(node_pids, result)
    print("Node " + str(pid) + " announces leader: " + str(leader))

    # Write results to file and sign random numbers
    FILENAME = "election_" + str(pid) + ".log"
    f = open(FILENAME, "w+")
    text += str(leader) + "\n"
    h = SHA3_256.new(text.encode("utf-8"))
    signature = signer.sign(h)

    text += str(int.from_bytes(signature, "big")) + "\n"
    text += str(pubkey)
    f.write(text)
    f.close()

    # Select k-random attacker nodes except leader
    # Every nodes apply to become malicious
    # If slot exits, let them be, otherwise they are honest
    status = "honest"
    if leader != pid:
        message = {"id": i, "pid": pid, "port": port, "pubkey": pubkey, "k": k}
        response = requests.post((API_URL + "/applymalicous"), json=message)
        data = response.json()  # defined whether bad or good boy
        status = data["status"]
    print(str(pid) + "Node is " + status)
    
    h_prev = SHA3_256.new("".encode("utf-8"))  # inital h_prev is empty string
    for j in range(0, r):  # Run consensus for r rounds
        verified_blocks = {}
        if leader == pid:  # Node is the leader
            print("Consesus protocol is initated...")
            print("Round %d" % j)
            block = generate_block(ell)
            # hash block with h_prev
            h = SHA3_256.new(block.encode("utf-8")+h_prev.digest())
            signature = signer.sign(h)  # generate signature for current block

            # now send the block with its signature to validators
            for pp in peer_ports:
                message = {"block": block, "pid": pid,
                           "signature": str(int.from_bytes(signature, "big"))}
                send_message(pp, message)

            # wait for message propogation to validators
            time.sleep(5)

            # add leader signature to valid signatures
            verified_blocks.update({block: [{"pid": pid, "signature": str(int.from_bytes(signature, "big"))}]})

            # start to pull verified blocks from validatos
            for _ in range(n-1):
                data = pull_socket.recv_json()
                v_block = data["block"]
                v_signature = data["signature"]
                # get pubkey of validator
                verify_key = ECC.import_key(requests.get((API_URL + "/peers/"+str(data["pid"]))).json()["pubkey"])
                verifier = DSS.new(verify_key, "fips-186-3")
                try:
                    # calculate hash of validator block
                    h_val = SHA3_256.new(v_block.encode("utf-8")+h_prev.digest())
                    # verify the signature of validator
                    verifier.verify(h_val, int( v_signature).to_bytes(64, byteorder="big"))

                    if v_block not in verified_blocks:
                       verified_blocks.update({v_block: [{"pid": data["pid"], "signature": data["signature"]}]})
                    else: 
                        verified_blocks[v_block].append({"pid": data["pid"], "signature": data["signature"]})

                except ValueError:
                    print("The signature of the peer DOES NOT verify " + str(pid))
                    pass

            blocks = [block for block in verified_blocks]
            for i, b in enumerate(blocks):
                f = open(DirPrefix + "/block_"+str(j)+"_"+str(i)+".log", "wt")
                f.write(b)
                f.write(json.dumps(verified_blocks[b]))
                f.close()

            if len(blocks[0]) > 2*tolerance:
                print("Block 0 has been accepted validator with %d pid" % pid)
            elif len(blocks[1]) > 2*tolerance:
                print("Block 1 has been accepted validator with %d pid" % pid)
            else:
                print("Block is declined")
            h_prev = h
            time.sleep(10)

        else:  # Node is a validator
            data = pull_socket.recv_json() # proposer"s block 
            p_block = data["block"]
            p_signature = data["signature"]

            # get pubkey of proposar and verify the block
            p_pubkey = requests.get((API_URL + "/peers/"+str(data["pid"]))).json()["pubkey"]
            verifier = DSS.new(ECC.import_key(p_pubkey), "fips-186-3")
            try:
                h = SHA3_256.new(p_block.encode("utf-8")+h_prev.digest())
                verifier.verify(h, int(p_signature).to_bytes(64, byteorder="big"))
                v_signature = signer.sign(h)   # sign the hash of the block
                verified_blocks.update({p_block:[{"pid": data["pid"], "signature": p_signature}]})# proposars block 
                verified_blocks[p_block].append({"pid": pid, "signature": str( int.from_bytes(v_signature, "big"))})  # validators block

                # wait a while make sure that every node has the original block
                # propagate the block 
                time.sleep(5)   

                if status == "malicous" and j == r-1:
                    bad_block = requests.post((API_URL + "/fakeblock"), json={"block": generate_block(ell)}).json()["block"]
                    bad_sign = signer.sign( SHA3_256.new(bad_block.encode("utf-8")+h_prev.digest()))
                    for pp in peer_ports:
                        message = {"block":  bad_block, "pid": pid, "signature": str(
                            int.from_bytes(bad_sign, "big"))}
                        send_message(pp, message)

                    for _ in range(n-2):  # clear queue
                        data = pull_socket.recv_json()

                else: # if honest
                    for pp in peer_ports:
                        message = {"block": p_block, "pid": pid, "signature": str(
                            int.from_bytes(v_signature, "big"))}
                        send_message(pp, message)

                    for _ in range(n-2):  # start to pull from other validators
                        data = pull_socket.recv_json()
                        vv_signature = data["signature"]
                        vv_pid = data["pid"]
                        vv_block = data["block"]
                        h_vval = SHA3_256.new(vv_block.encode("utf-8") + h_prev.digest())
                        verifier = DSS.new(ECC.import_key(requests.get( (API_URL + "/peers/"+str(data["pid"]))).json()["pubkey"]), "fips-186-3")
                        try:
                            verifier.verify(h_vval, int(vv_signature).to_bytes(64, byteorder="big"))

                            if vv_block not in verified_blocks:
                                verified_blocks.update({vv_block: [{"pid": data["pid"], "signature": data["signature"]}]})
                            else: 
                                verified_blocks[vv_block].append({"pid": data["pid"], "signature": data["signature"]})
                        except ValueError:
                            print( "The signature of the peer DOES NOT verify: " + str(pid))
                            pass

                    blocks = [block for block in verified_blocks]
                    for i, b in enumerate(blocks):
                        if status == 'honest':
                            f = open(DirPrefix + "/block_"+str(j)+"_"+str(i)+".log", "wt")
                            f.write(b)
                            f.write(json.dumps(verified_blocks[b]))
                            f.close()

                    if len(blocks[0]) > 2*tolerance:
                        print("Block 0 has been accepted validator with %d pid" % pid)
                    elif len(blocks[1]) > 2*tolerance:
                        print("Block 1 has been accepted validator with %d pid" % pid)
                    else:
                        print("Block is declined")
                h_prev = h  
            except ValueError:
                print("The signature of the peer DOES NOT verify: " + str(pid))
                pass


if __name__ == "__main__":

    processes = []
    for i in range(n):
        pid = random.randint(0, 2**24-1)
        processes.append(Process(target=start, args=(i, pid, n, t)))
        processes[i].start()

    for i in range(n):
        processes[i].join()
