# Run "pip install pycryptodome" in the command prompt to use Crypto
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import random
import math
import string
import json
from random import shuffle
import sys, os

def CheckBlock(block, ell, h_prev, verifiers):
    tmp = json.loads(block[ell])
    block = "".join(block[0:ell])
    h = SHA3_256.new(block.encode('utf-8')+h_prev.digest())
    cnt = 0
    for i in range(len(tmp)):        # check each signature
        pid = tmp[i]['pid']
        #print("pid: ", pid); input("Enter")
        signature = int(tmp[i]['signature']).to_bytes(64, byteorder='big')
        try:
            verifiers[pid].verify(h, signature)
            cnt += 1
        except ValueError:
            return -1, -1, -1
    return 0, h, cnt
    

## Note that verifiers is a list constructed from the public keys of the peers
## You need to get them (i.e., verify_keys) from the index server using REST API
ell = 10  # transaction count in a block
r = 5     # number of blockc
n = 7     # number of peers
tolerance = (n-1)//3
ScenarioNo = 1
print("Fault tolerance degree (f): ", tolerance)

# We are reading the public keys from the disk
# But you need to modify this part
######################################
import requests
verify_keys = dict()
API_URL = 'http://0.0.0.0:5000'
response = requests.get((API_URL + '/peers'))
infos = response.json()
for info in infos:
    pid = str(info['pid'])
    pubkey = info['pubkey']
    verify_keys[pid] = pubkey
######################################

PID = []
for key in sorted(verify_keys.keys()):
    PID.append(int(key))

verifiers = dict.fromkeys(PID)   # PID is the list of peer IDs
for i in range(n):
    verifiers[PID[i]] = DSS.new(ECC.import_key(verify_keys[str(PID[i])]), 'fips-186-3')

block_set = []
for j in range(r):
    block_set.append([])

DirPrefix = "Sc"+str(ScenarioNo)+"_"+"Peer_"    
    
for k in PID:    # check the log files of each peer
    if os.listdir(DirPrefix+str(k)):
        print("Log files exist for Peer", k)
        h_prev = SHA3_256.new("".encode('utf-8'))   # set to hash of the empty string as it is the first block
        for j in range(r):
            filename = DirPrefix+str(k)+'/block_'+str(j)+'_0'+'.log'
            if os.path.isfile(filename):
                f = open(filename, 'rt')
                block = f.readlines()
                f.close()
                correct, tmp, cnt = CheckBlock(block, ell, h_prev, verifiers)
                if correct == 0 and cnt > 2*tolerance:
                    #h_prev = tmp   
                    print("Block in %s is signed by %d peers" %(filename,cnt))
                elif correct == 0 and cnt <= 2*tolerance:
                    print("Block in %s is signed by insufficient number of peers" %(filename))
            filename = DirPrefix+str(k)+'/block_'+str(j)+'_1'+'.log'
            if os.path.isfile(filename):
                f = open(filename, 'rt')
                block = f.readlines()
                f.close()
                correct, tmp, cnt = CheckBlock(block, ell, h_prev, verifiers)
                if correct == 0 and cnt > 2*tolerance:
                    #h_prev = tmp
                    print("Block in %s is signed by %d peers" %(filename,cnt))
                elif correct == 0 and cnt <= 2*tolerance:
                    print("Block in %s is signed by insufficient number of peers" %(filename))  
            h_prev=tmp  
    else:
        print("Log files DO NOT exist for Peer", k, "Malicious")
