# Run "pip install pycryptodome" in the command prompt to use Crypto
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import random
import math
import string
import json
from random import shuffle
import requests
import sys

## Note that verifiers is a list constructed from the public keys of the peers
## You need to get them (i.e., verify_keys) from the index server using REST API
ell = 10  # transaction count in a block
r = 1     # number of block
n = 4     # number of peers
tolerance = (n-1)//3
print("Fault tolerance degree (f): ", tolerance)

# We are reading the public keys from the disk
# But you need to modify this part
######################################
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
    
for k in range(n):    # check the log file of each peer
    print("\n############")
    print("The log of peer ", k)
    h_prev = SHA3_256.new("".encode('utf-8'))   # set to hash of the empty string as it is the first block
    for j in range(r):      # check each block
        print("Block no: ", j)
        f = open('block_'+str(PID[k])+"_"+str(j)+'.log','rt')
        block = f.readlines()
        f.close()
        tmp = json.loads(block[ell])
        block = "".join(block[0:ell])
        if block not in block_set[j]:
            block_set[j].append(block)
        h = SHA3_256.new(block.encode('utf-8')+h_prev.digest())
        cnt = 0
        for i in range(n):        # check each signature
            pid = tmp[i]['pid']
            signature = int(tmp[i]['signature']).to_bytes(64, byteorder='big')
            try:
                verifiers[pid].verify(h, signature)
                cnt += 1
                print ("The signature of the peer %d for the block %d verifies" %(pid, k))
            except ValueError:
                print ("The signature of the peer %d for the block %d DOES NOT verify" %(pid, k))
                sys.exit()
        h_prev = h
        if cnt > 2*tolerance:
            print("Sufficiently many signatures verify")
        else:
            print("NOT sufficiently many signatures verify")
            sys.exit()

# we want to see if there are more than one block for each round
# The peers should agree on the same block in every round (for this phase)
for j in range(r):
    if (len(block_set[j])!=1):
        print("Conflicting blocks for the round ", j)
        sys.exit()
    else:
        print("Same block for the round ", j)

# If reach here, then success
print("Congratulations! all tests passed")

