# to install ecdsa, run "pip3 install ecdsa" in the command prompt
import random
import string
import sys
import ecdsa
import hashlib
import binascii
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Random import random


def VerifyElection(n, t, logname):
    # Signature verification
    f = open(logname,'rt')
    log = f.readlines()
    
    vkey = ECC.import_key(log[-1])

    sig = int(log[-2]).to_bytes(64, byteorder='big')

    h = SHA3_256.new("".join(log[0:n+1]).encode('utf-8'))

    verifier = DSS.new(vkey, 'fips-186-3')
    try:
        verifier.verify(h, sig)
        print ("The log is authentic.")
    except ValueError:
        print ("The log is not authentic.")
        return -1

    # Verification of the proposer
    R = 0
    for i in range(n):
        R = R ^ int(log[i])

    digest = SHA3_256.new(R.to_bytes(32, byteorder='big'))
    for i in range(t-1):
        digest = SHA3_256.new(digest.digest())
    if int.from_bytes(digest.digest(), "big")%n == int(log[n]):
        print("The proposer is verified", int(log[n]))
    else:
        print("The proposer is NOT verified")
        return -2
    return 0

#######
# Verification Part
#######
n  = 50   # number of peers
t = 100   # hash count 
ell = 50 # number of logs to test ell <= n

fname = 'sample_election_'
for i in range(ell):
    print("#### Filename:", fname+str(i)+".log")
    ret = VerifyElection(n, t, fname+str(i)+".log")
    if ret == -1:
        print("Log signature does NOT verify")
    if ret == -2:
        print("Proposer does NOT verify")
    print("\n")    
        
          
