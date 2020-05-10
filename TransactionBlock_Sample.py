# Run "pip install pycryptodome" in the command prompt to use Crypto
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import random
import math
import string
import json

pid = random.randint(0,2**24-1)  # Process id (picked it randomly; nothing special just sufficiently large to avoid collision)

sign_key = ECC.generate(curve='NIST P-256')   # Elliptic curve private key for signing (The curve is in the NIST standards)
verify_key = sign_key.public_key()            # Elliptic curve public key for signature verification 

# We are using Digital Signature Standards (DSS) of NIST (fips-186-3 is a bit old but it is OK) 
signer = DSS.new(sign_key, 'fips-186-3')      # signer instance 
verifier = DSS.new(verify_key, 'fips-186-3')  # verifier instance

#############################################
#############################################
# generate a block of ell transactions
# each transaction is a random string
# the first block of transactions
ell = 10
r = 5
h_prev = SHA3_256.new("".encode('utf-8'))   # set to hash of the empty string as it is the first block
for j in range(0, r):
    block = ""
    for i in range(ell):
        tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])  # random string (nothing special again; assuming a real transaction is a string)
        block += (tau + "\n")      # be careful with the new line character at the end of each line    
    h = SHA3_256.new(block.encode('utf-8')+h_prev.digest()) # hash value must be of "bytes" 
    signature = signer.sign(h)     # sign the hash of the block   
    h_prev = h                     # the current hash now becomes the previous hash for the next block 
    
    f = open('sample_block_'+str(pid)+"_"+str(j)+'.log','wt')   # Open the file (see the naming convention for the log file)
    f.write(block)                                              # write the block first 
    signature = {'pid': pid, 'signature': str(int.from_bytes(signature, "big"))}    
    f.write(json.dumps(signature))                              # use json to write the signature and peer id    
    f.close()

del h, h_prev, signature, block                                 # delete hashes, block, signature as the hashes will be re-calculated and block and signature will be read from the log file 

h_prev = SHA3_256.new("".encode('utf-8'))   # set to hash of the empty string as it is the first block
for j in range(0, r):
    f = open('sample_block_'+str(pid)+"_"+str(j)+'.log','rt')  # open the log file for reading 
    block = f.readlines()                                      # read it to a list, whose elements are lines in the file 
    tmp = json.loads(block[ell])                               # the last line is the signature line
    signature = int(tmp['signature']).to_bytes(64, byteorder='big')   # put the signature into the correct format to verify it  
    block = "".join(block[0:ell])                              # join the transactions into a block 
    h = SHA3_256.new(block.encode('utf-8')+h_prev.digest())    # hash the block
    f.close()
    try:
        verifier.verify(h, signature)                          # verify the block (i.e., its hash of course)
        print ("The block is authentic.")
    except ValueError:
        print ("The block is NOT authentic.")
    h_prev = h    
