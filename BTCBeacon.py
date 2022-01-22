import requests
import random
import hashlib
from binascii import hexlify, unhexlify
import hmac
from math import ceil
import json
hash_len = 32

def get_current_block_hash():
    """Return the currrent block hash from blockchain.info."""
    url = 'https://blockchain.info/q/latesthash'
    r = requests.get(url)
    data = r.content.decode('utf-8')

    return data


def extract_block_index(block_hash):
    """Extract the block index, given the block hash."""
    url = 'https://blockchain.info/rawblock/' + str(block_hash)
    r = requests.get(url)
    data = r.json()
    block_count = data['block_index']

    return block_count


def extract_block_header_hex(block_hash):
    """Extract the block header in hex, given the block hash."""
    url = 'https://blockchain.info/rawblock/' + str(block_hash) + '?format=hex'
    r = requests.get(url)
    data = r.content.decode('utf-8')
    header_hex = data[0:160]

    return header_hex

def lookup_block_hash(blockCount):
    """Return the block hash, given the block index."""
    url = 'https://blockchain.info/rawblock/' + str(blockCount)
    r = requests.get(url)
    data = r.json()
    blockHash = data['hash']

    return blockHash


def hmac_sha256(key, data):
    """Generate pseudo-random-keyed (PRK-keyed) hash-block"""
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf(length, ikm, salt=b"", info=b""):
    """Generate cryptographically strong output key material (OKM) of any desired length.
    Repeatedly generate pseudo-random-keyed (PRK-keyed) hash-blocks, append them into
    the output key material, and finally truncate to the desired length. 
    """
    prk = hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    for i in range(ceil(length / hash_len)):
        t = hmac_sha256(prk, t + info + bytes([1+i]))
        okm += t
    return okm[:length]

 
def output():

    blockCount = get_current_block_hash()
    index = extract_block_index(blockCount)
    lookupHash = lookup_block_hash(index)

    # compute the block hash
    headerHex = extract_block_header_hex(blockCount)
    headerUnhex = unhexlify(headerHex) # convert to binary
    headerHash = hashlib.sha256(hashlib.sha256(headerUnhex).digest()).digest() # hash twice using SHA256
    computedHash = str(hexlify(headerHash[::-1]), 'utf-8') # flip to big-endian

    print("Current round:",index,"")
    # compare hashes
    print("Current block hash {}".format(blockCount))
    if lookupHash == computedHash:
        print("The retrieved hash and the computed hash match! Both hashes are {}".format(lookupHash))
    else:
        print("The retrieved hash and the computed hash don't match! lookupHash is {} and computedHash is {}".format(lookupHash, computedHash))
 
 
    # convert inputs to binary
    # (pre-pend and strip a '1' to preserve leading zeros)
    header_bin = bin(int('1'+headerHex, 16))[3:] # 640 bits
    blockHash_bin = bin(int('1'+lookupHash, 16))[3:] # 256 bits

    # build input and feed to hkdf()
    extractorInput = int(header_bin,2) | int(blockHash_bin,2)
    extractorInput = bin(extractorInput)[2:].zfill(640)


    extractorInputBytes = extractorInput.encode('utf-8') # convert to bytes
    extractorOutputBytes = hkdf(4, extractorInputBytes)
    extractorOutput = bin(int.from_bytes(extractorOutputBytes, 'big'))[2:].zfill(32)
    print("Beacon extracted random following ({} bits number):\n{}".format(len(extractorOutput), extractorOutput))

    seed = int(extractorOutput,2) # creating the seed (converting beaconextractor to decimal)
    nce_list=[]
    winning_numbers_list =[]
    for el in range (6):
        nce = random.random()
        nce_list.append(nce)
        final_seed = seed + nce         # creating a seed by using nonce method
        random.seed(final_seed)
        winning_numbers_list.append(random.randint(1,49))

    print("The current seed in decimal: ", seed)
    print("The randomly generated nonces for the current round: ", nce_list)
    print("Round:",index,"finished with the following winning numbers",winning_numbers_list)


    data = {}
    data['seed'] = []
    data['nce_list'] = []
    data['seed'].append(seed)
    data['nce_list'].append(nce_list)
    with open('data.json', 'w') as f:
        json.dump(data, f)


output()










