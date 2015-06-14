# rxorbreak.py
#
# By Joseph Connor
#
# This script reads a hex-encoded repeating-XOR ciphertext on stdin
# and attempts to find the plaintext with basic frequency analysis

from __future__ import division
from string import ascii_lowercase

import sys


def enchunk(l, n):
    """Break list into chunks of size n"""
    chunks = []
    for i in xrange(0, len(l), n):
        chunks.append(l[i:i+n])
    return chunks


def xor(key, msg):
    """Encrypt or decrypt a repeating xor cipher"""
    key = key * (len(msg)/len(key) + 1)
    return ''.join(chr(ord(k) ^ ord(m)) for k, m in zip(key, msg))


def hamming(s1, s2):
    """Count the number of differing bits between two strings"""
    total = 0
    for c1, c2 in zip(s1, s2):
        total += sum(((ord(c1)^ord(c2)) >> i) & 1 for i in range(8))
    return total


def avg_hamming(keylen, ciphertext):
    """Calculate average hamming distance in first two chunks of cipertext"""
    chunks = enchunk(ciphertext, keylen)[:-1]
    return hamming(chunks[0], chunks[1]) / keylen


def try_keylen(keylen, ciphertext):
    """Try and find the most likely key for a given key length"""
    chunks = enchunk(ciphertext, keylen)[:-1]
    key = ''
    # Transpose chunks to get sets of bytes xored with same key byte
    nth_chars = zip(*chunks)

    # Find the most likely key byte for each set
    for nth_char in nth_chars:
        best_k = None
        max_letters = 0

        for k in range(256):
            # Right now, we just assume the best key byte is the one
            # that results in the most lower-case ascii letters
            # TODO: better frequency analysis
            plaintext = xor(chr(k), nth_char)
            num_letters = len([c for c in plaintext if c in ascii_lowercase])

            if best_k is None or num_letters > max_letters:
                best_k = k
                max_letters = num_letters

        key += chr(best_k)

    return key 
    

ciphertext = sys.stdin.read().strip().decode('hex')

print("calculating most likely key lenghts...")

hammings = [(keylen, avg_hamming(keylen, ciphertext)) for keylen in range(1, len(ciphertext)/3)]
hammings = sorted(hammings, key=lambda x: x[1])

for keylen, dist in hammings:
    print("Trying key length %d" % keylen)
    key = try_keylen(keylen, ciphertext)
    if key is not None:
        print("key = %s" % key.encode('hex'))
        print(xor(key, ciphertext))
        break
