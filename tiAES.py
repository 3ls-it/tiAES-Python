#!/usr/bin/env python3
# tiAES.py
# (c) 2024, 2025 J. Adams jfa63[at]duck[dot]com
# Released under the 2-clause BSD Licence

"""
 This implementation tries to by fully compliant with the FIPS 197 Advanced Encryption
Standard:
https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
While it works, we cannot make any claims as to how secure the coding is nor is it very
fast on large files. Do not use this code for anything other that personal education and
enjoyment.
"""

import os
import sys
import hashlib
import hmac
import argparse
from getpass import getpass
import numpy as np  # for CBC file I/O and block operations
import gc
# AES lookup tables (imported as numpy arrays, will convert to Python lists)
from aes_tables import NB, sbox as _sbox, sboxinv as _sboxinv, m2 as _m2, m3 as _m3, m9 as _m9, m11 as _m11, m13 as _m13, m14 as _m14

# Convert lookup tables to native Python lists
sbox = list(_sbox)
sboxinv = list(_sboxinv)
m2 = list(_m2)
m3 = list(_m3)
m9 = list(_m9)
m11 = list(_m11)
m13 = list(_m13)
m14 = list(_m14)

# --- Internal utility functions (pure-Python AES helpers) ---
def _bytes2state(block: bytes) -> list:
    """Convert 16-byte block into AES state (4×4 list, row-major structure but column-major mapping)."""
    return [[block[c*4 + r] for c in range(NB)] for r in range(4)]

def _state2bytes(state: list) -> bytes:
    """Flatten AES state into 16-byte block using column-major order."""
    return bytes(state[r][c] for c in range(NB) for r in range(4))

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))
 


## Functions

def KeyExpansion(key: bytes) -> list:
    """
    AES key expansion (FIPS-197).
    key: 16, 24, or 32 bytes. Returns list of 4-byte words.
    """
    key_len = len(key)
    if key_len not in (16, 24, 32):
        raise ValueError("Key must be 128, 192, or 256 bits")

    nk = key_len // 4
    nr = nk + 6
    total_words = NB * (nr + 1)

    # Rcon constants
    rcons = [
        [0x01, 0, 0, 0], [0x02, 0, 0, 0], [0x04, 0, 0, 0],
        [0x08, 0, 0, 0], [0x10, 0, 0, 0], [0x20, 0, 0, 0],
        [0x40, 0, 0, 0], [0x80, 0, 0, 0], [0x1b, 0, 0, 0],
        [0x36, 0, 0, 0], [0x6c, 0, 0, 0], [0xd8, 0, 0, 0],
    ]

    # Initialize key schedule 
    w = [[0]*4 for _ in range(total_words)]
    # Copy initial key
    for i in range(nk):
        w[i] = list(key[4*i : 4*i+4])

    # Expand words
    for i in range(nk, total_words):
        temp = w[i-1].copy()
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            rc = rcons[i//nk - 1]
            temp = [temp[j] ^ rc[j] for j in range(4)]
        elif nk > 6 and i % nk == 4:
            temp = [sbox[b] for b in temp]
        w[i] = [w[i-nk][j] ^ temp[j] for j in range(4)]

    return w
# End KeyExpansion


def AddRoundKey(state: list, w: list, rnd: int) -> list:
    """
    XOR state matrix with round key from key schedule.
    """
    for c in range(4):
        wd = w[rnd * 4 + c]
        for r in range(4):
            state[r][c] ^= wd[r]
    return state
# End AddRoundKey


# Change SubBytes to work on numpy arrays
def SubBytes(state: np.ndarray) -> np.ndarray:
    """
    Substitute bytes in state using sbox.
    """
    for r in range(4):
        for c in range(4):
            state[r, c] = sbox[int(state[r, c])]
    return state
# End SubBytes


# Change InvSubBytes to work on numpy arrays
def InvSubBytes(state: np.ndarray) -> np.ndarray:
    """
    Substitute bytes in state using inverse sbox.
    """
    for r in range(4):
        for c in range(4):
            state[r, c] = sboxinv[int(state[r, c])]
    return state
# End InvSubBytes


# Change ShiftRows to work on numpy arrays
def ShiftRows(state: np.ndarray) -> np.ndarray:
    """
    Shift rows of state left by offsets [0,1,2,3].
    """
    nst = state.copy()
    nst[1, :] = np.roll(state[1, :], -1)
    nst[2, :] = np.roll(state[2, :], -2)
    nst[3, :] = np.roll(state[3, :], -3)
    return nst
# End ShiftRows


def InvShiftRows(st: np.ndarray) -> np.ndarray:
    """
    Implements the FIPS 197 InvShiftRows() routine.
    Array st is the state.
    Shift values right (+) in rows 2, 3 and 4 of st
    by 1, 2 and 3 places, respectively.
    #These calls to numpy.roll() are very expensive.
    st[1, :] = np.roll(st[1, :], 1)
    st[2, :] = np.roll(st[2, :], 2)
    st[3, :] = np.roll(st[3, :], 3)
    The code below is twice as fast.
    """
    nst = np.zeros((4,4), dtype=np.uint8)

    #row 1, no rotation
    nst[0, :] = st[0, :]
    #row 2, -1 rotation
    nst[1, 0] = st[1, 3]
    nst[1, 1] = st[1, 0]
    nst[1, 2] = st[1, 1]
    nst[1, 3] = st[1, 2]
    #row 3, -2 rotation
    nst[2, 0] = st[2, 2]
    nst[2, 1] = st[2, 3]
    nst[2, 2] = st[2, 0]
    nst[2, 3] = st[2, 1]
    #row 4, -3 rotation
    nst[3, 0] = st[3, 1]
    nst[3, 1] = st[3, 2]
    nst[3, 2] = st[3, 3]
    nst[3, 3] = st[3, 0]

    return nst
# End InvShiftRows


def MixColumns(st: np.ndarray) -> np.ndarray:
    """
    Implements the FIPS 197 MixColums() routine.
    Array st is the state.
    Performs GF(256) matrix muliplication mcem*st, where
    mcem = [ 02  03  01  01 ]
           [ 01  02  03  01 ]
           [ 01  01  02  03 ]
           [ 03  01  01  02 ]
    """
    nst = st.copy()
    for c in range(4):
        nst[0, c] = m2[st[0, c]] ^ m3[st[1, c]] ^ st[2, c] ^ st[3, c]
        nst[1, c] = st[0, c] ^ m2[st[1, c]] ^ m3[st[2, c]] ^ st[3, c]
        nst[2, c] = st[0, c] ^ st[1, c] ^ m2[st[2, c]] ^ m3[st[3, c]]
        nst[3, c] = m3[st[0, c]] ^ st[1, c] ^ st[2, c] ^ m2[st[3, c]]

    return nst
# End MixColumns


def InvMixColumns(st: np.ndarray) -> np.ndarray:
    """
    Implements the FIPS 197 InvMixColums() routine.
    Array st is the state.
    Performs GF(256) matrix muliplication mcdm*st, where
    mcdm = [ 14  11  13  09 ]
           [ 09  14  11  13 ]
           [ 13  09  14  11 ]
           [ 11  13  09  14 ]
    """
    nst = st.copy()
    for c in range(4):
        nst[0, c] = m14[st[0, c]] ^ m11[st[1, c]] ^ m13[st[2, c]] ^ m9[st[3, c]]
        nst[1, c] = m9[st[0, c]] ^ m14[st[1, c]] ^ m11[st[2, c]] ^ m13[st[3, c]]
        nst[2, c] = m13[st[0, c]] ^ m9[st[1, c]] ^ m14[st[2, c]] ^ m11[st[3, c]]
        nst[3, c] = m11[st[0, c]] ^ m13[st[1, c]] ^ m9[st[2, c]] ^ m14[st[3, c]]

    return nst
# End InvMixColumns


def Cipher(st: np.ndarray, w: np.ndarray) -> np.ndarray:
    """
    Encrypts one block with AES
    Calculates number of rounds, nr, by dividing the
    number of rows in the key schedule, w, by 4.
    """
    nr = (np.shape(w)[0])//4 - 1

    # Round 0 whitening
    s = AddRoundKey(st, w, 0)

    # Rounds 1 -> nr-1
    for r in range(1, nr):
        s = SubBytes(s)
        s = ShiftRows(s)
        s = MixColumns(s)
        s = AddRoundKey(s, w, r)

    # Round nr
    s = SubBytes(s)
    s = ShiftRows(s)
    s = AddRoundKey(s, w, nr)

    return s
# End Cipher


def InvCipher(st: np.ndarray, w: np.ndarray) -> np.ndarray:
    """
    Decrypts one block with AES
    See above note on number of rounds.
    """
    nr = (np.shape(w)[0])//4 - 1

    # Round nr
    s = AddRoundKey(st, w, nr)
    s = InvShiftRows(s)
    s = InvSubBytes(s)

    # Rounds nr-1 -> 1
    for r in range(nr-1, 0, -1):
        s = AddRoundKey(s, w, r)
        s = InvMixColumns(s)
        s = InvShiftRows(s)
        s = InvSubBytes(s)

    # Round 0 whitening
    s = AddRoundKey(s, w, 0)

    return s
# End InvCipher


# Generate random IV
def gen_iv() -> np.ndarray:
    """
    Generates a random 16-byte IV.
    """
    iv_bytes = os.urandom(16)
    iv = np.frombuffer(iv_bytes, dtype=np.uint8).reshape(4, 4)
    return iv
# End gen_iv


def get_pad(sz: int) -> int:
    """
    Calculates padding size.
    """
    # Padding so num of bytes is a multiple of 16
    # as per the PKCS padding scheme.
    pd = 0x10 - (sz % 0x10)

    # If the file size is already a multiple of 16,
    # add one block of 0x10 bytes
    if pd == 0:
        pd = 0x10

    return pd
# End get_pad 


def get_passphrase() -> str:
    """
    Prompt for a passphrase.
    """
    pstr = getpass("Enter passphrase: ")
    return pstr
# End get_passphrase 


def derive_keys(passphrase: str, salt: bytes = None, iterations: int = 300000) -> tuple:
    """
    Derive AES encryption key and HMAC key from a passphrase using PBKDF2-HMAC-SHA256.
    Returns (enc_key_array, mac_key_bytes, salt).
    Default PBKDF2 iteration count increased to 300000.
    """
    if salt is None:
        salt = os.urandom(16)
    # Derive 64 bytes: first 32 for AES key, next 32 for HMAC key
    # Derive 64 bytes: first 32 for AES key, next 32 for HMAC key
    km = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, iterations, dklen=64)
    # Convert to mutable bytearrays for zeroization
    enc_key = bytearray(km[:32])
    mac_key = bytearray(km[32:])
    # Wipe intermediate buffer km by reassigning (no direct zero in Python)
    del km
    return enc_key, mac_key, salt
# End derive_keys 


def cbcencr(fname: str, key_sched: np.ndarray, mac_key: bytes, salt: bytes) -> None:
    """
    Encrypts in CBC mode.
    Saves output as fname.enc
    """
    # Get input file size & padding
    fsz = os.path.getsize(fname)
    pad = get_pad(fsz)

    # get a numpy byte array from input file
    with open(fname, 'rb', encoding=None) as inf:
        barr = np.fromfile(inf, dtype=np.uint8)

    # pad the byte array
    pv = np.uint8(pad)
    padding = [pv for x in range(pad)]
    # This is a byte array of the input file
    # plus the padding:
    bpd = np.append(barr, padding)
    del pv, padding, barr
    # Determine total bytes to encrypt
    total_bytes = bpd.size

    # Prepare atomic output file
    outfile = fname + '.enc'
    tmpfile = outfile + '.tmp'
    with open(tmpfile, 'w+b') as of:
        # Write salt and IV
        of.write(salt)
        iv = gen_iv()
        iv_bytes = iv.flatten()
        of.write(iv_bytes.tobytes())
        # Initialize HMAC (encrypt-then-MAC) 
        h = hmac.new(mac_key, digestmod=hashlib.sha256)
        h.update(salt)
        h.update(iv_bytes.tobytes())
        # Encrypt all padded blocks
        i = 0
        while i < total_bytes:
            block = bpd[i:i+16]
            stb = block.reshape(4, 4, order='F')
            stb ^= iv
            stb = Cipher(stb, key_sched)
            iv = stb.copy()
            fst = stb.flatten(order='F')
            of.write(fst.tobytes())
            h.update(fst.tobytes())
            i += 16
        # Append HMAC tag
        of.write(h.digest())
    # End writing, move tmp -> final atomically
    os.replace(tmpfile, outfile)
    # Cleanup
    del bpd, block, stb, fst, iv, h
    gc.collect()
# End cbcencr


## Decrypt in CBC mode with authentication
def cbcdecr(fname: str, key_sched: np.ndarray, mac_key: bytes) -> None:
    """
    Decrypts in CBC mode.
    Saves output as fname.dec
    """
    # Open encrypted file
    with open(fname, 'rb') as inf:
        data = inf.read()

    # File format: salt(16) | iv(16) | ciphertext | tag(32)
    if len(data) < 16 + 16 + 32:
        raise ValueError("Encrypted file is too short or corrupted.")

    salt = data[:16]
    iv_bytes = data[16:32]
    ciphertext = data[32:-32]
    tag = data[-32:]

    # Ensure ciphertext is block-aligned
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length is not a multiple of block size; corrupted file.")

    # Verify HMAC (encrypt-then-MAC)
    h = hmac.new(mac_key, digestmod=hashlib.sha256)
    h.update(salt)
    h.update(iv_bytes)
    h.update(ciphertext)
    if not hmac.compare_digest(h.digest(), tag):
        raise ValueError("HMAC verification failed: wrong passphrase or corrupted file.")

    # Prepare decryption
    iv = np.frombuffer(iv_bytes, dtype=np.uint8).reshape(4, 4)
    # Load ciphertext into writable numpy array
    ct_arr = np.frombuffer(ciphertext, dtype=np.uint8).copy()

    # Prepare atomic output file
    outfile = os.path.splitext(fname)[0] + '.dec'
    tmpfile = outfile + '.tmp'
    with open(tmpfile, 'wb') as of:
        total_blocks = ct_arr.size // 16
        for i in range(total_blocks):
            block = ct_arr[i*16:(i+1)*16]
            stb = block.reshape(4, 4, order='F')
            prev = stb.copy()
            # Decrypt block
            stb = InvCipher(stb, key_sched)
            # CBC combine
            stb ^= iv
            iv = prev
            fst = stb.flatten(order='F')
            if i == total_blocks - 1:
                # Remove PKCS padding
                pad = int(fst[-1])
                if pad < 1 or pad > 16:
                    raise ValueError("Invalid padding encountered.")
                of.write(fst[:-pad].tobytes())
            else:
                of.write(fst.tobytes())
    # End writing, move tmp -> final atomically
    os.replace(tmpfile, outfile)
# End cbcdecr


def get_args() -> tuple:
    """
    Handle args, return args tuple
    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', help='Encrypt <filename>',
                       action='store_true')
    group.add_argument('-d', '--decrypt', help='Decrypt <filename>',
                       action='store_true')
    parser.add_argument('filename', type=str,
                        help='Filename to encrypt or decrypt (no directories)')
    args = parser.parse_args()

    # Disallow directory components in filename to avoid traversal
    if os.path.basename(args.filename) != args.filename:
        parser.error("Filenames must not contain directory components")

    if args.encrypt:
        return (True, args.filename, '')

    # decrypt mode
    root, ext = os.path.splitext(args.filename)
    if ext != '.enc':
        parser.error("Decrypt: filename must have .enc extension")
    return (False, args.filename, root)
# End get_args



def main():
    """
    Our main()
    """
    # Get and set arguments
    do_encr,file,fsplt = get_args()

    # Handle invalid arguments
    if do_encr is None:
        return
    # Prompt for passphrase
    passphrase = get_passphrase()

    if do_encr is True:
        # Derive keys for encryption
        enc_key_bytes, mac_key, salt = derive_keys(passphrase)
        key_schedule = KeyExpansion(enc_key_bytes)
        print('We will now encrypt', file, 'to '+file+'.enc')
        cbcencr(file, key_schedule, mac_key, salt)
    elif do_encr is False:
        print('We will now decrypt', file, 'to '+fsplt+'.dec')
        # Read salt from encrypted file and derive keys
        with open(file, 'rb') as inf:
            salt = inf.read(16)
        enc_key_bytes, mac_key, _ = derive_keys(passphrase, salt)
        key_schedule = KeyExpansion(enc_key_bytes)
        cbcdecr(file, key_schedule, mac_key)

    # Cleanup: zero-out and delete sensitive data
    # Zero-out key schedule
    try:
        for i in range(len(key_schedule)):
            for j in range(len(key_schedule[i])):
                key_schedule[i][j] = 0
    except Exception:
        pass
    # Zero-out encryption key bytes
    try:
        if isinstance(enc_key_bytes, (bytearray, bytes, np.ndarray)):
            # numpy array
            enc_key_bytes[:] = type(enc_key_bytes)(len(enc_key_bytes))
    except Exception:
        pass
    # Zero-out MAC key
    try:
        if isinstance(mac_key, (bytearray, bytes)):
            mk = bytearray(mac_key)
            for i in range(len(mk)):
                mk[i] = 0
    except Exception:
        pass
    # Delete sensitive variables
    del passphrase, enc_key_bytes, mac_key, salt, key_schedule
# End main


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
