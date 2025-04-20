#!/usr/bin/env python3
# tiAES.py
# (c) 2024 J. Adams jfa63[at]duck[dot]com
# Released under the 2-clause BSD Licence
# Thanks to jfx2006 for contributions and advice.

"""
 This implementation tries to by fully compliant with the FIPS 197 Advanced Encryption
Standard:
https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
While it works, we cannot make any claims as to how secure the coding is nor is it very
fast on large files. Do not use this code for anything other that personal education and
enjoyment.
"""

import os
import gc
import hashlib
import hmac
import argparse
from getpass import getpass
import numpy as np
from aes_tables import (NB,
                        sbox,
                        sboxinv,
                        m2,
                        m3,
                        m9,
                        m11,
                        m13,
                        m14)
 
# ----------------------------------------------------------------------------
def get_passphrase() -> str:
    """
    Prompt for a passphrase (minimum length: 16 characters).
    """
    plen = 0
    while plen < 16:
        pstr = getpass("Enter passphrase (min 16 chars): ")
        plen = len(pstr)
    return pstr

def derive_keys(passphrase: str, salt: bytes = None, iterations: int = 100000) -> tuple:
    """
    Derive AES encryption key and HMAC key from a passphrase using PBKDF2-HMAC-SHA256.
    Returns (enc_key_array, mac_key_bytes, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    # Derive 64 bytes: first 32 for AES key, next 32 for HMAC key
    km = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, iterations, dklen=64)
    enc_key = np.frombuffer(km[:32], dtype=np.uint8)
    mac_key = km[32:]
    del km
    gc.collect()
    return enc_key, mac_key, salt
# ----------------------------------------------------------------------------


## Functions

def KeyExpansion(key: np.ndarray) -> np.ndarray:
    """
    Implements FIPS 197 KeyExpansion() routine
    Parameters:
    - key: 16-byte (128-bit) input key as a NumPy 1D array
    - key: 24-byte (192-bit) input key as a NumPy 1D array
    - key: 32-byte (256-bit) input key as a NumPy 1D array
    Returns:
    - key_sched: expanded key schedule as a NumPy 2D array of shape:
      (NB*(nr+1))words x 4bytes
    Verified FIPS compliant output 20231220
    """
    # Constants defined in FIPS 197
    nk = len(key)//4
    nr = nk + 6
    wl = NB * (nr + 1)

    # Round key constants as row vectors
    rcons = np.array([
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
        0x1b, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x00, 0x00,
        0xd8, 0x00, 0x00, 0x00
    ], dtype=np.uint8).reshape(-1, 4)

    w = np.zeros((wl, 4), dtype=np.uint8)

    # Copy the original key into the first nk words of w
    w[:nk] = key.reshape(-1, 4)

    # Expand key schedule
    for i in range(nk, wl):
        temp = w[i-1]

        if i % nk == 0:
            temp = np.roll(temp, -1)
            temp = np.array([sbox[val] for val in temp], dtype=np.uint8)
            temp ^= rcons[i//nk - 1]

        elif nk > 6 and i % nk == 4:
            temp = np.array([sbox[val] for val in temp], dtype=np.uint8)

        w[i] = w[i-nk] ^ temp

    del key, temp
    gc.collect()
    return w
# End KeyExpansion


def AddRoundKey(st: np.ndarray, w: np.ndarray, rnd: int) -> np.ndarray:
    """
    Implements the FIPS 197 AddRoundKey() routine.
    Array st is the state.
    Array w is the key schedule.
    Integer rnd is the round.
    AddRoundkey() xors columns of state with rows
    of key material.
    """

    for c in range(4):
        wd = w[((rnd * 4) + c), :]
        st[:, c] ^= wd

    return st
# End AddRoundKey


def SubBytes(st: np.ndarray) -> np.ndarray:
    """
    Implements the FIPS 197 SubBytes() routine.
    Array st is the state.
    Substitues values in state from the sbox.
    """
    for r in range(4):
        for c in range(4):
            st[r, c] = sbox[st[r, c]]

    return st
# End SubBytes


def InvSubBytes(st: np.ndarray) -> np.ndarray:
    """
    Implements the FIPS 197 InvSubBytes() routine.
    Array st is the state.
    Substitues values in state from the inverse sbox.
    """
    for r in range(4):
        for c in range(4):
            st[r, c] = sboxinv[st[r, c]]

    return st
# End InvSubBytes


def ShiftRows(st: np.ndarray) -> np.ndarray:
    """
    Implements the FIPS 197 ShiftRows() routine.
    Array st is the state.
    Shift values left (-) in rows 2, 3 and 4 of st
    by -1, -2 and -3 places, respectively.
    #These calls to numpy.roll() are very expensive.
    st[1, :] = np.roll(st[1, :], -1)
    st[2, :] = np.roll(st[2, :], -2)
    st[3, :] = np.roll(st[3, :], -3)
    The code below is twice as fast.
    """
    nst = np.zeros((4,4), dtype=np.uint8)

    # row 1, no rotation
    nst[0, :] = st[0, :]
    # row 2, 1 rotation
    nst[1, 0] = st[1, 1]
    nst[1, 1] = st[1, 2]
    nst[1, 2] = st[1, 3]
    nst[1, 3] = st[1, 0]
    # row 3, 2 rotations
    nst[2, 0] = st[2, 2]
    nst[2, 1] = st[2, 3]
    nst[2, 2] = st[2, 0]
    nst[2, 3] = st[2, 1]
    #row 4, 3 rotations
    nst[3, 0] = st[3, 3]
    nst[3, 1] = st[3, 0]
    nst[3, 2] = st[3, 1]
    nst[3, 3] = st[3, 2]

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
    gc.collect()
    # Determine total bytes to encrypt
    total_bytes = bpd.size

    # create an outfile name
    outfile = fname + '.enc'
    with open(outfile, 'w+b') as of:
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
    # End with
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

    # Output file name
    outfile = os.path.splitext(fname)[0] + '.dec'
    with open(outfile, 'wb') as of:
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

# End cbcdecr


def get_args() -> tuple:
    """
    Handle args, return args tuple
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--encrypt', help='Encrypt <filename>',
                        action='store_true')
    parser.add_argument('-d', '--decrypt', help='Decrypt <filename>',
                        action='store_true')
    parser.add_argument('filename', type=str,
                        help='Filename to encrypt or decrypt')
    args = parser.parse_args()

    if args.encrypt:
        print('Encrypt', args.filename)
        return (True, args.filename, '')

    if args.decrypt:
        fsplit = os.path.splitext(args.filename)
        if fsplit[1] == '.enc':
            print('Decrypt', args.filename)
        else:
            print('The file does not have the .enc extension.')
            print("We don't know if it was actually encrypted with PyAES.")
            return (None, None, None)
        return  (False, args.filename, fsplit[0])
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

    # Cleanup
    del passphrase, enc_key_bytes, mac_key, salt, key_schedule
    gc.collect()
    gc.collect()
# End main


if __name__ == '__main__':
    main()
