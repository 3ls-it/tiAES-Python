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
import argparse
from secrets import token_hex
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
    mcdm = [ 14  11  13  9  ]
           [ 9   14  11  13 ]
           [ 13  9   14  11 ]
           [ 11  13  9   14 ]
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
    Generates random IV
    """
    rn = token_hex(64)
    hsh = hashlib.sha256(str.encode(rn)).digest()
    iv = np.zeros(16, dtype=np.uint8)
    # We only need 16 bytes from the hash. We could use
    # MD5 to get only 16, however, it has know vulnerabilities.
    for i, b in enumerate(hsh):
        if i == 16:
            break
        iv[i] = b
    del rn, hsh
    gc.collect()
    iv = iv.reshape(4, 4)
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

# Encrpyt in CBC mode
def cbcencr(fname: str, key: np.ndarray):
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

    # create an outfile name
    outfile = fname + '.enc'

    with open(outfile, 'w+b') as of:
        ## Do CBC mode encr ##
        # We need to iterate through pbd 16 bytes
        # at a time, load them into a 4x4 state block
        # array (stb) encrypt, flatten (fst) then write
        # to outfile each time.
        # Note that we do (state xor IV) _before_ we encrypt.
        # The new state becomes the IV for the next CBC round.

        # Get our random IV
        iv = gen_iv()

        # Write the IV to the first 16 bytes of the outfile
        of.write(bytearray(iv.flatten()))

        # The mark 'i' tracks our position in the padded byte array
        i = 0
        while i < fsz:
            # Get next 16 bytes from bpd
            st = bpd[i:i+16]
            # Reshape into block by column
            stb = st.reshape(4, 4, order='F')
            # xor state and IV
            stb ^= iv
            # Call Cipher()
            stb = Cipher(stb, key)
            # Copy state to new IV
            iv = stb.copy()
            # Flatten state by column
            fst = stb.flatten(order='F')
            # This writes the flattend blocks to file
            of.write(bytearray(fst))
            # Set i
            i = of.tell() - 16
        # End while
    # End with, automatic of.close()

    del bpd, st, stb, iv, fst
    gc.collect()
# End cbcencr


# Decrytp in CBC mode
def cbcdecr(fname: str, key: np.ndarray):
    """
    Decrypts in CBC mode.
    Saves output as fname.dec
    """

    # Strip off .enc extension
    # create an outfile name
    outfile = os.path.splitext(fname)[0] + '.dec'

    # infile size
    fsz = os.path.getsize(fname)

    # get a numpy byte array
    with open(fname, 'rb', encoding=None) as inf:
        barr = np.fromfile(inf, dtype=np.uint8)

    # Split barr[] to get IV and byte array
    splits = np.split(barr, [16, fsz+1])
    iv = splits[0].reshape(4, 4)
    barr = splits[1]
    # Adjust fsz
    fsz = fsz - 16

    # Strip off .enc extension
    # create an outfile name
    outfile = os.path.splitext(fname)[0] + '.dec'

    with open(outfile, 'w+b') as of:
        ## Do CBC mode decr ##
        # We need to iterate through pbd 16 bytes
        # at a time, load them into a 4x4 state block
        # array (stb) decrypt, flatten (fst) then write
        # to outfile each time.
        # Note that we do (state xor IV) _after_ we decrypt.
        # The new state becomes the IV for the next CBC round.

        i = 0
        while i < fsz:
            # Get next 16 bytes from byte array
            st = barr[i:i+16]
            # Reshape into block by column
            stb = st.reshape(4, 4, order='F')
            # Copy state to a temp block
            tb = stb.copy()
            # Call Cipher()
            stb = InvCipher(stb, key)
            # xor state and IV
            stb ^= iv
            # Copy tmp block (old state) to new IV
            iv = tb.copy()
            # Flatten state by column
            fst = stb.flatten(order='F')
            # This writes the flattend blocks to file
            of.write(bytearray(fst))
            # Set i
            i = of.tell()
        # End while
        # Get last byte value = padding bytes
        of.seek(-1, 2)
        pv = int.from_bytes(of.read(1), "little")
        # Seek to cut-off point
        of.seek(-pv, 2)
        # Remove padding
        of.truncate()
    # End with, automatic of.close()
    del fsz, st, stb, tb, iv, fst
    gc.collect()
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


def get_passkey() -> np.ndarray:
    """
    Get passphrase, generate key with sha256
    """
    # Make sure pwd is 16 characters min
    plen = 1
    while plen < 16:
        pstr = getpass()
        plen = len(pstr)

    # The actual key is a hash of the passphrase
    # We're basically enforcing 256bit encryption
    # since the hash is always 32bytes/256bits
    phsh = hashlib.sha256(str.encode(pstr)).digest()
    pwd = np.zeros(32, dtype=np.uint8)
    for i, b in enumerate(phsh):
        pwd[i] = b
    del phsh, pstr, plen
    gc.collect()
    return pwd
# End get_passkey


def main():
    """
    Our main()
    """

    # Get and set arguments
    do_encr,file,fsplt = get_args()

    # Prompt for passphrase, build key schedule
    pw = get_passkey()
    key = KeyExpansion(pw)

    if do_encr is True:
        print('We will now encrypt', file, 'to '+file+'.enc')
        cbcencr(file, key)
    elif do_encr is False:
        print('We will now decrypt', file, 'to '+fsplt+'.dec')
        cbcdecr(file, key)
    del pw, key
    gc.collect()
# End main


if __name__ == '__main__':
    main()
