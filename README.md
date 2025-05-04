![alt text](python-icon.png)
# tiAES-Python
tiAES: AES for the TI nSpire CX II

__ABOUT__

tiAES software was developed as an educational tool for the purposes of demonstrating and teaching the basic principles of AES cryptography. It is a simple, straight forward implementation of AES using CBC mode (Cipher Block Chaining) with a random IV (Initialization Vector). It also employes HMAC verification and password salting.

tiAES is free and open source software released under the 2-clause BSD license. The purpose of this licensing is to provide attribution to the author(s), while giving the code to the world as a gift. I hope you enjoy it!

It is meant to be run on any system with python 3.x and the NumPy library installed. It will eventually be able to run on the TI nSpire CX II once the dependency of Numpy is removed. It's not quite there yet, and anyone interested is encouraged to hack away at it.


__USAGE__

Download the files tiAES.py and pyaes_tables.py and put them in the same directory. Other than the standard Python libraries, you will need NumPy installed:

    $ pip3 install numpy
or

    $ pip3 install -r requrirements.txt

Run:

    $ ./tiAES.py [-h|--help]

for options.

To encrypt a file:

    $ ./tiAES.py -e <filename>

which will write a file called filename.enc.

The decrypt will look for the file extension '.enc'. To decrypt:

    $ ./tiAES.py -d <filename>.enc

which will write the file filename.dec.  


__HMAC Overview__

HMAC (Hash-based Message Authentication Code) in this scheme serves to give you tamper-proof integrity and authentication on top of the confidentiality provided by AES:

- **Integrity**: By MAC’ing the salt, IV and every byte of ciphertext, you can detect any bit-flips or modifications to the encrypted file.
- **Authentication**: Only somebody who derives the correct HMAC key (i.e. knows the right passphrase) can produce a valid tag, so you’ll immediately know if you used the wrong passphrase or someone swapped in a forgery.
- **Encrypt-then-MAC**: This construction is provably secure against chosen-ciphertext attacks in the standard model. You encrypt first, then compute the HMAC over the resulting data, and reject decryption unless the tag matches.

Without the HMAC step you’d risk subtle malleability or padding-oracle attacks and you wouldn’t be able to tell whether the ciphertext you’re about to decrypt has been corrupted or maliciously altered.

__Changes April/May 2025:__  
  
In `cbcencr()`
  
- Fixed the loop condition by setting `total_bytes = bpd.size`, so every padded block actually gets encrypted and fed into the HMAC.
- After writing `salt | IV | ciphertext`, we now append `h.digest()` (the 32-byte tag).  
  
In `cbcdecr()`
  
- Switched to reading the file as `salt(16) | IV(16) | ciphertext | tag(32)`.
- Immediately verify the tag with `hmac.compare_digest`; if it fails, decryption is aborted.
- Only if the HMAC checks out do we proceed to decrypt the blocks and strip PKCS#7 padding.  
  
In `main()`
  
- For decryption we first read the salt off-disk and re-derive the exact same AES+HMAC keys before calling `cbcdecr()`.

Together, these changes ensure we get full integrity/authentication protection (and the encryption loop no longer skips blocks).
