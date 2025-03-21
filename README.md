![alt text](python-icon.png)
# tiAES-Python
tiAES: AES for the TI nSpire CX II  

__ABOUT__  

tiAES software was developed as an educational tool for the purposes of demonstrating and teaching the basic principles of AES cryptography. It is a simple, straight forward implementation of AES using CBC mode (Cipher Block Chaining) with a random IV (Initialization Vector).  

tiAES is free and open source software released under the 2-clause BSD license. The purpose of this licensing is to provide attribution to the author(s), while giving the code to the world as a gift. I hope you enjoy it!  

It is meant to be run on any system with python 3.x and the NumPy library installed. It will eventually be able to run on the TI nSpire CX II with the Ulab library providing numpy classes and methods. It's not quite there yet, and anyone interested is encouraged to hack away at it.  


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

__STATUS__  

This version is fully functional and produces FIPS 197 compliant output. It uses CBC mode  block-chaining. The initialization vector is randomly chosen by first obtaining a 64Byte/512bit random sequence. This random number is then digested with SHA256 resulting in 32bytes. The first 16bytes are used as the IV.  

The purpose of hashing the 64Bytes of randomness is that software produced randomness is 'pseudorandom' and contains mathematical structure that can possibly tell an attacker something predictable about your generator. Hashing the random sequence 'smoothes out' any structure thereby increasing security. We say that the hash has a higher entropy than the pseudorandom number sequence.  

The key is an SHA256 hash of the passphrase providing a 32byte/256bit key. Not only does this provide us with a fixed-length key--32Bytes/256bits--but it also, again, smoothes out the (very) low-entropy passphrase and gives us a realatively high-entropy key. The increased entropy helps improve the security of the encryption key.  

The KeyExpanson and Cypher routines produce FIPS-197 compliant output as verified with a block-by-block comparison to the "APPENDIX A - KEY EXPANSION EXAMPLES", "APPENDIX B – CIPHER EXAMPLE", and "Appendix C – Example Vectors" in the FIPS 197 documentation: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf  

While it works, we cannot make any claims as to how secure the coding is nor is it very fast on large files. Do not use this code for anything other that personal education and enjoyment.  

__Notes on reading and writing blocks__  

We use numpy.fromfile() to read bytes into a byte array: We will read blocks of 16 bytes into a vector, then use reshape(4,4,order='F') to create a new state block, which then is encr|decr, flattened, then written to outfile. Order 'F' loads the bytes into a block by column.  

We track the offset i with outfile.tell() to load 16 bytes from the byte array  
 for each block:  
 
     sv = bpd[i:i+16]
     st = sv.reshape(4, 4, order='F')  
(where bpd is the padded byte array from the input file).  
``` 
                                                                          [01 05 09 13]  
bpd[i:i+16]->[01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16].reshape()->[02 06 10 14]  
                                                                          [03 07 11 15]  
                                                                          [04 08 12 16]
```

To write out state blocks, we call sv = st.flatten(order='F') on each block, then write the bytes from each flattened block sv in to the open outfile, tracking the byte position with outfile.tell().  
``` 
[01 05 09 13]  
[02 06 10 14].flatten()->[01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16]-> of.write()  
[03 07 11 15]   
[04 08 12 16]
```

__Notes on block padding__  

    padding_bytes = block_size - (message_length % block_size)  
    where block_size = 16  
    
Padding bytes are appended to the file's byte array _before_ encryption. The value of the added bytes = padding_bytes.  

After decryption, the last byte is read and assigned to padding_bytes, which is the number of bytes to be truncated.  
https://www.ibm.com/docs/en/zos/3.1.0?topic=rules-pkcs-padding-method  

__Notes on using the ulab library in place of numpy in MicroPython__  

Use of ulab in place of numpy in MicroPython supplies a good amount of numpy functionality however, two important methods are currently missing: fromfile() and append(), both of which are used here. This matters to the author in as much as it was hoped that this code could run on the TI nSpire cx calculators using ulab.  

If/when the ulab library supports these methods, it should be a 'drop in' replacement for numpy using:  
```python
from ulab import numpy as np  
```
In the mean time, the existing code can be reworked to get around the use of fromfile() and append().    

__TUTORIAL__  

I have outlined a tutorial which will eventually end up here.
