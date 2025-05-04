# HMAC Overview

HMAC (Hash-based Message Authentication Code) in this scheme serves to give you tamper-proof integrity and authentication on top of the confidentiality provided by AES:

- **Integrity**: By MAC’ing the salt, IV and every byte of ciphertext, you can detect any bit-flips or modifications to the encrypted file.
- **Authentication**: Only somebody who derives the correct HMAC key (i.e. knows the right passphrase) can produce a valid tag, so you’ll immediately know if you used the wrong passphrase or someone swapped in a forgery.
- **Encrypt-then-MAC**: This construction is provably secure against chosen-ciphertext attacks in the standard model. You encrypt first, then compute the HMAC over the resulting data, and reject decryption unless the tag matches.

Without the HMAC step you’d risk subtle malleability or padding-oracle attacks and you wouldn’t be able to tell whether the ciphertext you’re about to decrypt has been corrupted or maliciously altered.

## Changes

### In `cbcencr()`

- Fixed the loop condition by setting `total_bytes = bpd.size`, so every padded block actually gets encrypted and fed into the HMAC.
- After writing `salt | IV | ciphertext`, we now append `h.digest()` (the 32-byte tag).

### In `cbcdecr()`

- Switched to reading the file as `salt(16) | IV(16) | ciphertext | tag(32)`.
- Immediately verify the tag with `hmac.compare_digest`; if it fails, decryption is aborted.
- Only if the HMAC checks out do we proceed to decrypt the blocks and strip PKCS#7 padding.

### In `main()`

- For decryption we first read the salt off-disk and re-derive the exact same AES+HMAC keys before calling `cbcdecr()`.

Together, these changes ensure we get full integrity/authentication protection (and the encryption loop no longer skips blocks).
