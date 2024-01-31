# ``SwiftECC/ECPublicKey``

## Overview

Use public keys to:

* Encrypt a plain text
* Verify a signature
* Be part of a key agreement

## Topics

### Properties

- ``domain``
- ``w``
- ``asn1``
- ``der``
- ``pem``
- ``description``

### Constructors

- ``init(domain:w:)``
- ``init(der:)``
- ``init(pem:)``
- ``init(privateKey:)``

### Encryption

- ``encrypt(msg:cipher:mode:)-4dil1``
- ``encrypt(msg:cipher:mode:)-4xz0p``
- ``encryptChaCha(msg:aad:)-535bd``
- ``encryptChaCha(msg:aad:)-7qtyj``
- ``encryptAESGCM(msg:cipher:aad:)-7ow39``
- ``encryptAESGCM(msg:cipher:aad:)-7w8j9``

### Verification

- ``verify(signature:msg:bw:)-61z0``
- ``verify(signature:msg:bw:)-41jz7``
