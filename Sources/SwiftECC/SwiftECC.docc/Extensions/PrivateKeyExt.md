# ``SwiftECC/ECPrivateKey``

An elliptic curve private key

## Overview 

Use private keys to:

* Decrypt a cipher text
* Sign a message
* Be part of a key agreement

## Topics

### Properties

- ``domain``
- ``s``
- ``asn1``
- ``der``
- ``pem``
- ``derPkcs8``
- ``pemPkcs8``
- ``description``

### Constructors

- ``init(domain:s:)``
- ``init(der:pkcs8:)``
- ``init(pem:)``
- ``init(der:password:)``
- ``init(pem:password:)``

### Decryption

- ``derEncrypted(password:cipher:)``
- ``pemEncrypted(password:cipher:)``
- ``decrypt(msg:cipher:mode:)-9pdnd``
- ``decrypt(msg:cipher:mode:)-9nqsp``
- ``getKeyAndMac(msg:cipher:mode:)-8d85z``
- ``getKeyAndMac(msg:cipher:mode:)-6t51``
- ``decryptChaCha(msg:aad:)-7bguu``
- ``decryptChaCha(msg:aad:)-ttft``
- ``decryptAESGCM(msg:cipher:aad:)-7hhik``
- ``decryptAESGCM(msg:cipher:aad:)-1yypz``

### Signing

- ``sign(msg:deterministic:)-1t1sl``
- ``sign(msg:deterministic:)-24jcb``

### Key Agreement

- ``sharedSecret(pubKey:cofactor:)``
- ``x963KeyAgreement(pubKey:length:kind:sharedInfo:cofactor:)``
- ``hkdfKeyAgreement(pubKey:length:kind:sharedInfo:salt:cofactor:)``
