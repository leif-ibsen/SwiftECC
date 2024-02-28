## SwiftECC

SwiftECC provides elliptic curve cryptography in Swift.
This encompasses:

* Creating, loading and storing public and private keys</li>
* Encryption and decryption using the ECIES algorithm based on the AES block cipher and six different block modes
* AEAD (Authenticated Encryption with Associated Data) encryption and decryption using the ECIES algorithm with the ChaCha20/Poly1305 or the AES/GCM cipher
* Signature signing and verifying using the ECDSA algorithm, including the option of deterministic signatures
* Secret key agreement using the Diffie-Hellman key agreement algorithm - ECDH
* Ability to create your own domains
* General elliptic curve arithmetic

SwiftECC requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftECC/documentation/swiftecc

The documentation is also available in the *SwiftECC.doccarchive* file.

