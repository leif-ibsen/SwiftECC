# ``SwiftECC``

## Overview

SwiftECC provides elliptic curve cryptography in Swift.
This encompasses:

* Creating, loading and storing public and private keys
* Encryption and decryption using the ECIES algorithm based on the AES block cipher and six different block modes
* AEAD (Authenticated Encryption with Associated Data) encryption and decryption using the ECIES algorithm with the ChaCha20/Poly1305 or the AES/GCM cipher
* Signature signing and verifying using the ECDSA algorithm, including the option of deterministic signatures
* Secret key agreement using the Diffie-Hellman key agreement algorithm - ECDH
* Ability to create your own domains
* General elliptic curve arithmetic
> Important:
SwiftECC requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.
>
> SwiftECC uses Apple’s CryptoKit framework. Therefore, for macOS the version must be at least 10.15,
for iOS the version must be at least 13, and for watchOS the version must be at least 8.

## Topics

- <doc:Usage>
- <doc:Basics>
- <doc:CreateKeys>
- <doc:LoadKeys>
- <doc:EncryptedKeys>
- <doc:EncryptDecrypt>
- <doc:AEADEncryptDecrypt>
- <doc:SignVerify>
- <doc:KeyAgrement>
- <doc:CreateDomain>
- <doc:ECArithmetic>
- <doc:Performance>
- <doc:Dependencies>
- <doc:References>
- <doc:Acknowledgement>
