# ``SwiftECC``

Elliptic Curve Cryptography

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

### Basics

The basic concept in SwiftECC is the Elliptic Curve Domain, represented by the ``SwiftECC/Domain`` class.
Please, refer section 3.1 in [SEC 1] that describes the domain concept in detail.

There are 18 predefined NIST domains and 14 predefined Brainpool domains in SwiftECC,
and it is possible to create your own characteristic 2, and odd prime characteristic domains.

You can get a predefined domain either from its curve, like
```swift
let domain = Domain.instance(curve: .EC521r1)
```

or from its OID, like

```swift
let domain = try Domain.instance(oid: EC521r1.oid)
```

### Usage

To use SwiftECC, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftECC", from: "5.4.0"),
]
```

SwiftECC itself depends on the ASN1, BigInt and Digest packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.6.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.19.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.8.0"),
],
```

> Important:
SwiftECC requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.
>
> SwiftECC uses the CryptoKit framework. Therefore, for macOS the version must be at least 10.15,
for iOS the version must be at least 13, and for watchOS the version must be at least 8.

## Topics

### Classes

- ``SwiftECC/Domain``
- ``SwiftECC/ECPrivateKey``
- ``SwiftECC/ECPublicKey``
- ``SwiftECC/ECSignature``

### Structures

- ``SwiftECC/Point``
- ``SwiftECC/RP``

### Type Aliases

- ``SwiftECC/Byte``
- ``SwiftECC/Bytes``

### Enumerations

- ``SwiftECC/ECCurve``
- ``SwiftECC/AESCipher``
- ``SwiftECC/BlockMode``
- ``SwiftECC/ECException``

### Articles

- <doc:KeyManagement>
- <doc:EncryptedKeys>
- <doc:EncryptDecrypt>
- <doc:AEADEncryptDecrypt>
- <doc:SignVerify>
- <doc:KeyAgrement>
- <doc:CreateDomain>
- <doc:ECArithmetic>
- <doc:Performance>
- <doc:References>
