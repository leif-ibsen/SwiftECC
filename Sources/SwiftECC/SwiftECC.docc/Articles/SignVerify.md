# Sign and Verify

Signing data and verifying signatures

## 

Signing data and verifying signatures is performed using the ECDSA algorithm. It is possible to generate
deterministic signatures as specified in [RFC 6979] by setting the `deterministic` parameter to `true` in the sign operation.

The message digest used in the process is determined from the domain field size as follows:

* field size <= 224: SHA2-224
* 224 < field size <= 256: SHA2-256
* 256 < field size <= 384: SHA2-384
* 384 < field size: SHA2-512

#### Example

```swift
import SwiftECC

// Get a predefined domain - for example brainpool BP160r1

let domain = Domain.instance(curve: .BP160r1)

// Create your own keys

let (pubKey, privKey) = domain.makeKeyPair()

// See how they look

print(pubKey.asn1)
print(privKey.asn1)

// Store them in PEM format for future use

let pubPEM = pubKey.pem
let privPEM = privKey.pem

let message = "The quick brown fox jumps over the lazy dog!".data(using: .utf8)!

let sig = privKey.sign(msg: message)
let ok = pubKey.verify(signature: sig, msg: message)
print("Signature is", ok ? "good" : "wrong")
```

giving (for example):

```swift
Sequence (2):
  Sequence (2):
    Object Identifier: 1.2.840.10045.2.1
    Object Identifier: 1.3.36.3.3.2.8.1.1.1
  Bit String (328): 00000100 00000011 00000111 00110011 01010100 00000001 10111100 01101111 10100001 01001000 11101000 01111100 10001111 00000110 00010010 11100111 11111010 10010001 00100100 01001000 11000110 01110001 00110100 01001000 10011110 01011110 11000000 10010001 01000110 01011010 01001110 01110000 00011011 01010111 10101011 01101010 00011011 01101100 01100100 01000100 01111101

Sequence (4):
  Integer: 1
  Octet String (20): 32 96 e0 c4 d7 f5 cb 03 0c 95 63 b1 a2 c1 2f 64 4c dc d6 4c
  [0]:
    Object Identifier: 1.3.36.3.3.2.8.1.1.1
  [1]:
    Bit String (328): 00000100 00000011 00000111 00110011 01010100 00000001 10111100 01101111 10100001 01001000 11101000 01111100 10001111 00000110 00010010 11100111 11111010 10010001 00100100 01001000 11000110 01110001 00110100 01001000 10011110 01011110 11000000 10010001 01000110 01011010 01001110 01110000 00011011 01010111 10101011 01101010 00011011 01101100 01100100 01000100 01111101

Signature is good
```

#### BlueECC Compatibility

Signatures created by SwiftECC in the EC256r1, EC384r1 and EC521r1 domains can be verified by IBM's BlueECC product
using curve prime256v1, secp384r1 and secp521r1, respectively.

Likewise, signatures created by BlueECC with one of the curves
prime256v1, secp384r1 and secp521r1 can be verified by SwiftECC using domains EC256r1, EC384r1 and EC521r1, respectively.

#### CryptoKit Compatibility

Signatures created by SwiftECC in the EC256r1, EC384r1 and EC521r1 domains can be verified by CryptoKit
using curve P256, P384 and P521, respectively.

Likewise, signatures created by CryptoKit with one of the curves
P256, P384 and P521 can be verified by SwiftECC using domains EC256r1, EC384r1 and EC521r1, respectively.
