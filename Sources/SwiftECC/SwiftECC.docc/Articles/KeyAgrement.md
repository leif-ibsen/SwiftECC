# Secret Key Agreement

## 

Given your own private key and another party's public key, you can generate a byte array that can be used as a symmetric encryption key.

The other party can generate the same byte array by using his own private key and your public key.

SwiftECC supports three mechanisms:

* The basic Diffie-Hellman primitive
* The X9.63 version specified in [SEC 1] section 3.6.1
* The HKDF version specified in [RFC 5869]

### Basic Diffie-Hellman Example
```swift
import SwiftECC

do {
  let domain = Domain.instance(curve: .EC256r1)

  // Party A's keys
  let (pubA, privA) = domain.makeKeyPair()

  // Party B's keys
  let (pubB, privB) = domain.makeKeyPair()

  let secretA = try privA.sharedSecret(pubKey: pubB)
  let secretB = try privB.sharedSecret(pubKey: pubA)
  print(secretA)
  print(secretB)
} catch {
  print("Exception: \(error)")
}
```
giving (for example):
```swift
[44, 218, 188, 109, 139, 24, 227, 22, 116, 197, 147, 194, 138, 107, 105, 11, 236, 67, 236, 110, 42, 26, 250, 151, 111, 236, 60, 98, 210, 121, 243, 44]
[44, 218, 188, 109, 139, 24, 227, 22, 116, 197, 147, 194, 138, 107, 105, 11, 236, 67, 236, 110, 42, 26, 250, 151, 111, 236, 60, 98, 210, 121, 243, 44]
```
### X9.63 Example
```swift
import SwiftECC

do {
  let domain = Domain.instance(curve: .EC256r1)

  // Party A's keys
  let (pubA, privA) = domain.makeKeyPair()

  // Party B's keys
  let (pubB, privB) = domain.makeKeyPair()

  let info: Bytes = [1, 2, 3]
  let secretA = try privA.x963KeyAgreement(pubKey: pubB, length: 16, md: .SHA2_256, sharedInfo: info)
  let secretB = try privB.x963KeyAgreement(pubKey: pubA, length: 16, md: .SHA2_256, sharedInfo: info)
  print(secretA)
  print(secretB)
} catch {
  print("Exception: \(error)")
}
```
giving (for example):
```swift
[92, 161, 137, 44, 47, 30, 6, 26, 43, 183, 199, 130, 19, 254, 232, 106]
[92, 161, 137, 44, 47, 30, 6, 26, 43, 183, 199, 130, 19, 254, 232, 106]
```
For the key agreement to work, the two parties must agree on which domain, which message digest and which shared information (possibly none) to use.
### HKDF Example
```swift
import SwiftECC

do {
  let domain = Domain.instance(curve: .EC256r1)

  // Party A's keys
  let (pubA, privA) = domain.makeKeyPair()

  // Party B's keys
  let (pubB, privB) = domain.makeKeyPair()

  let info: Bytes = [1, 2, 3]
  let salt: Bytes = [4, 5, 6]
  let secretA = try privA.hkdfKeyAgreement(pubKey: pubB, length: 16, md: .SHA2_256, sharedInfo: info, salt: salt)
  let secretB = try privB.hkdfKeyAgreement(pubKey: pubA, length: 16, md: .SHA2_256, sharedInfo: info, salt: salt)
  print(secretA)
  print(secretB)
} catch {
  print("Exception: \(error)")
}
```
giving (for example):
```swift
[202, 36, 31, 96, 207, 220, 135, 77, 130, 41, 214, 139, 214, 30, 106, 180]
[202, 36, 31, 96, 207, 220, 135, 77, 130, 41, 214, 139, 214, 30, 106, 180]
```
For the key agreement to work, the two parties must agree on which domain, which message digest,
which shared information (possibly none) and which salt (possibly none) to use.

### CryptoKit Compatibility
SwiftECC key agreement is compatible with Apple CryptoKit key agreement
in that the EC256r1, EC384r1 and EC521r1 domains correspond to CryptoKit's P256, P384 and P521 curves,
and the SHA2_256, SHA2_384 and SHA2_512 message digests correspond to CryptoKit's SHA256, SHA384 and SHA512 message digests.

* The `sharedSecret` method corresponds to the CryptoKit method `sharedSecretFromKeyAgreement`
* The `x963KeyAgreement` method corresponds to the CryptoKit method `x963DerivedSymmetricKey`
* The `hkdfKeyAgreement` method corresponds to the CryptoKit method `hkdfDerivedSymmetricKey`

To convert CryptoKit keys - say `ckPubKey` and `ckPrivKey` - to the corresponding SwiftECC keys:
```swift
let eccPubKey = try ECPublicKey(pem: ckPubKey.pemRepresentation)
let eccPrivKey = try ECPrivateKey(pem: ckPrivKey.pemRepresentation)
```
To convert SwiftECC keys - say `eccPubKey` and `eccPrivKey` - to the corresponding CryptoKit keys:
```swift
let ckPubKey = try P256.KeyAgreement.PublicKey(pemRepresentation: eccPubKey.pem)
let ckPrivKey = try P256.KeyAgreement.PrivateKey(pemRepresentation: eccPrivKey.pem)
```
