# Encrypt and Decrypt

## 

Encryption and decryption is done using the ECIES algorithm based on the AES block cipher using one of
AES-128, AES-192 or AES-256 ciphers, depending on your choice.

The following cipher block modes are supported:

* **GCM** - Galois Counter mode. This is the default mode
* **ECB** - Electronic Codebook mode with PKCS#7 padding
* **CBC** - Cipher Block Chaining mode with PKCS#7 padding
* **CFB** - Cipher Feedback mode
* **CTR** - Counter mode
* **OFB** - Output Feedback mode

The encryption and decryption speed for domain EC256k1 (the bitcoin domain) measured on an iMac 2021, Apple M1 chip
using AES-128 is shown below - units are Megabytes per second.

| Block Mode | Encrypt      | Decrypt      |
|:-----------|-------------:|-------------:|
| GCM        | 53 MByte/Sec | 53 MByte/Sec |
| ECB        | 30 MByte/Sec | 30 MByte/Sec |
| CBC        | 24 MByte/Sec | 25 MByte/Sec |
| CFB        | 23 MByte/Sec | 23 MByte/Sec |
| CTR        | 30 MByte/Sec | 30 MByte/Sec |
| OFB        | 29 MByte/Sec | 29 MByte/Sec |

Unless compatibility with IBM's BlueECC product is necessary, encryption / decryption using GCM block mode is deprecated.
Use the encryptAESGCM / decryptAESGCM methods instead. Their performance is many times better.

### Example
```swift
import SwiftECC

// You need a public key to encrypt a message and the corresponding private key to decrypt it,
// for example from the EC163k1 domain

let pemPublic163k1 =
"""
-----BEGIN PUBLIC KEY-----
MEAwEAYHKoZIzj0CAQYFK4EEAAEDLAAEA6txn7CCae0d9AiGj3Rk5m9XflTCB81oe1fKZi4F4oip
SF2u79k8TD5J
-----END PUBLIC KEY-----
"""

let pemPrivate163k1 =
"""
-----BEGIN EC PRIVATE KEY-----
MFICAQEEFNfflqz2oOd9WpxuMZ9wJTFO1sjgoAcGBSuBBAABoS4DLAAEA6txn7CCae0d9AiGj3Rk
5m9XflTCB81oe1fKZi4F4oipSF2u79k8TD5J
-----END EC PRIVATE KEY-----
"""

let text = "The quick brown fox jumps over the lazy dog!"

do {
  let pubKey = try ECPublicKey(pem: pemPublic163k1)
  let privKey = try ECPrivateKey(pem: pemPrivate163k1)
  let encryptedData = pubKey.encrypt(msg: text.data(using: .utf8)!, cipher: .AES128)
  let decryptedData = try privKey.decrypt(msg: encryptedData, cipher: .AES128)
  print(String(data: decryptedData, encoding: .utf8)!)
} catch {
  print("\(error)")
}
```
giving:
```swift
The quick brown fox jumps over the lazy dog!
```

### Key Derivation
SwiftECC uses the X9.63 Key Derivation Function to derive block cipher keying materiel. Please refer [SEC 1] section 3.6.
Six cases are considered:

#### AES-128/GCM block mode
KDF generates 32 bytes.

AES encryption/decryption key = bytes 0 ..< 16

Nonce = bytes 16 ..< 32

#### AES-192/GCM block mode
KDF generates 40 bytes.

AES encryption/decryption key = bytes 0 ..< 24

Nonce = bytes 24 ..< 40

#### AES-256/GCM block mode
KDF generates 48 bytes.

AES encryption/decryption key = bytes 0 ..< 32

Nonce = bytes 32 ..< 48

#### AES-128/Non-GCM block mode
KDF generates 48 bytes.

AES encryption/decryption key = bytes 0 ..< 16

HMAC key = bytes 16 ..< 48

#### AES-192/Non-GCM block mode
KDF generates 56 bytes.

AES encryption/decryption key = bytes 0 ..< 24

HMAC key = bytes 24 ..< 56

#### AES-256/Non-GCM block mode
KDF generates 64 bytes.

AES encryption/decryption key = bytes 0 ..< 32

HMAC key = bytes 32 ..< 64

### 
The AES key and HMAC key can be retrieved with the `ECPrivateKey` method `getKeyAndMac`.

For block modes CBC, CFB, CTR, and OFB the initialization vector (IV) is 16 zero bytes.

### BlueECC Compatibility
Data encrypted by SwiftECC in the EC256r1 domain with AES128/GCM, in the EC384r1 domain with AES256/GCM
and in the EC521r1 domain with AES256/GCM can be decrypted with IBM's BlueECC product using curve prime256v1,
secp384r1, and secp521r1, respectively.

Likewise, data encrypted by BlueECC with curve prime256v1, secp384r1 and secp521,
can be decrypted by SwiftECC using EC256r1 with AES128/GCM, EC384r1 with AES256/GCM and EC521r1 with AES256/GCM, respectively.
