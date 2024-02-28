# AEAD Encrypt and Decrypt

Authenticated Encryption with Associated Data

## 

Authenticated Encryption with Associated Data (AEAD) is implemented with the ChaCha20 / Poly1305 algorithm and the AES / GCM algorithm.
Both implementations use the CryptoKit framework, that takes advantage of hardware support for the AES and GCM algorithms.

#### Example

```swift
import SwiftECC

let plainText = "Hi, there!"
let aaData = "This is the additional authenticated data"

let (pub, priv) = Domain.instance(curve: .EC256k1).makeKeyPair()

let cipherText1 = pub.encryptChaCha(msg: Bytes(plainText.utf8), aad: Bytes(aaData.utf8))
let cipherText2 = pub.encryptAESGCM(msg: Bytes(plainText.utf8), cipher: .AES128, aad: Bytes(aaData.utf8))

do {
  let text1 = try priv.decryptChaCha(msg: cipherText1, aad: Bytes(aaData.utf8))
  print(String(bytes: text1, encoding: .utf8)!)

  let text2 = try priv.decryptAESGCM(msg: cipherText2, cipher: .AES128, aad: Bytes(aaData.utf8))
  print(String(bytes: text2, encoding: .utf8)!)
} catch {
  print("Exception: \(error)")
}
```

giving:

```swift
Hi, there!
Hi, there!
```

The encryption and decryption speed for domain EC256k1 (the bitcoin domain) measured on an iMac 2021,
Apple M1 chip is shown below - units are Megabytes per second.

| Algorithm         | Encrypt        | Decrypt        |
|------------------:|---------------:|---------------:|
| ChaCha20/Poly1305 | 500 MByte/Sec  | 425 MByte/Sec  |
| AES-128/GCM       | 2000 MByte/Sec | 1200 MByte/Sec |


#### Key Derivation

SwiftECC uses the X9.63 Key Derivation Function to derive block cipher keying materiel. Please refer [SEC 1] section 3.6.  
Four cases are considered:

* **ChaCha20/Poly1305**

    KDF generates 44 bytes.  
    Encryption/decryption key = bytes 0 ..< 32  
    Nonce = bytes 32 ..< 44  

* **AES-128/GCM**

    KDF generates 28 bytes.  
    AES encryption/decryption key = bytes 0 ..< 16  
    Nonce = bytes 16 ..< 28  

* **AES-192/GCM**

    KDF generates 36 bytes.  
    AES encryption/decryption key = bytes 0 ..< 24  
    Nonce = bytes 24 ..< 36  

* **AES-256/GCM**

    KDF generates 44 bytes.  
    AES encryption/decryption key = bytes 0 ..< 32  
    Nonce = bytes 32 ..< 44  
