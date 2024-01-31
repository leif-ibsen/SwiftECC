# Encrypted Private Keys

## 
Private keys can be encrypted as described in [PKCS#5] using the PBES2 scheme.

### Example
```swift
let pw = Bytes("MySecret".utf8)
let domain = Domain.instance(curve: .EC384r1)
let (_, priv) = domain.makeKeyPair()
let encryptedKey = priv.pemEncrypted(password: pw, cipher: .AES256)
print(encryptedKey)
```
giving (for example):
```swift
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBHjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI3id2VFlFxXUCAggA
MB0GCWCGSAFlAwQBKgQQlJJQtcZ23p1Q4fXmvpS6hgSB0DBuxL/sCUc/c9NDhrHK
/R2sbtS7rs5a9zUFwcMNV1nVUCK1SSbaCg8/BxHPfqKlAw4RcnsQtN+YD7hz5pxF
YDcYk4mEZo7ODFkRxhKF7vLsUsRZAl2XYGIJflp03+fAWdsiNisjo/4Y/5xxWvCe
OBzfjRpsDT4HjRgcxTtxrzvInzrJkQwyDBAkPMudIshkPOQ1LEoXhi0gVFl9jGN+
eSLv5Wba2chf/kQcw7R4B3iiE5787wE2fWvvh4ek3oSYcLCvO/gkwgUhyA2hk3rn
01k=
-----END ENCRYPTED PRIVATE KEY-----
```
The implied encryption parameters are cipher block mode = CBC, iteration count = 2048 and salt = 8 random bytes.
The password is simply a byte array, any possible interpretation of it as a string is unspecified.
The encrypted private key is compatible with, and is readable by OpenSSL.

Private keys can be created from their PEM encodings in encrypted form.
In the example the encrypted private key was created by OpenSSL using the AES-256 cipher in CBC mode with password `abcd`.

### Example
```swift
let encryptedPem =
"""
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAg7pgGVDlE/xgICCAAw
HQYJYIZIAWUDBAEqBBCFF4KWxWqhOB5Q8dOwdcPkBIGQbuj2TvlhtpMZ3ZhLBBBx
kJfY1l09yNcJNEcvS8RX4/STXZkt5gMBgtY2DvGAKI0wkpbim+kXSjM6/hmNxY5b
jhQapm8l8jbVGkETtYfseZXpvIT5lnBy9KtO8o3OmlRTV3xXu3KeDZakDoimfQ8G
N7SldmFRcz171yMoIQ17ZU95uneZoogsRuMVMVUJXEh7
-----END ENCRYPTED PRIVATE KEY-----
"""
let privKey = try ECPrivateKey(pem: encryptedPem, password: Bytes("abcd".utf8))
print(privKey)
```
giving:
```swift
Sequence (4):
  Integer: 1
  Octet String (32): 1e 4d c5 de 0f 47 66 6b 7e 4c b8 ee e5 0f f9 6c 4a d3 4f 6f 2e 07 f7 fc e7 c8 24 dd 17 18 fd fa
  [0]:
    Object Identifier: 1.2.840.10045.3.1.7
  [1]:
    Bit String (520): 00000100 00101110 10100100 10110110 10001111 11111010 00111111 00000111 01011010 01011101 01110000 01100001 10110000 10101110 01011010 10011100 10001111 00110100 11010000 11111101 10010110 11001110 00101011 10001111 11000001 10101001 11000000 00001101 00011101 11011101 11001011 10101110 10011000 11001011 10000101 01110001 10100010 11100000 01100011 01101010 11110100 11011101 00011000 01011101 10010110 01010101 10110011 00101101 01010000 10100010 00110001 10000100 11011001 00111001 00011000 01100100 10001110 11011111 10011100 00010100 10110101 11011010 00111010 10101100 11111100
```
SwiftECC can read encrypted private key files provided they were encrypted with one of the ciphers AES-128, AES-192 or AES-256 in CBC mode.
