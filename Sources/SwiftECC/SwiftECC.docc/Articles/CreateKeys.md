# Create new Keys

## 
For a given domain it is possible to generate a public/private key pair.

### Example
```swift
let domain = Domain.instance(curve: .EC384r1)
let (pubKey, privKey) = domain.generateKeyPair()
```
The private key is simply a random positive integer less than the domain order.
The public key is the domain generator point multiplied by the private key.
Given a private key, say `privKey`, you can generate the corresponding public key, like
```swift
let pubKey = ECPublicKey(privateKey: privKey)
```
Given a domain, say `dom` and a curve point, say `pt`, you can generate a public key, like
```swift
let pubKey = try ECPublicKey(domain: dom, w: pt)
```
