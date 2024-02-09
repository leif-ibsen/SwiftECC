# Basics

## 

The basic concept in SwiftECC is the Elliptic Curve Domain, represented by the ``SwiftECC/Domain`` class.
Please, refer section 3.1 in [SEC 1] that describes the domain concept in detail.

There are 18 predefined NIST domains and 14 predefined Brainpool domains in SwiftECC,
and it is possible to create your own characteristic 2, and odd prime characteristic domains.

You need a ``SwiftECC/ECPublicKey`` in order to encrypt a message or verify a signature,
and you need a ``SwiftECC/ECPrivateKey`` in order to decrypt a message or sign a message.

Given a domain, you can generate public / private key pairs or you can load them from the PEM- or DER encoding of existing keys.

### Getting a predefined domain

You can get a predefined domain either from its curve, like
```swift
let domain = Domain.instance(curve: .EC521r1)
```
or from its OID, like
```swift
let domain = try Domain.instance(oid: EC521r1.oid)
```

