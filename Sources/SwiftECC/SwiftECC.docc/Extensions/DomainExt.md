# ``SwiftECC/Domain``

## Overview
A Domain instance contains an elliptic curve domain - either with characteristic 2 or characteristic an odd prime.

Please refer [SEC 1] section 3.1.

## Topics

### Constants

- ``OID_2``
- ``OID_P``
- ``OID_EC``

### Properties

- ``name``
- ``p``
- ``a``
- ``b``
- ``g``
- ``order``
- ``cofactor``
- ``oid``
- ``characteristic2``
- ``asn1``
- ``pem``
- ``description``

### Domain Creation

- ``instance(curve:)``
- ``instance(oid:)``
- ``instance(pem:)``
- ``instance(name:p:a:b:gx:gy:order:cofactor:oid:)``
- ``instance(name:rp:a:b:gx:gy:order:cofactor:oid:)``

### Arithmetic

- ``doublePoint(_:)``
- ``addPoints(_:_:)``
- ``subtractPoints(_:_:)``
- ``negatePoint(_:)``
- ``multiplyPoint(_:_:)``
- ``contains(_:)``

### Methods

- ``makeKeyPair()``
- ``encodePoint(_:_:)``
- ``decodePoint(_:)``
- ``asn1EncodePoint(_:_:)``
- ``asn1DecodePoint(_:)-5xuks``
- ``asn1DecodePoint(_:)-5k4zf``
- ``asn1Explicit()``
- ``==(_:_:)``
