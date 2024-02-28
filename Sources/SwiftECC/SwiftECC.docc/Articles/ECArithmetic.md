# Elliptic Curve Arithmetic

SwiftECC implements the common elliptic curve arithmetic operations

## 

* Point doubling
* Point addition
* Point subtraction
* Point negation
* Point multiplication
* Is Point on curve?

It is also possible to encode curve points in either compressed- or uncompressed format,
as well as to do the reverse decoding.
This is done using the `Domain` methods ``SwiftECC/Domain/encodePoint(_:_:)`` and ``SwiftECC/Domain/decodePoint(_:)``.

