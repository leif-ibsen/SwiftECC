# ``SwiftECC/RP``

An elliptic curve reduction polynomial

## Overview

RP instances contain reduction polynomials like

* x^m + x^k3 + x^k2 + x^k1 + 1 where m > k3 > k2 > k1 > 0
* x^m + x^k1 + 1 where m > k1 > 0

## Topics

### Properties

- ``m``
- ``k3``
- ``k2``
- ``k1``
- ``p``
- ``description``

### Constructors

- ``init(_:_:_:_:)``
- ``init(_:_:)``

### Equality

- ``==(_:_:)``

