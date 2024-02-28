# ``SwiftECC/Point``

An elliptic curve point

## Overview

For points in a prime characteristic domain, the x-coordinate and y-coordinate are non-negative integers.

For points in a characteristic 2 domain, the x-coordinate and y-coordinate are binary polynomials
where the coefficients (0 or 1) are the bits of the x and y values.

## Topics

### Constants

- ``INFINITY-swift.type.property``

### Properties

- ``x``
- ``y``
- ``infinity-swift.property``
- ``description``

### Constructor

- ``init(_:_:)``

### Equality

- ``==(_:_:)``
