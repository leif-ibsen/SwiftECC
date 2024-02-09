# Create new Domains

## 
You can create your own domains as illustrated by the two examples below.

### Example 1

This is example 3.5 from [GUIDE]. It shows how to make your own prime characteristic domain.
```swift
import SwiftECC
import BigInt

// Create the domain
let domain = try Domain.instance(name: "EC29", p: BInt(29), a: BInt(4), b: BInt(20), gx: BInt(1), gy: BInt(5), order: BInt(37), cofactor: 1)

let p1 = Point(BInt(5), BInt(22))
let p2 = Point(BInt(16), BInt(27))

print("p1 + p2 =", try domain.addPoints(p1, p2))
print("p1 * 2  =", try domain.multiplyPoint(p1, BInt(2)))

// Inspect the domain - please refer [SEC 1] appendix C.2
print(domain.asn1Explicit())
```
giving:
```swift
p1 + p2 = Point(13, 6)
p1 * 2  = Point(14, 6)
Sequence (6):
  Integer: 1
  Sequence (2):
    Object Identifier: 1.2.840.10045.1.1
    Integer: 29
  Sequence (2):
    Octet String (1): 04
    Octet String (1): 14
  Octet String (3): 04 01 05
  Integer: 37
  Integer: 1
```
### Example 2

This is example 3.6 from [GUIDE]. It shows how to make your own characteristic 2 domain.
```swift
import SwiftECC
import BigInt

// Reduction polynomial for x^4 + x^1 + 1    
let rp = RP(4, 1)

// Create the domain
let domain = try Domain.instance(name: "EC4", rp: rp, a: BInt(8), b: BInt(9), gx: BInt(1), gy: BInt(1), order: BInt(22), cofactor: 2)

let p1 = Point(BInt(2), BInt(15))
let p2 = Point(BInt(12), BInt(12))

print("p1 + p2 =", try domain.addPoints(p1, p2))
print("p1 * 2  =", try domain.multiplyPoint(p1, BInt(2)))

// Inspect the domain - please refer [SEC 1] appendix C.2
print(domain.asn1Explicit())
```
giving:
```swift
p1 + p2 = Point(1, 1)
p1 * 2  = Point(11, 2)
Sequence (6):
  Integer: 1
  Sequence (2):
    Object Identifier: 1.2.840.10045.1.2
    Sequence (2):
      Integer: 4
      Integer: 1
  Sequence (2):
    Octet String (1): 08
    Octet String (1): 09
  Octet String (3): 04 01 01
  Integer: 22
  Integer: 2
```
