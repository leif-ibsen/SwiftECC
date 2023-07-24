//
//  Field448.swift
//  SwiftX25519Test
//
//  Created by Leif Ibsen on 05/01/2023.
//

struct Field448: CustomStringConvertible {
    
    static let fe0 = Field448(Limbs([0, 0, 0, 0, 0, 0, 0, 0]))
    static let fe1 = Field448(Limbs([1, 0, 0, 0, 0, 0, 0, 0]))
    static let feP = Field448(Limbs([0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff, 0xfffffffffffffe, 0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff]))
    static let M56 = Limb(0xffffffffffffff)

    var l: Limbs
    
    init(_ x: Limbs) {
        assert(x.count == 8)
        self.l = x
    }
    
    init(_ x: Bytes) {
        assert(x.count == 56)
        self.l = Limbs(repeating: 0, count: 8)
        for i in 0 ..< 8 {
            var w = Limb(0)
            for j in 0 ..< 7 {
                w |= Limb(x[i * 7 + j]) << (8 * j)
            }
            self.l[i] = w
        }
    }
    
    var description: String {
        var s = ""
        for i in (0 ..< self.l.count).reversed() {
            s = s + String(self.l[i], radix: 16) + " "
        }
        return s
    }
    
    var bytes: Bytes {
        let p = Field448.feP.l
        var x = self
        x.reduce()
        
        // Subtract p with borrow
        
        var carry = Int64(0)
        for i in 0 ..< 8 {
            carry += Int64(x.l[i]) - Int64(p[i])
            x.l[i] = Limb(carry & 0xffffffffffffff)
            carry >>= 56
        }

        // Add it back
        
        let addback = Limb(carry < 0 ? 0xffffffffffffff : carry)
        carry = 0
        for i in 0 ..< 8 {
            carry += Int64(x.l[i]) + Int64(p[i] & addback)
            x.l[i] = Limb(carry & 0xffffffffffffff)
            carry >>= 56
        }

        var b = Bytes(repeating: 0, count: 56)
        for i in 0 ..< 56 {
            b[i] = Byte((x.l[i / 7] >> ((i % 7) << 3)) & 0xff)
        }
        b.reverse()
        return b
    }

    mutating func reduce() {
        for i in 0 ..< 7 {
            let t = self.l[i] >> 56
            self.l[i] &= Field448.M56
            self.l[i + 1] &+= t
        }
        let t = self.l[7] >> 56
        self.l[7] &= Field448.M56
        self.l[0] &+= t
        self.l[4] &+= t
    }
        
    func add(_ a: Field448) -> Field448 {
        var x = self
        for i in 0 ..< 8 {
            x.l[i] &+= a.l[i]
        }
        x.reduce()
        return x
    }
    
    func sub(_ a: Field448) -> Field448 {
        var x = self
        x.l[0] &+= (0xffffffffffffff &- a.l[0])
        x.l[1] &+= (0xffffffffffffff &- a.l[1])
        x.l[2] &+= (0xffffffffffffff &- a.l[2])
        x.l[3] &+= (0xffffffffffffff &- a.l[3])
        x.l[4] &+= (0xfffffffffffffe &- a.l[4])
        x.l[5] &+= (0xffffffffffffff &- a.l[5])
        x.l[6] &+= (0xffffffffffffff &- a.l[6])
        x.l[7] &+= (0xffffffffffffff &- a.l[7])
        x.reduce()
        return x
    }
    
    func mul(_ a: Limb) -> Field448 {
        var sum0 = UInt128(a.multipliedFullWidth(by: self.l[0]))
        var sum1 = UInt128(a.multipliedFullWidth(by: self.l[1]))
        var sum2 = UInt128(a.multipliedFullWidth(by: self.l[2]))
        var sum3 = UInt128(a.multipliedFullWidth(by: self.l[3]))
        var sum4 = UInt128(a.multipliedFullWidth(by: self.l[4]))
        var sum5 = UInt128(a.multipliedFullWidth(by: self.l[5]))
        var sum6 = UInt128(a.multipliedFullWidth(by: self.l[6]))
        var sum7 = UInt128(a.multipliedFullWidth(by: self.l[7]))
        sum7.add(sum6.shiftRight56())
        sum4.add((sum7.high << 8) | (sum7.low >> 56))
        sum0.add(sum7.shiftRight56())
        sum1.add(sum0.shiftRight56())
        sum2.add(sum1.shiftRight56())
        sum3.add(sum2.shiftRight56())
        sum4.add(sum3.shiftRight56())
        sum5.add(sum4.shiftRight56())
        sum6.add(sum5.shiftRight56())
        sum7.add(sum6.shiftRight56())
        return Field448(Limbs([sum0.low, sum1.low, sum2.low, sum3.low, sum4.low, sum5.low, sum6.low, sum7.low]))
    }

    func mul(_ a: Field448) -> Field448 {
        var x0 = self.l[0]
        var x1 = self.l[1]
        var x2 = self.l[2]
        var x3 = self.l[3]
        var x4 = self.l[4]
        var x5 = self.l[5]
        var x6 = self.l[6]
        var x7 = self.l[7]
        let a0 = a.l[0]
        var sum0 = UInt128(a0.multipliedFullWidth(by: x0))
        var sum1 = UInt128(a0.multipliedFullWidth(by: x1))
        var sum2 = UInt128(a0.multipliedFullWidth(by: x2))
        var sum3 = UInt128(a0.multipliedFullWidth(by: x3))
        var sum4 = UInt128(a0.multipliedFullWidth(by: x4))
        var sum5 = UInt128(a0.multipliedFullWidth(by: x5))
        var sum6 = UInt128(a0.multipliedFullWidth(by: x6))
        var sum7 = UInt128(a0.multipliedFullWidth(by: x7))
        x3 &+= x7
        let a1 = a.l[1]
        sum1.add(a1.multipliedFullWidth(by: x0))
        sum2.add(a1.multipliedFullWidth(by: x1))
        sum3.add(a1.multipliedFullWidth(by: x2))
        sum4.add(a1.multipliedFullWidth(by: x3))
        sum5.add(a1.multipliedFullWidth(by: x4))
        sum6.add(a1.multipliedFullWidth(by: x5))
        sum7.add(a1.multipliedFullWidth(by: x6))
        sum0.add(a1.multipliedFullWidth(by: x7))
        x2 &+= x6
        let a2 = a.l[2]
        sum2.add(a2.multipliedFullWidth(by: x0))
        sum3.add(a2.multipliedFullWidth(by: x1))
        sum4.add(a2.multipliedFullWidth(by: x2))
        sum5.add(a2.multipliedFullWidth(by: x3))
        sum6.add(a2.multipliedFullWidth(by: x4))
        sum7.add(a2.multipliedFullWidth(by: x5))
        sum0.add(a2.multipliedFullWidth(by: x6))
        sum1.add(a2.multipliedFullWidth(by: x7))
        x1 &+= x5
        let a3 = a.l[3]
        sum3.add(a3.multipliedFullWidth(by: x0))
        sum4.add(a3.multipliedFullWidth(by: x1))
        sum5.add(a3.multipliedFullWidth(by: x2))
        sum6.add(a3.multipliedFullWidth(by: x3))
        sum7.add(a3.multipliedFullWidth(by: x4))
        sum0.add(a3.multipliedFullWidth(by: x5))
        sum1.add(a3.multipliedFullWidth(by: x6))
        sum2.add(a3.multipliedFullWidth(by: x7))
        x0 &+= x4
        let a4 = a.l[4]
        sum4.add(a4.multipliedFullWidth(by: x0))
        sum5.add(a4.multipliedFullWidth(by: x1))
        sum6.add(a4.multipliedFullWidth(by: x2))
        sum7.add(a4.multipliedFullWidth(by: x3))
        sum0.add(a4.multipliedFullWidth(by: x4))
        sum1.add(a4.multipliedFullWidth(by: x5))
        sum2.add(a4.multipliedFullWidth(by: x6))
        sum3.add(a4.multipliedFullWidth(by: x7))
        x7 &+= x3
        let a5 = a.l[5]
        sum5.add(a5.multipliedFullWidth(by: x0))
        sum6.add(a5.multipliedFullWidth(by: x1))
        sum7.add(a5.multipliedFullWidth(by: x2))
        sum0.add(a5.multipliedFullWidth(by: x3))
        sum1.add(a5.multipliedFullWidth(by: x4))
        sum2.add(a5.multipliedFullWidth(by: x5))
        sum3.add(a5.multipliedFullWidth(by: x6))
        sum4.add(a5.multipliedFullWidth(by: x7))
        x6 &+= x2
        let a6 = a.l[6]
        sum6.add(a6.multipliedFullWidth(by: x0))
        sum7.add(a6.multipliedFullWidth(by: x1))
        sum0.add(a6.multipliedFullWidth(by: x2))
        sum1.add(a6.multipliedFullWidth(by: x3))
        sum2.add(a6.multipliedFullWidth(by: x4))
        sum3.add(a6.multipliedFullWidth(by: x5))
        sum4.add(a6.multipliedFullWidth(by: x6))
        sum5.add(a6.multipliedFullWidth(by: x7))
        x5 &+= x1
        let a7 = a.l[7]
        sum7.add(a7.multipliedFullWidth(by: x0))
        sum0.add(a7.multipliedFullWidth(by: x1))
        sum1.add(a7.multipliedFullWidth(by: x2))
        sum2.add(a7.multipliedFullWidth(by: x3))
        sum3.add(a7.multipliedFullWidth(by: x4))
        sum4.add(a7.multipliedFullWidth(by: x5))
        sum5.add(a7.multipliedFullWidth(by: x6))
        sum6.add(a7.multipliedFullWidth(by: x7))
        x4 &+= x0
        sum7.add(sum6.shiftRight56())
        sum4.add((sum7.high << 8) | (sum7.low >> 56))        
        sum0.add(sum7.shiftRight56())
        sum1.add(sum0.shiftRight56())
        sum2.add(sum1.shiftRight56())
        sum3.add(sum2.shiftRight56())
        sum4.add(sum3.shiftRight56())
        sum5.add(sum4.shiftRight56())
        sum6.add(sum5.shiftRight56())
        sum7.add(sum6.shiftRight56())
        return Field448(Limbs([sum0.low, sum1.low, sum2.low, sum3.low, sum4.low, sum5.low, sum6.low, sum7.low]))
    }

    func square() -> Field448 {
        return self.mul(self)
    }

    func square(_ n: Int) -> Field448 {
        var x = self
        for _ in 0 ..< n {
            x = x.square()
        }
        return x
    }
    
    func invert() -> Field448 {
        let x2 = self.square().mul(self)
        let x3 = x2.square().mul(self)
        let x6 = x3.square(3).mul(x3)
        let x9 = x6.square(3).mul(x3)
        let x18 = x9.square(9).mul(x9)
        let x19 = x18.square().mul(self)
        let x37 = x19.square(18).mul(x18)
        let x74 = x37.square(37).mul(x37)
        let x111 = x74.square(37).mul(x37)
        let x222 = x111.square(111).mul(x111)
        let x223 = x222.square().mul(self)
        return x223.square(223).mul(x222).square(2).mul(self)
    }

}
