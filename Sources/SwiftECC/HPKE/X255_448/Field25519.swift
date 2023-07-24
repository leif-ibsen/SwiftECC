//
//  Field25519.swift
//  SwiftX25519
//
//  Created by Leif Ibsen on 11/01/2023.
//

struct Field25519: CustomStringConvertible {
    
    static let fe0 = Field25519(0, 0, 0, 0, 0)
    static let fe1 = Field25519(1, 0, 0, 0, 0)
    static let fe9 = Field25519(9, 0, 0, 0, 0)

    static let mask51 = UInt64(0x7ffffffffffff)
    
    var l0: UInt64
    var l1: UInt64
    var l2: UInt64
    var l3: UInt64
    var l4: UInt64
    
    init(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64, _ l4: UInt64) {
        self.l0 = l0
        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4
    }

    init(_ b: Bytes) {
        assert(b.count == 32)
        self.l0 = UInt64(b[0]) | UInt64(b[1]) << 8 | UInt64(b[2]) << 16 | UInt64(b[3]) << 24 | UInt64(b[4]) << 32 | UInt64(b[5]) << 40 | UInt64(b[6]) << 48 | UInt64(b[7]) << 56
        self.l0 = self.l0 & Field25519.mask51
        self.l1 = UInt64(b[6]) | UInt64(b[7]) << 8 | UInt64(b[8]) << 16 | UInt64(b[9]) << 24 | UInt64(b[10]) << 32 | UInt64(b[11]) << 40 | UInt64(b[12]) << 48 | UInt64(b[13]) << 56
        self.l1 = (self.l1 >> 3) & Field25519.mask51
        self.l2 = UInt64(b[12]) | UInt64(b[13]) << 8 | UInt64(b[14]) << 16 | UInt64(b[15]) << 24 | UInt64(b[16]) << 32 | UInt64(b[17]) << 40 | UInt64(b[18]) << 48 | UInt64(b[19]) << 56
        self.l2 = (self.l2 >> 6) & Field25519.mask51
        self.l3 = UInt64(b[19]) | UInt64(b[20]) << 8 | UInt64(b[21]) << 16 | UInt64(b[22]) << 24 | UInt64(b[23]) << 32 | UInt64(b[24]) << 40 | UInt64(b[25]) << 48 | UInt64(b[26]) << 56
        self.l3 = (self.l3 >> 1) & Field25519.mask51
        self.l4 = UInt64(b[24]) | UInt64(b[25]) << 8 | UInt64(b[26]) << 16 | UInt64(b[27]) << 24 | UInt64(b[28]) << 32 | UInt64(b[29]) << 40 | UInt64(b[30]) << 48 | UInt64(b[31]) << 56
        self.l4 = (self.l4 >> 12) & Field25519.mask51
    }

    var description: String {
        return String(l0, radix: 16) + " " + String(l1, radix: 16) + " " + String(l2, radix: 16) + " " + String(l3, radix: 16) + " " + String(l4, radix: 16)
    }

    var bytes: Bytes {
        var b = Bytes(repeating: 0, count: 32)
        var x0 = self.l0
        var x1 = self.l1
        var x2 = self.l2
        var x3 = self.l3
        var x4 = self.l4
        x0 += 19
        x1 += x0 >> 51
        x0 &= Field25519.mask51
        x2 += x1 >> 51
        x1 &= Field25519.mask51
        x3 += x2 >> 51
        x2 &= Field25519.mask51
        x4 += x3 >> 51
        x3 &= Field25519.mask51
        x0 += 19 * (x4 >> 51)
        x4 &= Field25519.mask51
        
        /* now between 19 and 2^255-1 in both cases, and offset by 19. */

        x0 += 0x7ffffffffffed
        x1 += 0x7ffffffffffff
        x2 += 0x7ffffffffffff
        x3 += 0x7ffffffffffff
        x4 += 0x7ffffffffffff

        /* now between 2^255 and 2^256-20, and offset by 2^255. */

        x1 += x0 >> 51
        x0 &= Field25519.mask51
        x2 += x1 >> 51
        x1 &= Field25519.mask51
        x3 += x2 >> 51
        x2 &= Field25519.mask51
        x4 += x3 >> 51
        x3 &= Field25519.mask51
        x4 &= Field25519.mask51
        Field25519.storeBytes(&b, 0, x0 | (x1 << 51))
        Field25519.storeBytes(&b, 8, (x1 >> 13) | (x2 << 38))
        Field25519.storeBytes(&b, 16, (x2 >> 26) | (x3 << 25))
        Field25519.storeBytes(&b, 24, (x3 >> 39) | (x4 << 12))
        return b
    }
    
    static func storeBytes(_ b: inout Bytes, _ n: Int, _ x: UInt64) {
        var w = x
        for i in 0 ..< 8 {
            b[n + i] = Byte(w & 0xff)
            w >>= 8
        }
    }

    mutating func carryPropagate() {
        let c0 = self.l0 >> 51
        let c1 = self.l1 >> 51
        let c2 = self.l2 >> 51
        let c3 = self.l3 >> 51
        let c4 = self.l4 >> 51
        self.l0 = self.l0 & Field25519.mask51 + c4 * 19
        self.l1 = self.l1 & Field25519.mask51 + c0
        self.l2 = self.l2 & Field25519.mask51 + c1
        self.l3 = self.l3 & Field25519.mask51 + c2
        self.l4 = self.l4 & Field25519.mask51 + c3
    }

    mutating func reduce() {
        self.carryPropagate()
        var c = (self.l0 + 19) >> 51
        c = (self.l1 + c) >> 51
        c = (self.l2 + c) >> 51
        c = (self.l3 + c) >> 51
        c = (self.l4 + c) >> 51

        // If v < 2^255 - 19 and c = 0, this will be a no-op. Otherwise, it's
        // effectively applying the reduction identity to the carry.
        self.l0 += 19 * c
        self.l1 += self.l0 >> 51
        self.l0 = self.l0 & Field25519.mask51
        self.l2 += self.l1 >> 51
        self.l1 = self.l1 & Field25519.mask51
        self.l3 += self.l2 >> 51
        self.l2 = self.l2 & Field25519.mask51
        self.l4 += self.l3 >> 51
        self.l3 = self.l3 & Field25519.mask51
        // no additional carry
        self.l4 = self.l4 & Field25519.mask51
    }

    func add(_ x: Field25519) -> Field25519 {
        var v = Field25519(
            self.l0 + x.l0,
            self.l1 + x.l1,
            self.l2 + x.l2,
            self.l3 + x.l3,
            self.l4 + x.l4)
        v.carryPropagate()
        return v
    }

    func sub(_ x: Field25519) -> Field25519 {
        var v = Field25519(
            (self.l0 + 0xfffffffffffda) - x.l0,
            (self.l1 + 0xffffffffffffe) - x.l1,
            (self.l2 + 0xffffffffffffe) - x.l2,
            (self.l3 + 0xffffffffffffe) - x.l3,
            (self.l4 + 0xffffffffffffe) - x.l4)
        v.carryPropagate()
        return v
    }
    
    func mul(_ x: Field25519) -> Field25519 {
        let a0 = self.l0
        let a1 = self.l1
        let a2 = self.l2
        let a3 = self.l3
        let a4 = self.l4
        let b0 = x.l0
        let b1 = x.l1
        let b2 = x.l2
        let b3 = x.l3
        let b4 = x.l4
        let a1_19 = a1 * 19
        let a2_19 = a2 * 19
        let a3_19 = a3 * 19
        let a4_19 = a4 * 19

        var r0 = UInt128(a0.multipliedFullWidth(by: b0))
        r0.add(a1_19.multipliedFullWidth(by: b4))
        r0.add(a2_19.multipliedFullWidth(by: b3))
        r0.add(a3_19.multipliedFullWidth(by: b2))
        r0.add(a4_19.multipliedFullWidth(by: b1))

        var r1 = UInt128(a0.multipliedFullWidth(by: b1))
        r1.add(a1.multipliedFullWidth(by: b0))
        r1.add(a2_19.multipliedFullWidth(by: b4))
        r1.add(a3_19.multipliedFullWidth(by: b3))
        r1.add(a4_19.multipliedFullWidth(by: b2))

        var r2 = UInt128(a0.multipliedFullWidth(by: b2))
        r2.add(a1.multipliedFullWidth(by: b1))
        r2.add(a2.multipliedFullWidth(by: b0))
        r2.add(a3_19.multipliedFullWidth(by: b4))
        r2.add(a4_19.multipliedFullWidth(by: b3))

        var r3 = UInt128(a0.multipliedFullWidth(by: b3))
        r3.add(a1.multipliedFullWidth(by: b2))
        r3.add(a2.multipliedFullWidth(by: b1))
        r3.add(a3.multipliedFullWidth(by: b0))
        r3.add(a4_19.multipliedFullWidth(by: b4))

        var r4 = UInt128(a0.multipliedFullWidth(by: b4))
        r4.add(a1.multipliedFullWidth(by: b3))
        r4.add(a2.multipliedFullWidth(by: b2))
        r4.add(a3.multipliedFullWidth(by: b1))
        r4.add(a4.multipliedFullWidth(by: b0))

        let c0 = r0.shiftRight51()
        let c1 = r1.shiftRight51()
        let c2 = r2.shiftRight51()
        let c3 = r3.shiftRight51()
        let c4 = r4.shiftRight51()

        let rr0 = r0.low & Field25519.mask51 + c4 * 19
        let rr1 = r1.low & Field25519.mask51 + c0
        let rr2 = r2.low & Field25519.mask51 + c1
        let rr3 = r3.low & Field25519.mask51 + c2
        let rr4 = r4.low & Field25519.mask51 + c3

        var v = Field25519(rr0, rr1, rr2, rr3, rr4)
        v.carryPropagate()
        return v
    }
    
    func square() -> Field25519 {
        let l0 = self.l0
        let l1 = self.l1
        let l2 = self.l2
        let l3 = self.l3
        let l4 = self.l4
        
        let l0_2 = l0 * 2
        let l1_2 = l1 * 2
        let l1_38 = l1 * 38
        let l2_38 = l2 * 38
        let l3_38 = l3 * 38
        let l3_19 = l3 * 19
        let l4_19 = l4 * 19

        var r0 = UInt128(l0.multipliedFullWidth(by: l0))
        r0.add(l1_38.multipliedFullWidth(by: l4))
        r0.add(l2_38.multipliedFullWidth(by: l3))
        
        var r1 = UInt128(l0_2.multipliedFullWidth(by: l1))
        r1.add(l2_38.multipliedFullWidth(by: l4))
        r1.add(l3_19.multipliedFullWidth(by: l3))
        
        var r2 = UInt128(l0_2.multipliedFullWidth(by: l2))
        r2.add(l1.multipliedFullWidth(by: l1))
        r2.add(l3_38.multipliedFullWidth(by: l4))
        
        var r3 = UInt128(l0_2.multipliedFullWidth(by: l3))
        r3.add(l1_2.multipliedFullWidth(by: l2))
        r3.add(l4_19.multipliedFullWidth(by: l4))
        
        var r4 = UInt128(l0_2.multipliedFullWidth(by: l4))
        r4.add(l1_2.multipliedFullWidth(by: l3))
        r4.add(l2.multipliedFullWidth(by: l2))

        let c0 = r0.shiftRight51()
        let c1 = r1.shiftRight51()
        let c2 = r2.shiftRight51()
        let c3 = r3.shiftRight51()
        let c4 = r4.shiftRight51()

        let rr0 = r0.low & Field25519.mask51 + c4 * 19
        let rr1 = r1.low & Field25519.mask51 + c0
        let rr2 = r2.low & Field25519.mask51 + c1
        let rr3 = r3.low & Field25519.mask51 + c2
        let rr4 = r4.low & Field25519.mask51 + c3

        var v = Field25519(rr0, rr1, rr2, rr3, rr4)
        v.carryPropagate()
        return v
    }
    
    func square(_ n: Int) -> Field25519 {
        var t = self
        for _ in 0 ..< n {
            t = t.square()
        }
        return t
    }

    func invert() -> Field25519 {
        let z2 = self.square()
        var t = z2.square(2)
        let z9 = t.mul(self)
        let z11 = z9.mul(z2)
        t = z11.square()
        let z2_5_0 = t.mul(z9)
        t = z2_5_0.square(5)
        let z2_10_0 = t.mul(z2_5_0)
        t = z2_10_0.square(10)
        let z2_20_0 = t.mul(z2_10_0)
        t = z2_20_0.square(20)
        t = t.mul(z2_20_0)
        t = t.square(10)
        let z2_50_0 = t.mul(z2_10_0)
        t = z2_50_0.square(50)
        let z2_100_0 = t.mul(z2_50_0)
        t = z2_100_0.square(100)
        t = t.mul(z2_100_0)
        t = t.square(50)
        t = t.mul(z2_50_0)
        t = t.square(5)
        return t.mul(z11)
    }

}
