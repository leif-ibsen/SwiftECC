//
//  Poly1305.swift
//  ASN1
//
//  Created by Leif Ibsen on 03/04/2022.
//

struct UInt128 {
    
    let hi: Limb
    let lo: Limb
    
    init(_ hi: Limb, _ lo: Limb) {
        self.hi = hi
        self.lo = lo
    }
    
    init(_ t: (high: Limb, low: Limb)) {
        self.hi = t.high
        self.lo = t.low
    }
    
    func add(_ x: UInt128) -> UInt128 {
        var lo = self.lo
        var hi = self.hi
        var ovfl: Bool
        (lo, ovfl) = lo.addingReportingOverflow(x.lo)
        if ovfl {
            hi &+= 1
            assert(hi != 0)
        }
        (hi, ovfl) = hi.addingReportingOverflow(x.hi)
        assert(!ovfl)
        return UInt128(hi, lo)
    }
    
    func shift2right() -> UInt128 {
        return UInt128(self.hi >> 2, self.lo >> 2 | self.hi << 62)
    }

}

//
// The Poly1305 algorithm as defined in [RFC-8439] secton 2.5
//
// The implementation is based on the GO implementation in [FILIPPO]
//
class Poly1305 {
    
    // P = 2^130 - 5
    static let p0 = Limb(0xfffffffffffffffb)
    static let p1 = Limb(0xffffffffffffffff)
    static let p2 = Limb(0x0000000000000003)
    
    static func add(_ x: Limb, _ y: Limb, _ carry: Bool = false) -> (Limb, Bool) {
        let (a, ovfl) = x.addingReportingOverflow(y)
        if ovfl {
            return (a &+ (carry ? 1 : 0), true)
        } else if carry {
            return a.addingReportingOverflow(1)
        } else {
            return (a, false)
        }
    }

    static func sub(_ x: Limb, _ y: Limb, _ borrow: Bool = false) -> (Limb, Bool) {
        let (a, ovfl) = x.subtractingReportingOverflow(y)
        if ovfl {
            return (a &- (borrow ? 1 : 0), true)
        } else if borrow{
            return a.subtractingReportingOverflow(1)
        } else {
            return (a, false)
        }
    }

    let r0: Limb
    let r1: Limb
    let s0: Limb
    let s1: Limb
    var h0: Limb
    var h1: Limb
    var h2: Limb

    init(_ key: (r0: Limb, r1: Limb, s0: Limb, s1: Limb)) {
        self.r0 = key.r0
        self.r1 = key.r1
        self.s0 = key.s0
        self.s1 = key.s1
        self.h0 = 0
        self.h1 = 0
        self.h2 = 0
    }

    func computeTag(_ text: Bytes) -> Bytes {
        var remaining = text.count
        var index = 0
        var b0, b1: Limb
        while remaining >= 16 {
            b0 = 0
            b1 = 0
            for i in (0 ..< 8).reversed() {
                b0 = b0 << 8 | Limb(text[index + i])
            }
            for i in (8 ..< 16).reversed() {
                b1 = b1 << 8 | Limb(text[index + i])
            }
            doBlock(b0, b1, false)
            remaining -= 16
            index += 16
        }
        if remaining > 0 {
            b0 = 0
            b1 = 0
            for i in (0 ..< min(8, remaining)).reversed() {
                b0 = b0 << 8 | Limb(text[index + i])
            }
            if remaining >= 8 {
                for i in (8 ..< min(16, remaining)).reversed() {
                    b1 = b1 << 8 | Limb(text[index + i])
                }
            }
            if remaining < 8 {
                b0 |= 1 << (8 * remaining)
            } else {
                b1 |= 1 << (8 * remaining - 8)
            }
            doBlock(b0, b1, true)
        }
        var t0, t1: Limb
        var borrow, carry: Bool

        // t = h - P
        (t0, borrow) = Poly1305.sub(self.h0, Poly1305.p0)
        (t1, borrow) = Poly1305.sub(self.h1, Poly1305.p1, borrow)
        (_, borrow) = Poly1305.sub(self.h2, Poly1305.p2, borrow)
        
        // borrow iff h < P
        self.h0 = borrow ? self.h0 : t0
        self.h1 = borrow ? self.h1 : t1
        (self.h0, carry) = Poly1305.add(self.h0, self.s0)
        (self.h1, _) = Poly1305.add(self.h1, self.s1, carry)
        var tag = Bytes(repeating: 0, count: 16)
        for i in 0 ..< 8 {
            tag[i] = Byte(self.h0 & 0xff)
            self.h0 >>= 8
        }
        for i in 8 ..< 16 {
            tag[i] = Byte(self.h1 & 0xff)
            self.h1 >>= 8
        }
        return tag
    }

    func doBlock(_ b0: Limb, _ b1: Limb, _ lastBlock: Bool) {
        var carry: Bool
        (self.h0, carry) = Poly1305.add(self.h0, b0)
        (self.h1, carry) = Poly1305.add(self.h1, b1, carry)
        self.h2 += carry ? 1 : 0
        self.h2 += lastBlock ? 0 : 1

        let h0r0 = UInt128(self.h0.multipliedFullWidth(by: self.r0))
        let h1r0 = UInt128(self.h1.multipliedFullWidth(by: self.r0))
        let h2r0 = UInt128(self.h2.multipliedFullWidth(by: self.r0))
        let h0r1 = UInt128(self.h0.multipliedFullWidth(by: self.r1))
        let h1r1 = UInt128(self.h1.multipliedFullWidth(by: self.r1))
        let h2r1 = UInt128(self.h2.multipliedFullWidth(by: self.r1))
        assert(h2r0.hi == 0)
        assert(h2r1.hi == 0)
        let m0 = h0r0
        let m1 = h1r0.add(h0r1)
        let m2 = h2r0.add(h1r1)
        let m3 = h2r1
        let t0 = m0.lo
        let (t1, c1) = Poly1305.add(m1.lo, m0.hi)
        let (t2, c2) = Poly1305.add(m2.lo, m1.hi, c1)
        let (t3, _) = Poly1305.add(m3.lo, m2.hi, c2)
        
        // Let P = 2^130-5 and view h as cc * 2^130 + x
        // Then h = cc * 5 + x (mod P), because 2^130 = 5 (mod P)
        var cc = UInt128(t3, t2 & 0xfffffffffffffffc)

        self.h0 = t0
        self.h1 = t1
        self.h2 = t2 & 0x3
        
        // h = h + 4 * cc
        (self.h0, carry) = Poly1305.add(self.h0, cc.lo)
        (self.h1, carry) = Poly1305.add(self.h1, cc.hi, carry)
        self.h2 += carry ? 1 : 0
        cc = cc.shift2right()

        // h = h + cc
        (self.h0, carry) = Poly1305.add(self.h0, cc.lo)
        (self.h1, carry) = Poly1305.add(self.h1, cc.hi, carry)
        self.h2 += carry ? 1 : 0
    }
    
}
