//
//  UInt128.swift
//  SwiftX25519Test
//
//  Created by Leif Ibsen on 09/01/2023.
//

struct UInt128 {

    var high: Limb
    var low: Limb
    
    init(_ x: (high: Limb, low: Limb)) {
        self.high = x.high
        self.low = x.low
    }

    mutating func add(_ x: (high: Limb, low: Limb)) {
        let a = x.low
        self.low &+= x.low
        self.high &+= x.high
        if self.low < a {
            self.high &+= 1
        }
    }

    mutating func add(_ x: Limb) {
        self.low &+= x
        if self.low < x {
            self.high &+= 1
        }
    }

    func shiftRight51() -> Limb {
        return (self.high << 13) | (self.low >> 51)
    }
    
    mutating func shiftRight56() -> Limb {
        let x = (self.high << 8) | (self.low >> 56)
        self.low &= Field448.M56
        self.high = 0
        return x
    }

}

