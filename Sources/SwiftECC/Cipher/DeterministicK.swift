//
//  DeterministicK.swift
//  AEC
//
//  Created by Leif Ibsen on 23/01/2020.
//

import BigInt
import Digest

// Generate a deterministic K value for a signature - please refer [RFC 6979]
class DeterministicK {
    
    let kind: MessageDigest.Kind
    let q: BInt
    let len: Int
    let qlen: Int
    let hlen: Int
    var x: Bytes
    
    init(_ kind: MessageDigest.Kind, _ q: BInt, _ privKey: BInt) {
        self.kind = kind
        self.q = q
        self.qlen = q.bitWidth
        self.len = (self.qlen + 7) >> 3
        self.hlen = ECPrivateKey.digestLength(kind)
        self.x = privKey.asMagnitudeBytes()
        while x.count < self.len {
            x.insert(0, at: 0)
        }
    }

    func makeK(_ digest: Bytes) -> BInt {
        var V = Bytes(repeating: 0x01, count: hlen)
        var K = Bytes(repeating: 0x00, count: hlen)
        var mac = HMAC(self.kind, K)
        mac.update(V)
        mac.update([0x00])
        mac.update(self.x)
        mac.update(bits2octets(digest))
        K = mac.compute()
        mac = HMAC(self.kind, K)
        V = mac.compute(V)
        mac.reset()
        mac.update(V)
        mac.update([0x01])
        mac.update(self.x)
        mac.update(bits2octets(digest))
        K = mac.compute()
        mac = HMAC(self.kind, K)
        V = mac.compute(V)

        while true {
            var T: Bytes = []
            while T.count * 8 < self.qlen {
                mac.reset()
                V = mac.compute(V)
                T.append(contentsOf: V)
            }
            let k = bits2int(T)
            if k < self.q {
                return k
            }
            mac.reset()
            mac.update(V)
            mac.update([0x00])
            K = mac.compute()
            mac = HMAC(self.kind, K)
            V = mac.compute(V)
        }
    }
    
    func bits2octets(_ x: Bytes) -> Bytes {
        let z1 = bits2int(x)
        var b = (z1 < self.q ? z1 : z1 - self.q).asMagnitudeBytes()
        while b.count < self.len {
            b.insert(0, at: 0)
        }
        return b
    }

    func bits2int(_ x: Bytes) -> BInt {
        var b = BInt(magnitude: x)
        if self.qlen < x.count * 8 {
            b >>= x.count * 8 - self.qlen
        }
        return b
    }

}
