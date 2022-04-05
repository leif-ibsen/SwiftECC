//
//  ChaChaPoly.swift
//  ASN1
//
//  Created by Leif Ibsen on 03/04/2022.
//

// A ChaChaPoly instance encrypts and decrypts data with authentication for a given key and nonce
// as defined in [RFC-8439]
class ChaChaPoly {
    
    let key: Bytes
    let nonce: Bytes

    init(_ key: Bytes, _ nonce: Bytes) {
        self.key = key
        self.nonce = nonce
    }

    func encrypt(_ plaintext: inout Bytes, _ aad: Bytes = []) -> Bytes {
        let chacha = ChaCha20(self.key, self.nonce)
        chacha.doCrypt(&plaintext)
        var aead = Bytes(repeating: 0, count: 16 * ((aad.count + 15) / 16) + 16 * ((plaintext.count + 15) / 16) + 16)
        for i in 0 ..< aad.count {
            aead[i] = aad[i]
        }
        let n = 16 * ((aad.count + 15) / 16)
        for i in 0 ..< plaintext.count {
            aead[n + i] = plaintext[i]
        }
        let m = 16 * ((plaintext.count + 15) / 16)
        int2bytes(aad.count, &aead, n + m)
        int2bytes(plaintext.count, &aead, n + m + 8)
        return Poly1305(makePolyKey()).computeTag(aead)
    }

    func decrypt(_ ciphertext: inout Bytes, _ tag: Bytes, _ aad: Bytes = []) -> Bool {
        let n = 16 * ((aad.count + 15) / 16)
        let m = 16 * ((ciphertext.count + 15) / 16)
        var aead = Bytes(repeating: 0, count: n + m + 16)
        for i in 0 ..< aad.count {
            aead[i] = aad[i]
        }
        for i in 0 ..< ciphertext.count {
            aead[n + i] = ciphertext[i]
        }
        int2bytes(aad.count, &aead, n + m)
        int2bytes(ciphertext.count, &aead, n + m + 8)
        if Poly1305(makePolyKey()).computeTag(aead) == tag {
            let chacha = ChaCha20(self.key, self.nonce)
            chacha.doCrypt(&ciphertext)
            return true
        }
        return false
    }
    
    func int2bytes(_ x: Int, _ bytes: inout Bytes, _ n: Int) {
        bytes[n] = Byte(x & 0xff)
        bytes[n + 1] = Byte((x >> 8) & 0xff)
        bytes[n + 2] = Byte((x >> 16) & 0xff)
        bytes[n + 3] = Byte((x >> 24) & 0xff)
        bytes[n + 4] = Byte((x >> 32) & 0xff)
        bytes[n + 5] = Byte((x >> 40) & 0xff)
        bytes[n + 6] = Byte((x >> 48) & 0xff)
        bytes[n + 7] = Byte((x >> 56) & 0xff)
    }

    func makePolyKey() -> (r0: Limb, r1: Limb, s0: Limb, s1: Limb) {
        var x = Words(repeating: 0, count: 16)
        ChaCha20(self.key, self.nonce).blockFunction(&x, 0)
        return ((Limb(x[1]) << 32 | Limb(x[0])) & 0x0ffffffc0fffffff, (Limb(x[3]) << 32 | Limb(x[2])) & 0x0ffffffc0ffffffc, Limb(x[5]) << 32 | Limb(x[4]), Limb(x[7]) << 32 | Limb(x[6]))
    }

}
