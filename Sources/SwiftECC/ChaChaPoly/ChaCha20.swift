//
//  ChaCha20.swift
//  ASN1
//
//  Created by Leif Ibsen on 03/04/2022.
//

class ChaCha20 {
    
    static func wordFromBytes(_ b: Bytes, _ n: Int) -> Word {
        return Word(b[n]) | Word(b[n + 1]) << 8 | Word(b[n + 2]) << 16 | Word(b[n + 3]) << 24
    }

    let state0: Word
    let state1: Word
    let state2: Word
    let state3: Word
    let state4: Word
    let state5: Word
    let state6: Word
    let state7: Word
    let state8: Word
    let state9: Word
    let state10: Word
    let state11: Word
    let state13: Word
    let state14: Word
    let state15: Word

    init(_ key: Bytes, _ nonce: Bytes) {
        self.state0 = 0x61707865
        self.state1 = 0x3320646e
        self.state2 = 0x79622d32
        self.state3 = 0x6b206574
        self.state4 = ChaCha20.wordFromBytes(key, 0)
        self.state5 = ChaCha20.wordFromBytes(key, 4)
        self.state6 = ChaCha20.wordFromBytes(key, 8)
        self.state7 = ChaCha20.wordFromBytes(key, 12)
        self.state8 = ChaCha20.wordFromBytes(key, 16)
        self.state9 = ChaCha20.wordFromBytes(key, 20)
        self.state10 = ChaCha20.wordFromBytes(key, 24)
        self.state11 = ChaCha20.wordFromBytes(key, 28)
        self.state13 = ChaCha20.wordFromBytes(nonce, 0)
        self.state14 = ChaCha20.wordFromBytes(nonce, 4)
        self.state15 = ChaCha20.wordFromBytes(nonce, 8)
    }


    // [RFC-8439] section 2.3
    func blockFunction(_ x: inout Words, _ counter: Word) {
        var x0 = self.state0
        var x1 = self.state1
        var x2 = self.state2
        var x3 = self.state3
        var x4 = self.state4
        var x5 = self.state5
        var x6 = self.state6
        var x7 = self.state7
        var x8 = self.state8
        var x9 = self.state9
        var x10 = self.state10
        var x11 = self.state11
        var x12 = counter
        var x13 = self.state13
        var x14 = self.state14
        var x15 = self.state15
        for _ in 0 ..< 10 {

            // 8 quarterrounds unrolled

            x0 &+= x4
            x12 ^= x0
            x12 = (x12 << 16) | (x12 >> 16)
            x8 &+= x12
            x4 ^= x8
            x4 = (x4 << 12) | (x4 >> 20)
            x0 &+= x4
            x12 ^= x0
            x12 = (x12 << 8) | (x12 >> 24)
            x8 &+= x12
            x4 ^= x8
            x4 = (x4 << 7) | (x4 >> 25)
            x1 &+= x5
            x13 ^= x1
            x13 = (x13 << 16) | (x13 >> 16)
            x9 &+= x13
            x5 ^= x9
            x5 = (x5 << 12) | (x5 >> 20)
            x1 &+= x5
            x13 ^= x1
            x13 = (x13 << 8) | (x13 >> 24)
            x9 &+= x13
            x5 ^= x9
            x5 = (x5 << 7) | (x5 >> 25)
            x2 &+= x6
            x14 ^= x2
            x14 = (x14 << 16) | (x14 >> 16)
            x10 &+= x14
            x6 ^= x10
            x6 = (x6 << 12) | (x6 >> 20)
            x2 &+= x6
            x14 ^= x2
            x14 = (x14 << 8) | (x14 >> 24)
            x10 &+= x14
            x6 ^= x10
            x6 = (x6 << 7) | (x6 >> 25)
            x3 &+= x7
            x15 ^= x3
            x15 = (x15 << 16) | (x15 >> 16)
            x11 &+= x15
            x7 ^= x11
            x7 = (x7 << 12) | (x7 >> 20)
            x3 &+= x7
            x15 ^= x3
            x15 = (x15 << 8) | (x15 >> 24)
            x11 &+= x15
            x7 ^= x11
            x7 = (x7 << 7) | (x7 >> 25)
            x0 &+= x5
            x15 ^= x0
            x15 = (x15 << 16) | (x15 >> 16)
            x10 &+= x15
            x5 ^= x10
            x5 = (x5 << 12) | (x5 >> 20)
            x0 &+= x5
            x15 ^= x0
            x15 = (x15 << 8) | (x15 >> 24)
            x10 &+= x15
            x5 ^= x10
            x5 = (x5 << 7) | (x5 >> 25)
            x1 &+= x6
            x12 ^= x1
            x12 = (x12 << 16) | (x12 >> 16)
            x11 &+= x12
            x6 ^= x11
            x6 = (x6 << 12) | (x6 >> 20)
            x1 &+= x6
            x12 ^= x1
            x12 = (x12 << 8) | (x12 >> 24)
            x11 &+= x12
            x6 ^= x11
            x6 = (x6 << 7) | (x6 >> 25)
            x2 &+= x7
            x13 ^= x2
            x13 = (x13 << 16) | (x13 >> 16)
            x8 &+= x13
            x7 ^= x8
            x7 = (x7 << 12) | (x7 >> 20)
            x2 &+= x7
            x13 ^= x2
            x13 = (x13 << 8) | (x13 >> 24)
            x8 &+= x13
            x7 ^= x8
            x7 = (x7 << 7) | (x7 >> 25)
            x3 &+= x4
            x14 ^= x3
            x14 = (x14 << 16) | (x14 >> 16)
            x9 &+= x14
            x4 ^= x9
            x4 = (x4 << 12) | (x4 >> 20)
            x3 &+= x4
            x14 ^= x3
            x14 = (x14 << 8) | (x14 >> 24)
            x9 &+= x14
            x4 ^= x9
            x4 = (x4 << 7) | (x4 >> 25)
        }
        x[0] = x0 &+ self.state0
        x[1] = x1 &+ self.state1
        x[2] = x2 &+ self.state2
        x[3] = x3 &+ self.state3
        x[4] = x4 &+ self.state4
        x[5] = x5 &+ self.state5
        x[6] = x6 &+ self.state6
        x[7] = x7 &+ self.state7
        x[8] = x8 &+ self.state8
        x[9] = x9 &+ self.state9
        x[10] = x10 &+ self.state10
        x[11] = x11 &+ self.state11
        x[12] = x12 &+ counter
        x[13] = x13 &+ self.state13
        x[14] = x14 &+ self.state14
        x[15] = x15 &+ self.state15
    }

    // [RFC-8439] section 2.4
    func doCrypt(_ text: inout Bytes) {
        var xor = Words(repeating: 0, count: 16)
        
        // bytePtr points to start of xor array

        let bytePtr = withUnsafePointer(to: &xor[0]) {
            $0.withMemoryRebound(to: Byte.self, capacity: 64) {
                UnsafeBufferPointer(start: $0, count: 64)
            }
        }
        var j = 0
        var counter = Word(0)
        for i in 0 ..< text.count {
            if i % 64 == 0 {
                j = 0
                counter += 1
                blockFunction(&xor, counter)
            }
            text[i] ^= bytePtr[j]
            j += 1
        }
    }

}
