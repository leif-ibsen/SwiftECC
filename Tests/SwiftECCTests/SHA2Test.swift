//
//  SHA2Test.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 09/07/2021.
//

import XCTest
@testable import SwiftECC

class SHA2Test: XCTestCase {

    // Test vectors from http://www.di-mgt.com.au/sha_testvectors.html - (http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf)

    let s1 = Bytes("".utf8)
    let s2 = Bytes("abc".utf8)
    let s3 = Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
    let s4 = Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".utf8)
    let s5 = Bytes(repeating: 0x61, count: 1000000)
    var s6: Bytes = []

    override func setUp() {
        s6 = []
        s6.reserveCapacity(1073741824)
        let x = Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".utf8)
        for _ in 0 ..< 16777216 {
            s6 += x
        }
    }

    func toHexString(_ x: Bytes) -> String {
        let hexDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }

    func test1() {
        let md = MessageDigest(.SHA1)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "a9993e364706816aba3e25717850c26c9cd0d89d")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "a49b2446a02c645bf419f995b67091253a04a259")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        md.update(s6)
        XCTAssertEqual(toHexString(md.digest()), "7789f0c9ef7bfc40d93311143dfbe69e2017f592")
    }

    func test224() {
        let md = MessageDigest(.SHA2_224)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67")
        md.update(s6)
        XCTAssertEqual(toHexString(md.digest()), "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85")
    }

    func test256() {
        let md = MessageDigest(.SHA2_256)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        md.update(s6)
        XCTAssertEqual(toHexString(md.digest()), "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e")
    }

    func test384() {
        let md = MessageDigest(.SHA2_384)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")
        md.update(s6)
        XCTAssertEqual(toHexString(md.digest()), "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023")
    }

    func test512() {
        let md = MessageDigest(.SHA2_512)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
        md.update(s6)
        XCTAssertEqual(toHexString(md.digest()), "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086")
    }
    
}
