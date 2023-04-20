//
//  HMACTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 26/03/2022.
//

import XCTest
@testable import SwiftECC

// Test vectors from RFC 2202 and RFC 4231

class HMACTest: XCTestCase {

    // Convert a hex string to the corresponding byte array.
    static func hex2bytes(_ hex: String) -> Bytes {
        var b: Bytes = []
        var odd = false
        var x = Byte(0)
        var y = Byte(0)
        for c in hex {
            switch c {
            case "0" ... "9":
                x = c.asciiValue! - 48
            case "a" ... "f":
                x = c.asciiValue! - 87
            case "A" ... "F":
                x = c.asciiValue! - 55
            default:
                fatalError("hex2bytes")
            }
            if odd {
                b.append(y * 16 + x)
            } else {
                y = x
            }
            odd = !odd
        }
        if odd {
            fatalError("hex2bytes")
        }
        return b
    }

    struct testStruct1 {
        let key: Bytes
        let data: Bytes
        let digest1: Bytes

        init(key: Bytes, data: Bytes, digest1: Bytes) {
            self.key = key
            self.data = data
            self.digest1 = digest1
        }
    }

    struct testStruct2 {
        let key: Bytes
        let data: Bytes
        let digest224: Bytes
        let digest256: Bytes
        let digest384: Bytes
        let digest512: Bytes

        init(key: Bytes, data: Bytes, digest224: Bytes, digest256: Bytes, digest384: Bytes, digest512: Bytes) {
            self.key = key
            self.data = data
            self.digest224 = digest224
            self.digest256 = digest256
            self.digest384 = digest384
            self.digest512 = digest512
        }
    }

    let tests1: [testStruct1] = [
        testStruct1(
            key: HMACTest.hex2bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data: Bytes("Hi There".utf8),
            digest1: HMACTest.hex2bytes("b617318655057264e28bc0b6fb378c8ef146be00")
        ),
        testStruct1(
            key: Bytes("Jefe".utf8),
            data: Bytes("what do ya want for nothing?".utf8),
            digest1: HMACTest.hex2bytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        ),
        testStruct1(
            key: HMACTest.hex2bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data: HMACTest.hex2bytes("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            digest1: HMACTest.hex2bytes("125d7342b9ac11cd91a39af48aa17b4f63f175d3")
        ),
        testStruct1(
            key: HMACTest.hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            data: HMACTest.hex2bytes("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
            digest1: HMACTest.hex2bytes("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
        ),
        testStruct1(
            key: HMACTest.hex2bytes("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            data: Bytes("Test With Truncation".utf8),
            digest1: HMACTest.hex2bytes("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")
        ),
        testStruct1(
            key: HMACTest.hex2bytes(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data: Bytes("Test Using Larger Than Block-Size Key - Hash Key First".utf8),
            digest1: HMACTest.hex2bytes("aa4ae5e15272d00e95705637ce8a3b55ed402112")
        ),
        testStruct1(
            key: HMACTest.hex2bytes(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data: Bytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".utf8),
            digest1: HMACTest.hex2bytes("e8e99d0f45237d786d6bbaa7965c7808bbff1a91")
        ),
    ]

    let tests2: [testStruct2] = [
        testStruct2(
            key: HMACTest.hex2bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data: HMACTest.hex2bytes("4869205468657265"),
            digest224: HMACTest.hex2bytes("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),
            digest256: HMACTest.hex2bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            digest384: HMACTest.hex2bytes("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
            digest512: HMACTest.hex2bytes(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
        ),
        testStruct2(
            key: HMACTest.hex2bytes("4a656665"),
            data: HMACTest.hex2bytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
            digest224: HMACTest.hex2bytes("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"),
            digest256: HMACTest.hex2bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            digest384: HMACTest.hex2bytes("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"),
            digest512: HMACTest.hex2bytes(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
        ),
        testStruct2(
            key: HMACTest.hex2bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data: HMACTest.hex2bytes("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            digest224: HMACTest.hex2bytes("7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"),
            digest256: HMACTest.hex2bytes("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            digest384: HMACTest.hex2bytes("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"),
            digest512: HMACTest.hex2bytes(
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")
        ),
        testStruct2(
            key: HMACTest.hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            data: HMACTest.hex2bytes("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
            digest224: HMACTest.hex2bytes("6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"),
            digest256: HMACTest.hex2bytes("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            digest384: HMACTest.hex2bytes("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"),
            digest512: HMACTest.hex2bytes(
                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")
        ),
        testStruct2(
            key: HMACTest.hex2bytes(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data: HMACTest.hex2bytes("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"),
            digest224: HMACTest.hex2bytes("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"),
            digest256: HMACTest.hex2bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            digest384: HMACTest.hex2bytes("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"),
            digest512: HMACTest.hex2bytes(
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
        ),
        testStruct2(
            key: HMACTest.hex2bytes(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data: HMACTest.hex2bytes(
                "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"),
            digest224: HMACTest.hex2bytes("3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"),
            digest256: HMACTest.hex2bytes("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
            digest384: HMACTest.hex2bytes("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"),
            digest512: HMACTest.hex2bytes(
                "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")
        ),
    ]

    func doTest1(_ t: testStruct1) {
        let hmac = HMac(MessageDigest(.SHA1), t.key)
        XCTAssertEqual(t.digest1, hmac.doFinal(t.data))
    }

    func doTest224(_ t: testStruct2) {
        let hmac = HMac(MessageDigest(.SHA2_224), t.key)
        XCTAssertEqual(t.digest224, hmac.doFinal(t.data))
    }
    
    func doTest256(_ t: testStruct2) {
        let hmac = HMac(MessageDigest(.SHA2_256), t.key)
        XCTAssertEqual(t.digest256, hmac.doFinal(t.data))
    }

    func doTest384(_ t: testStruct2) {
        let hmac = HMac(MessageDigest(.SHA2_384), t.key)
        XCTAssertEqual(t.digest384, hmac.doFinal(t.data))
    }

    func doTest512(_ t: testStruct2) {
        let hmac = HMac(MessageDigest(.SHA2_512), t.key)
        XCTAssertEqual(t.digest512, hmac.doFinal(t.data))
    }

    func testSHA1() {
        for t in tests1 {
            doTest1(t)
        }
    }

    func testSHA2() {
        for t in tests2 {
            doTest224(t)
            doTest256(t)
            doTest384(t)
            doTest512(t)
        }
    }

}
