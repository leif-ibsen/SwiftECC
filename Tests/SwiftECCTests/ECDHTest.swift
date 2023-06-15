//
//  ECDHTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 25/01/2022.
//

import XCTest
@testable import SwiftECC
import BigInt

class ECDHTest: XCTestCase {

    func doTestX963(_ length: Int, _ info: Bytes, _ cofactor: Bool) throws {
        var secret1: Bytes
        var secret2: Bytes
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (pubA, privA) = domain.makeKeyPair()
            let (pubB, privB) = domain.makeKeyPair()
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, md: .SHA2_224, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, md: .SHA2_224, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, md: .SHA2_256, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, md: .SHA2_256, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, md: .SHA2_384, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, md: .SHA2_384, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, md: .SHA2_512, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, md: .SHA2_512, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
        }
    }
    
    func doTestHKDF(_ length: Int, _ info: Bytes, _ salt: Bytes, _ cofactor: Bool) throws {
        var secret1: Bytes
        var secret2: Bytes
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (pubA, privA) = domain.makeKeyPair()
            let (pubB, privB) = domain.makeKeyPair()

            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, md: .SHA2_224, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, md: .SHA2_224, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, md: .SHA2_256, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, md: .SHA2_256, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, md: .SHA2_384, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, md: .SHA2_384, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, md: .SHA2_512, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, md: .SHA2_512, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
        }

    }

    // Test keyAgreement - ANS X9.63 version
    func testX963() throws {
        var length = 1
        for _ in 0 ..< 2 {
            try doTestX963(length, [], false)
            try doTestX963(length, [], true)
            try doTestX963(length, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false)
            try doTestX963(length, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], true)
            length += 100
        }
    }
    
    // Test keyAgreement - RFC 5869 HKDF version
    func testHKDF() throws {
        var length = 1
        for _ in 0 ..< 2 {
            try doTestHKDF(length, [], [], false)
            try doTestHKDF(length, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [], false)
            try doTestHKDF(length, [], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false)
            try doTestHKDF(length, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], false)
            try doTestHKDF(length, [], [], true)
            try doTestHKDF(length, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [], true)
            try doTestHKDF(length, [], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], true)
            try doTestHKDF(length, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], true)
            length += 100
        }
    }

    struct hkdf {
        let hash: MessageDigestAlgorithm
        let IKM: Bytes
        let salt: Bytes
        let info: Bytes
        let L: Int
        let PRK: Bytes
        let OKM: Bytes
        
        init(_ hash: MessageDigestAlgorithm, _ IKM: String, _ salt: String, _ info: String, _ L: Int, _ PRK: String, _ OKM: String) {
            self.hash = hash
            self.IKM = HMACTest.hex2bytes(IKM)
            self.salt = HMACTest.hex2bytes(salt)
            self.info = HMACTest.hex2bytes(info)
            self.L = L
            self.PRK = HMACTest.hex2bytes(PRK)
            self.OKM = HMACTest.hex2bytes(OKM)
        }
    }
    
    let hkdfTests: [hkdf] = [
        hkdf(.SHA2_256,
             "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
             "000102030405060708090a0b0c",
             "f0f1f2f3f4f5f6f7f8f9",
             42,
             "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
             "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
        hkdf(.SHA2_256,
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
             "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
             "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
             82,
             "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
             "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
        hkdf(.SHA2_256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            42,
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        ),
        hkdf(.SHA1,
             "0b0b0b0b0b0b0b0b0b0b0b",
             "000102030405060708090a0b0c",
             "f0f1f2f3f4f5f6f7f8f9",
             42,
             "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
             "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"),
        hkdf(.SHA1,
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
             "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
             "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
             82,
             "8adae09a2a307059478d309b26c4115a224cfaf6",
             "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"),
        hkdf(.SHA1,
             "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
             "",
             "",
             42,
             "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
             "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"),
        ]

    // Test RFC 5869
    func testRFC5869() throws {
        for t in hkdfTests {
            let x = try ECPrivateKey.HKDF(t.IKM, t.L, t.hash, t.info, t.salt)
            XCTAssertEqual(x, t.OKM)
        }
    }
    
    // Test sharedSecret
    func testSharedSecret() throws {
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (pubA, privA) = domain.makeKeyPair()
            let (pubB, privB) = domain.makeKeyPair()
            var secret1 = try privA.sharedSecret(pubKey: pubB, cofactor: false)
            var secret2 = try privB.sharedSecret(pubKey: pubA, cofactor: false)
            XCTAssertEqual(secret1, secret2)
            secret1 = try privA.sharedSecret(pubKey: pubB, cofactor: true)
            secret2 = try privB.sharedSecret(pubKey: pubA, cofactor: true)
            XCTAssertEqual(secret1, secret2)
        }
    }

}
