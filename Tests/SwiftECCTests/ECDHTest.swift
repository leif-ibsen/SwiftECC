//
//  ECDHTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 25/01/2022.
//

import XCTest
@testable import SwiftECC
import BigInt
import Digest

class ECDHTest: XCTestCase {

    func doTestX963(_ length: Int, _ info: Bytes, _ cofactor: Bool) throws {
        var secret1: Bytes
        var secret2: Bytes
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (pubA, privA) = domain.makeKeyPair()
            let (pubB, privB) = domain.makeKeyPair()
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, kind: .SHA2_224, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, kind: .SHA2_224, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, kind: .SHA2_256, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, kind: .SHA2_256, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, kind: .SHA2_384, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, kind: .SHA2_384, sharedInfo: info, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.x963KeyAgreement(pubKey: pubB, length: length, kind: .SHA2_512, sharedInfo: info, cofactor: cofactor)
            secret2 = try privB.x963KeyAgreement(pubKey: pubA, length: length, kind: .SHA2_512, sharedInfo: info, cofactor: cofactor)
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

            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, kind: .SHA2_224, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, kind: .SHA2_224, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, kind: .SHA2_256, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, kind: .SHA2_256, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, kind: .SHA2_384, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, kind: .SHA2_384, sharedInfo: info, salt: salt, cofactor: cofactor)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.hkdfKeyAgreement(pubKey: pubB, length: length, kind: .SHA2_512, sharedInfo: info, salt: salt, cofactor: cofactor)
            secret2 = try privB.hkdfKeyAgreement(pubKey: pubA, length: length, kind: .SHA2_512, sharedInfo: info, salt: salt, cofactor: cofactor)
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
