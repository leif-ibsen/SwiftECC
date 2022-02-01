//
//  ECDHTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 25/01/2022.
//

import XCTest
import BigInt

class ECDHTest: XCTestCase {

    func test1() throws {
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (pubA, privA) = domain.makeKeyPair()
            let (pubB, privB) = domain.makeKeyPair()
            var secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_224, sharedInfo: [])
            var secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_224, sharedInfo: [])
            XCTAssertEqual(secret1, secret2)
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_224, sharedInfo: [], cofactor: true)
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_224, sharedInfo: [], cofactor: true)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_256, sharedInfo: [])
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_256, sharedInfo: [])
            XCTAssertEqual(secret1, secret2)
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_256, sharedInfo: [], cofactor: true)
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_256, sharedInfo: [], cofactor: true)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_384, sharedInfo: [])
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_384, sharedInfo: [])
            XCTAssertEqual(secret1, secret2)
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_384, sharedInfo: [], cofactor: true)
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_384, sharedInfo: [], cofactor: true)
            XCTAssertEqual(secret1, secret2)
            
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_512, sharedInfo: [])
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_512, sharedInfo: [])
            XCTAssertEqual(secret1, secret2)
            secret1 = try privA.keyAgreement(pubKey: pubB, length: 100, md: .SHA2_512, sharedInfo: [], cofactor: true)
            secret2 = try privB.keyAgreement(pubKey: pubA, length: 100, md: .SHA2_512, sharedInfo: [], cofactor: true)
            XCTAssertEqual(secret1, secret2)
        }
    }

}
