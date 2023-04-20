//
//  KeysTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
@testable import SwiftECC
import ASN1

class KeysTest: XCTestCase {

    func doTest1(_ c: ECCurve) throws {
        let domain = Domain.instance(curve: c)
        let (pubKey, privKey) = domain.makeKeyPair()
        let pubDER = pubKey.der
        let privDER = privKey.der
        let privDER8 = privKey.derPkcs8
        let pubKeyDER = try ECPublicKey(der: pubDER)
        let privKeyDER = try ECPrivateKey(der: privDER, pkcs8: false)
        let privKeyDER8 = try ECPrivateKey(der: privDER8, pkcs8: true)
        let pubPEM = pubKey.pem
        let privPEM = privKey.pem
        let privPEM8 = privKey.pemPkcs8
        let pubKeyPEM = try ECPublicKey(pem: pubPEM)
        let privKeyPEM = try ECPrivateKey(pem: privPEM)
        let privKeyPEM8 = try ECPrivateKey(pem: privPEM8)
        let pubKeyPriv = ECPublicKey(privateKey: privKey)
        XCTAssertEqual(pubKey.w, pubKeyDER.w)
        XCTAssertEqual(pubKey.w, pubKeyPEM.w)
        XCTAssertEqual(pubKey.w, pubKeyPriv.w)
        XCTAssertEqual(pubKey.domain.name, pubKeyDER.domain.name)
        XCTAssertEqual(pubKey.domain.name, pubKeyPEM.domain.name)
        XCTAssertEqual(pubKey.domain.name, pubKeyPriv.domain.name)
        XCTAssertEqual(privKey.s, privKeyDER.s)
        XCTAssertEqual(privKey.s, privKeyDER8.s)
        XCTAssertEqual(privKey.s, privKeyPEM.s)
        XCTAssertEqual(privKey.s, privKeyPEM8.s)
        XCTAssertEqual(privKey.domain.name, privKeyDER.domain.name)
        XCTAssertEqual(privKey.domain.name, privKeyDER8.domain.name)
        XCTAssertEqual(privKey.domain.name, privKeyPEM.domain.name)
        XCTAssertEqual(privKey.domain.name, privKeyPEM8.domain.name)
    }
    
    func test1() throws {
        for c in ECCurve.allCases {
            try doTest1(c)
        }
    }

}
