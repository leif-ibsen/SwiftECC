//
//  KeysTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import ASN1

class KeysTest: XCTestCase {

    func doTest(_ c: ECCurve) throws {
        let domain = Domain.instance(curve: c)
        let (pubKey, privKey) = domain.makeKeyPair()
        let pubASN1 = pubKey.asn1
        let privASN1 = privKey.asn1
        let pubDER = pubASN1.encode()
        let privDER = privASN1.encode()
        let pubKeyDER = try ECPublicKey(der: pubDER)
        let privKeyDER = try ECPrivateKey(der: privDER)
        let pubPEM = pubKey.pem
        let privPEM = privKey.pem
        let pubKeyPEM = try ECPublicKey(pem: pubPEM)
        let privKeyPEM = try ECPrivateKey(pem: privPEM)
        XCTAssertEqual(pubKey.w, pubKeyDER.w)
        XCTAssertEqual(pubKey.w, pubKeyPEM.w)
        XCTAssertEqual(pubKey.domain.name, pubKeyDER.domain.name)
        XCTAssertEqual(pubKey.domain.name, pubKeyPEM.domain.name)
        XCTAssertEqual(privKey.s, privKeyDER.s)
        XCTAssertEqual(privKey.s, privKeyPEM.s)
        XCTAssertEqual(privKey.domain.name, privKeyDER.domain.name)
        XCTAssertEqual(privKey.domain.name, privKeyPEM.domain.name)
    }

    func test1() throws {
        for c in ECCurve.allCases {
            try doTest(c)
        }
    }

}
