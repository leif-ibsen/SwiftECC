//
//  SignatureTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest

class SignatureTest: XCTestCase {

    let message1 = Bytes("The quick brown fox jumps over the lazy dog".utf8)
    let message2 = Bytes("the quick brown fox jumps over the lazy dog".utf8)
    let data1: Data = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let data2: Data = "the quick brown fox jumps over the lazy dog".data(using: .utf8)!

    func doTest(_ c: ECCurve) {
        let domain = Domain.instance(curve: c)
        let (pub, priv) = domain.makeKeyPair()
        let sig1 = priv.sign(msg: message1)
        XCTAssertTrue(pub.verify(signature: sig1, msg: message1))
        XCTAssertFalse(pub.verify(signature: sig1, msg: message2))
        XCTAssertEqual((domain.p.bitWidth + 7) / 8, sig1.r.count)
        XCTAssertEqual((domain.p.bitWidth + 7) / 8, sig1.s.count)
        let sig2 = priv.sign(msg: data1)
        XCTAssertEqual((domain.p.bitWidth + 7) / 8, sig2.r.count)
        XCTAssertEqual((domain.p.bitWidth + 7) / 8, sig2.s.count)
        XCTAssertTrue(pub.verify(signature: sig2, msg: data1))
        XCTAssertFalse(pub.verify(signature: sig2, msg: data2))
        
        // Signature r and s out of range
        
        let sig3 = ECSignature(domain: domain, r: [0], s: sig2.s)
        XCTAssertFalse(pub.verify(signature: sig3, msg: data1))
        let sig4 = ECSignature(domain: domain, r: Bytes(repeating: 0xff, count: (domain.order.bitWidth + 7) / 8), s: sig2.s)
        XCTAssertFalse(pub.verify(signature: sig4, msg: data1))
        let sig5 = ECSignature(domain: domain, r: sig2.r, s: [0])
        XCTAssertFalse(pub.verify(signature: sig5, msg: data1))
        let sig6 = ECSignature(domain: domain, r: sig2.r, s: Bytes(repeating: 0xff, count: (domain.order.bitWidth + 7) / 8))
        XCTAssertFalse(pub.verify(signature: sig6, msg: data1))
    }

    func test1() {
        for c in ECCurve.allCases {
            doTest(c)
        }
    }

}
