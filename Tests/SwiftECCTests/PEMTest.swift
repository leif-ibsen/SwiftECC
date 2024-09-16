//
//  PEMTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
@testable import SwiftECC
import Digest

class PEMTest: XCTestCase {

    func doTest(_ domain: Domain, _ explicit: Bool) throws {
        let pem = Base64.pemEncode((explicit ? domain.asn1Explicit() : domain.asn1).encode(), "EC PARAMETERS")
        let d1 = try Domain.instance(pem: pem)
        XCTAssertEqual(domain.p, d1.p)
        XCTAssertEqual(domain.a, d1.a)
        XCTAssertEqual(domain.b, d1.b)
        XCTAssertEqual(domain.g, d1.g)
        XCTAssertEqual(domain.order, d1.order)
        XCTAssertEqual(domain.cofactor, d1.cofactor)
        if domain.characteristic2 {
            XCTAssertEqual(domain.domain2!.rp, d1.domain2!.rp)
        }
    }

    func test1() throws {
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            try doTest(domain, true)
            try doTest(domain, false)
        }
    }
    
    func test2() throws {
        let domain = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: EC4.b, gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
        try doTest(domain, true)
        try doTest(domain, false)
    }

    func test3() throws {
        let domain = try Domain.instance(name: EC29.name, p: EC29.fp, a: EC29.a, b: EC29.b, gx: EC29.gx, gy: EC29.gy, order: EC29.order, cofactor: EC29.cofactor)
        try doTest(domain, true)
        try doTest(domain, false)
    }

}
