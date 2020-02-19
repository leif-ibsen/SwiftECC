//
//  PointTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import BigInt

// Test point encoding and decoding

class PointTest: XCTestCase {

    func doTest(_ c: ECCurve) throws {
        let domain = Domain.instance(curve: c)
        let inf = domain.multiply(domain.g, domain.order)
        var b1 = try domain.encodePoint(inf, false)
        var b2 = try domain.encodePoint(inf, true)
        XCTAssert(b1.count == 1)
        XCTAssert(b2.count == 1)
        let inf1 = try domain.decodePoint(b1)
        let inf2 = try domain.decodePoint(b2)
        XCTAssert(inf1.infinity)
        XCTAssert(inf2.infinity)
        let p = domain.multiply(domain.g, domain.order - BInt.ONE)
        b1 = try domain.encodePoint(p, false)
        b2 = try domain.encodePoint(p, true)
        let p1 = try domain.decodePoint(b1)
        let p2 = try domain.decodePoint(b2)
        XCTAssertEqual(b1.count, 2 * ((domain.p.bitWidth + 7) / 8) + 1)
        XCTAssertEqual(b2.count, (domain.p.bitWidth + 7) / 8 + 1)
        XCTAssertEqual(p1, p)
        XCTAssertEqual(p2, p)
        for _ in 0 ..< 10 {
            let n = domain.order.randomLessThan()
            let p = domain.multiply(domain.g, n)
            b1 = try domain.encodePoint(p, false)
            b2 = try domain.encodePoint(p, true)
            XCTAssertEqual(b1.count, 2 * ((domain.p.bitWidth + 7) / 8) + 1)
            XCTAssertEqual(b2.count, (domain.p.bitWidth + 7) / 8 + 1)
            let p1 = try domain.decodePoint(b1)
            let p2 = try domain.decodePoint(b2)
            XCTAssertEqual(p1, p)
            XCTAssertEqual(p2, p)
        }
        let x1 = domain.negate(domain.multiply(domain.g, BInt(2)))
        let x2 = domain.multiply(domain.negate(domain.g), BInt(2))
        XCTAssertEqual(x1, x2)
    }

    func test1() throws {
        for c in ECCurve.allCases {
            try doTest(c)
        }
    }

}
