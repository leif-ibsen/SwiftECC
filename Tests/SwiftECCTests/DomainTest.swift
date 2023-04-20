//
//  DomainTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
@testable import SwiftECC
import BigInt

// Test all predefined domains

class DomainTest: XCTestCase {

    func domainTest(_ domain: Domain, _ p: Point) throws {
        let pp = try domain.addPoints(p, p)
        let ppp = try domain.addPoints(domain.addPoints(p, p), p)
        let dp = try domain.doublePoint(p)
        let p2 = try domain.multiplyPoint(p, BInt(2))
        let p3 = try domain.multiplyPoint(p, BInt(3))
        XCTAssert(domain.contains(p))
        XCTAssert(domain.contains(pp))
        XCTAssert(domain.contains(ppp))
        XCTAssert(domain.contains(try domain.negatePoint(p)))
        XCTAssert(domain.contains(try domain.negatePoint(pp)))
        XCTAssert(domain.contains(try domain.negatePoint(ppp)))
        XCTAssertEqual(pp, dp)
        XCTAssertEqual(pp, p2)
        XCTAssertEqual(ppp, p3)
        XCTAssertEqual(try domain.subtractPoints(Point.INFINITY, p), try domain.negatePoint(p))
        XCTAssertEqual(try domain.subtractPoints(p, Point.INFINITY), p)
    }
    
    func multiplyGTest(_ domain: Domain, _ n: BInt) throws {
        let p1 = domain.multiplyG(n)
        let p2 = try domain.multiplyPoint(domain.g, n)
        XCTAssertEqual(p1, p2)
        XCTAssertEqual(try domain.multiplyPoint(domain.g, domain.order), Point.INFINITY)
        XCTAssertEqual(domain.multiplyG(domain.order), Point.INFINITY)
    }

    func reduceModPTest(_ domain: Domain) {
        guard let d = domain.domainP else {
            return
        }
        XCTAssertEqual(d.reduceModP(BInt.ZERO), BInt.ZERO)
        XCTAssertEqual(d.reduceModP(BInt.ONE), BInt.ONE)
        XCTAssertEqual(d.reduceModP(domain.order), domain.order.mod(domain.p))
        if domain.order < domain.p {
            XCTAssertEqual(d.reduceModP(domain.order ** 2), (domain.order ** 2).mod(domain.p))
        }
        XCTAssertEqual(d.reduceModP((domain.p - 1) ** 2), ((domain.p - 1) ** 2).mod(domain.p))
        XCTAssertEqual(d.reduceModP(domain.p), BInt.ZERO)
        XCTAssertEqual(d.reduceModP(domain.p + 1), BInt.ONE)
    }

    func equalTest(_ c: ECCurve) {
        let domain = Domain.instance(curve: c)
        for c1 in ECCurve.allCases {
            let domain1 = Domain.instance(curve: c1)
            if domain.name == domain1.name {
                XCTAssertTrue(domain == domain1)
            } else {
                XCTAssertFalse(domain == domain1)
            }
        }
    }

    func doTest(_ c: ECCurve) throws {
        let domain = Domain.instance(curve: c)
        try domainTest(domain, try domain.multiplyPoint(domain.g, BInt(0)))
        try domainTest(domain, try domain.multiplyPoint(domain.g, BInt(1)))
        try domainTest(domain, try domain.multiplyPoint(domain.g, BInt(2)))
        try domainTest(domain, try domain.multiplyPoint(domain.g, BInt(bitWidth: domain.g.x.bitWidth / 2)))
        try multiplyGTest(domain, BInt(0))
        try multiplyGTest(domain, BInt(1))
        try multiplyGTest(domain, BInt(2))
        try multiplyGTest(domain, BInt(bitWidth: domain.g.x.bitWidth / 2))
        reduceModPTest(domain)
        equalTest(c)
    }

    func test() throws {
        for c in ECCurve.allCases {
            try doTest(c)
        }
    }

}
