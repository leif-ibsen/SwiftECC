//
//  DomainTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import BigInt

// Test all predefined domains

class DomainTest: XCTestCase {

    func domainTest(_ domain: Domain, _ p: Point) {
        let pp = domain.add(p, p)
        let ppp = domain.add(domain.add(p, p), p)
        let dp = domain.double(p)
        let p2 = domain.multiply(p, BInt(2))
        let p3 = domain.multiply(p, BInt(3))
        XCTAssert(domain.contains(p))
        XCTAssert(domain.contains(pp))
        XCTAssert(domain.contains(ppp))
        XCTAssert(domain.contains(domain.negate(p)))
        XCTAssert(domain.contains(domain.negate(pp)))
        XCTAssert(domain.contains(domain.negate(ppp)))
        XCTAssertEqual(pp, dp)
        XCTAssertEqual(pp, p2)
        XCTAssertEqual(ppp, p3)
        XCTAssertEqual(domain.subtract(Point.INFINITY, p), domain.negate(p))
        XCTAssertEqual(domain.subtract(p, Point.INFINITY), p)
    }
    
    func multiplyGTest(_ domain: Domain, _ n: BInt) {
        let p1 = domain.multiplyG(n)
        let p2 = domain.multiply(domain.g, n)
        XCTAssertEqual(p1, p2)
        XCTAssertEqual(domain.multiply(domain.g, domain.order), Point.INFINITY)
        XCTAssertEqual(domain.multiplyG(domain.order), Point.INFINITY)
    }

    func reduceModPTest(_ domain: Domain) {
        guard let d = domain.domainP else {
            return
        }
        XCTAssertEqual(d.reduceModP(BInt.ZERO), BInt.ZERO)
        XCTAssertEqual(d.reduceModP(BInt.ONE), BInt.ONE)
        XCTAssertEqual(d.reduceModP(-BInt.ONE), (-BInt.ONE).mod(domain.p))
        XCTAssertEqual(d.reduceModP(domain.order), domain.order.mod(domain.p))
        XCTAssertEqual(d.reduceModP(-domain.order), (-domain.order).mod(domain.p))
        XCTAssertEqual(d.reduceModP(domain.order ** 2), (domain.order ** 2).mod(domain.p))
        XCTAssertEqual(d.reduceModP(-(domain.order ** 2)), (-(domain.order ** 2)).mod(domain.p))
        XCTAssertEqual(d.reduceModP((domain.p - 1) ** 2), ((domain.p - 1) ** 2).mod(domain.p))
        XCTAssertEqual(d.reduceModP(-((domain.p - 1) ** 2)), (-((domain.p - 1) ** 2)).mod(domain.p))
        XCTAssertEqual(d.reduceModP(domain.p), BInt.ZERO)
        XCTAssertEqual(d.reduceModP(-domain.p), BInt.ZERO)
        XCTAssertEqual(d.reduceModP(domain.p + 1), BInt.ONE)
        XCTAssertEqual(d.reduceModP(-domain.p + 1), BInt.ONE)
    }

    func doTest(_ c: ECCurve) {
        let domain = Domain.instance(curve: c)
        domainTest(domain, domain.multiply(domain.g, BInt(0)))
        domainTest(domain, domain.multiply(domain.g, BInt(1)))
        domainTest(domain, domain.multiply(domain.g, BInt(2)))
        domainTest(domain, domain.multiply(domain.g, BInt(bitWidth: domain.g.x.bitWidth / 2)))
        multiplyGTest(domain, BInt(0))
        multiplyGTest(domain, BInt(1))
        multiplyGTest(domain, BInt(2))
        multiplyGTest(domain, BInt(bitWidth: domain.g.x.bitWidth / 2))
        reduceModPTest(domain)
    }

    func test() {
        for c in ECCurve.allCases {
            doTest(c)
        }
    }

}
