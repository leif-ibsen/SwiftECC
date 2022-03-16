//
//  Test29.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import BigInt

// Test a home made prime characteristic domain - Guide to Elliptic Curve Cryptography - example 3.5

class EC29 {
    
    static let points = [Point.INFINITY,
                         Point(BInt(0), BInt(7)),
                         Point(BInt(0), BInt(22)),
                         Point(BInt(1), BInt(5)),
                         Point(BInt(1), BInt(24)),
                         Point(BInt(2), BInt(6)),
                         Point(BInt(2), BInt(23)),
                         Point(BInt(3), BInt(1)),
                         Point(BInt(3), BInt(28)),
                         Point(BInt(4), BInt(10)),
                         Point(BInt(4), BInt(19)),
                         Point(BInt(5), BInt(7)),
                         Point(BInt(5), BInt(22)),
                         Point(BInt(6), BInt(12)),
                         Point(BInt(6), BInt(17)),
                         Point(BInt(8), BInt(10)),
                         Point(BInt(8), BInt(19)),
                         Point(BInt(10), BInt(4)),
                         Point(BInt(10), BInt(25)),
                         Point(BInt(13), BInt(6)),
                         Point(BInt(13), BInt(23)),
                         Point(BInt(14), BInt(6)),
                         Point(BInt(14), BInt(23)),
                         Point(BInt(15), BInt(2)),
                         Point(BInt(15), BInt(27)),
                         Point(BInt(16), BInt(2)),
                         Point(BInt(16), BInt(27)),
                         Point(BInt(17), BInt(10)),
                         Point(BInt(17), BInt(19)),
                         Point(BInt(19), BInt(13)),
                         Point(BInt(19), BInt(16)),
                         Point(BInt(20), BInt(3)),
                         Point(BInt(20), BInt(26)),
                         Point(BInt(24), BInt(7)),
                         Point(BInt(24), BInt(22)),
                         Point(BInt(27), BInt(2)),
                         Point(BInt(27), BInt(27)),
                         ]
    
    static let name = "ec29"
    static let fp = BInt("1d", radix: 16)!
    static let a = BInt("4", radix: 16)!
    static let b = BInt("14", radix: 16)!
    static let gx = BInt("1", radix: 16)!
    static let gy = BInt("5", radix: 16)!
    static let order = BInt(37)
    static let cofactor = 1
    
}

class Test29: XCTestCase {

    func test1() throws {
        let curve = try Domain.instance(name: EC29.name, p: EC29.fp, a: EC29.a, b: EC29.b, gx: EC29.gx, gy: EC29.gy, order: EC29.order, cofactor: EC29.cofactor)
        
        for i in 0 ..< EC29.points.count {
            XCTAssert(curve.contains(EC29.points[i]))
        }
        for i in 0 ..< EC29.points.count {
            let p1 = EC29.points[i]
            var x = Point.INFINITY
            for j in 0 ..< EC29.order.asInt()! {
                let pj = try curve.multiplyPoint(p1, BInt(j))
                XCTAssertEqual(x, pj)
                XCTAssert(curve.contains(pj))
                x = try curve.addPoints(x, p1)
            }
            for j in 0 ..< EC29.points.count {
                let p2 = EC29.points[j]
                XCTAssert(curve.contains(try curve.addPoints(p1, p2)))
            }
        }
    }
    
    func test2() throws {
        let curve = try Domain.instance(name: EC29.name, p: EC29.fp, a: EC29.a, b: EC29.b, gx: EC29.gx, gy: EC29.gy, order: EC29.order, cofactor: EC29.cofactor)
        var n = 1 // Accounts for Point.INFINITY
        for i in 0 ..< 29 {
            for j in 0 ..< 29 {
                if curve.contains(Point(BInt(i), BInt(j))) {
                    n += 1
                }
            }
        }
        XCTAssertEqual(n, EC29.order.asInt()!)
    }
    
    func test3() {
        do {
            _ = try Domain.instance(name: EC29.name, p: EC29.fp, a: BInt(2), b: BInt(4), gx: EC29.gx, gy: EC29.gy, order: EC29.order, cofactor: EC29.cofactor)
            XCTFail("Expected domainParameter exception")
        } catch ECException.domainParameter {
        } catch {
            XCTFail("Expected domainParameter exception")
        }
        do {
            // Generator point not on curve
            _ = try Domain.instance(name: EC29.name, p: EC29.fp, a: EC29.a, b: EC29.b, gx: EC29.gx, gy: BInt("1")!, order: EC29.order, cofactor: EC29.cofactor)
            XCTFail("Expected domainParameter exception")
        } catch ECException.domainParameter {
        } catch {
            XCTFail("Expected domainParameter exception")
        }
    }

    func test4() throws {
        let curve = try Domain.instance(name: EC29.name, p: EC29.fp, a: EC29.a, b: EC29.b, gx: EC29.gx, gy: EC29.gy, order: EC29.order, cofactor: EC29.cofactor)
        let (pubKey, privKey) = curve.makeKeyPair()
        let pubPemKey = try ECPublicKey(pem: pubKey.pem)
        XCTAssertEqual(pubKey.w, pubPemKey.w)
        let privPemKey = try ECPrivateKey(pem: privKey.pem)
        XCTAssertEqual(privKey.s, privPemKey.s)
        XCTAssertEqual("", privPemKey.domain.name)
    }

}
