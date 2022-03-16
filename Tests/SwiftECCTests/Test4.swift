//
//  Test4.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import BigInt

// Test a home made characteristic 2 domain - Guide to Elliptic Curve Cryptography - example 3.6

class EC4 {
    
    static let points = [Point.INFINITY,
                         Point(BInt(0), BInt(11)),
                         Point(BInt(1), BInt(0)),
                         Point(BInt(1), BInt(1)),
                         Point(BInt(2), BInt(13)),
                         Point(BInt(2), BInt(15)),
                         Point(BInt(3), BInt(12)),
                         Point(BInt(3), BInt(15)),
                         Point(BInt(5), BInt(0)),
                         Point(BInt(5), BInt(5)),
                         Point(BInt(7), BInt(11)),
                         Point(BInt(7), BInt(12)),
                         Point(BInt(8), BInt(1)),
                         Point(BInt(8), BInt(9)),
                         Point(BInt(9), BInt(6)),
                         Point(BInt(9), BInt(15)),
                         Point(BInt(11), BInt(2)),
                         Point(BInt(11), BInt(9)),
                         Point(BInt(12), BInt(0)),
                         Point(BInt(12), BInt(12)),
                         Point(BInt(15), BInt(4)),
                         Point(BInt(15), BInt(11)),
                         ]
    
    static let name = "ec4"
    static let rp = RP(4, 1)
    static let p = BInt("13", radix: 16)!
    static let a = BInt("8", radix: 16)!
    static let b = BInt("9", radix: 16)!
    static let gx = BInt("1", radix: 16)!
    static let gy = BInt("1", radix: 16)!
    static let order = BInt(22)
    static let cofactor = 2
    
}

class Test4: XCTestCase {

    func test1() throws {
        let curve = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: EC4.b, gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
        for i in 0 ..< EC4.points.count {
            XCTAssert(curve.contains(EC4.points[i]))
        }
        for i in 0 ..< EC4.points.count {
            let p1 = EC4.points[i]
            var x = Point.INFINITY
            for j in 0 ..< EC4.order.asInt()! {
                let pj = try curve.multiplyPoint(p1, BInt(j))
                XCTAssertEqual(x, pj)
                XCTAssert(curve.contains(pj))
                x = try curve.addPoints(x, p1)
            }
            for j in 0 ..< EC4.points.count {
                let p2 = EC4.points[j]
                XCTAssert(curve.contains(try curve.addPoints(p1, p2)))
            }
        }
    }

    func test2() throws {
        let curve = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: EC4.b, gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
        var n = 1 // Accounts for Point.INFINITY
        for i in 0 ..< 16 {
            let li = [Limb(i)]
            for j in 0 ..< 16 {
                let lj = [Limb(j)]
                if curve.contains(Point(BInt(li), BInt(lj))) {
                    n += 1
                }
            }
        }
        XCTAssertEqual(n, EC4.order.asInt()!)
    }
    
    func test3() {
        do {
            _ = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: BInt.ZERO, gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
            XCTFail("Expected domainParameter exception")
        } catch ECException.domainParameter {
        } catch {
            XCTFail("Expected domainParameter exception")
        }
        do {
            // Generator point not on curve
            _ = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: EC4.b, gx: EC4.gx, gy: BInt("2")!, order: EC4.order, cofactor: EC4.cofactor)
            XCTFail("Expected domainParameter exception")
        } catch ECException.domainParameter {
        } catch {
            XCTFail("Expected domainParameter exception")
        }
    }
    
    func test4() throws {
        let curve = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: EC4.b, gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
        var n = 1 // Point.INFINITY
        for i in 0 ..< 16 {
            let li = [Limb(i)]
            for j in 0 ..< 16 {
                let lj = [Limb(j)]
                if curve.contains(Point(BInt(li), BInt(lj))) {
                    n += 1
                }
            }
        }
        XCTAssertEqual(n, EC4.order.asInt()!)
    }

    func test5() throws {
        let curve = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: EC4.b, gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
        let (pubKey, privKey) = curve.makeKeyPair()
        let pubPemKey = try ECPublicKey(pem: pubKey.pem)
        XCTAssertEqual(pubKey.w, pubPemKey.w)
        let privPemKey = try ECPrivateKey(pem: privKey.pem)
        XCTAssertEqual(privKey.s, privPemKey.s)
        XCTAssertEqual("", privPemKey.domain.name)
    }

}
