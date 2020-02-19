//
//  Test521.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import BigInt

// Special test for the 'secp521r1' domain

class Test521: XCTestCase {

    func test1() {
        let domain = EC521r1()
        XCTAssertEqual(domain.reduceModP(BInt.ZERO), BInt.ZERO)
        XCTAssertEqual(domain.reduceModP(BInt.ONE), BInt.ONE)
        XCTAssertEqual(domain.reduceModP(-BInt.ONE), EC521r1.p - BInt.ONE)
        XCTAssertEqual(domain.reduceModP(-EC521r1.p), BInt.ZERO)
        let Rx = BInt("117389fb4af71faeb34a1c8f3d80fef1d4ad11928b5d2918a13d04e43dd39bba3ae347dd1ea9588f74233e5f4b0631d1ecdb8150d6ea84c308c51627fec1e002d3e", radix: 16)!
        let Ry = BInt("10d88cb4403fbf3204fbeae2faa8e698e15d1084f0b1178f3d3dc3a057036c74c9adfede25bfb54ddcaa979178d77905d0c0df1774c0cd50825e7a51529b1ab6134", radix: 16)!
        let S = BInt("2b2bd902731d71977e298353638b4123076c95148e29bb573898945175f8c2b47c03e8ea9c2006de7178da4019cce094536b2d0866499fa16bfa800591739cc365", radix: 16)!
        let p = Point(Rx, Ry)
        XCTAssert(domain.contains(domain.multiply(p, S)))
    }

}
