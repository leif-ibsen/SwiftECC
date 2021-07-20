//
//  ZTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
import BigInt

// Test the twisted brainpool domains

class ZTest: XCTestCase {

    static let z160 = BInt("24dbff5dec9b986bbfe5295a29bfbae45e0f5d0b", radix: 16)!
    static let z192 = BInt("1b6f5cc8db4dc7af19458a9cb80dc2295e5eb9c3732104cb", radix: 16)!
    static let z224 = BInt("2df271e14427a346910cf7a2e6cfa7b3f484e5c2cce1c8b730e28b3f", radix: 16)!
    static let z256 = BInt("3e2d4bd9597b58639ae7aa669cab9837cf5cf20a2c852d10f655668dfc150ef0", radix: 16)!
    static let z320 = BInt("15f75caf668077f7e85b42eb01f0a81ff56ecd6191d55cb82b7d861458a18fefc3e5ab7496f3c7b1", radix: 16)!
    static let z384 = BInt("41dfe8dd399331f7166a66076734a89cd0d2bcdb7d068e44e1f378f41ecbae97d2d63dbc87bccddccc5da39e8589291c", radix: 16)!
    static let z512 = BInt("12ee58e6764838b69782136f0f2d3ba06e27695716054092e60a80bedb212b64e585d90bce13761f85c3f1d2a64e3be8fea2220f01eba5eeb0f35dbd29d922ab", radix: 16)!

    func doTest(_ r: Domain, _ t: Domain, _ z: BInt) {
        let a = ((z ** 4) * r.a).mod(r.p)
        let b = ((z ** 6) * r.b).mod(r.p)
        XCTAssertEqual(a, t.a)
        XCTAssertEqual(b, t.b)
    }

    func test() {
        doTest(Domain.instance(curve: .BP160r1), Domain.instance(curve: .BP160t1), ZTest.z160)
        doTest(Domain.instance(curve: .BP192r1), Domain.instance(curve: .BP192t1), ZTest.z192)
        doTest(Domain.instance(curve: .BP224r1), Domain.instance(curve: .BP224t1), ZTest.z224)
        doTest(Domain.instance(curve: .BP256r1), Domain.instance(curve: .BP256t1), ZTest.z256)
        doTest(Domain.instance(curve: .BP320r1), Domain.instance(curve: .BP320t1), ZTest.z320)
        doTest(Domain.instance(curve: .BP384r1), Domain.instance(curve: .BP384t1), ZTest.z384)
        doTest(Domain.instance(curve: .BP512r1), Domain.instance(curve: .BP512t1), ZTest.z512)
    }

}
