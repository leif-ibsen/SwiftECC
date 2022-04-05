//
//  ExceptionTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 17/02/2020.
//

import XCTest
import ASN1
import BigInt

class ExceptionTest: XCTestCase {

    func testAsn1Structure() {
        do {
            let _  = try ECPrivateKey(der: ASN1Null().encode())
            XCTFail("Expected ECException.asn1Structure")
        } catch ECException.asn1Structure {
        } catch {
            XCTFail("Expected ECException.asn1Structure")
        }
    }

    func testAuthentication() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            let (pub, priv) = domain.makeKeyPair()
            let message = "abc".data(using: .utf8)!
            var xyz = pub.encrypt(msg: message, cipher: .AES128)
            xyz[xyz.count - 1] ^= 0xff
            _ = try priv.decrypt(msg: xyz, cipher: .AES128)
            XCTFail("Expected ECException.authentication")
        } catch ECException.authentication {
        } catch {
            XCTFail("Expected ECException.authentication")
        }
        do {
            let domain = Domain.instance(curve: .BP160r1)
            let (pub, priv) = domain.makeKeyPair()
            let message = Bytes("abc".utf8)
            let xyz = pub.encryptChaCha(msg: message, aad: [Byte(1), Byte(2), Byte(3)])
            _ = try priv.decryptChaCha(msg: xyz, aad: [Byte(3), Byte(2), Byte(1)])
            XCTFail("Expected ECException.authentication")
        } catch ECException.authentication {
        } catch {
            XCTFail("Expected ECException.authentication")
        }
    }

    func testBase64() {
        do {
            let bytes: Bytes = [1, 2, 3]
            var b64 = Base64.encode(bytes)
            b64.append("a")
            _ = try Base64.decode(b64)
            XCTFail("Expected ECException.base64")
        } catch ECException.base64 {
        } catch {
            XCTFail("Expected ECException.base64")
        }
    }

    func testDecodePoint() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            var bytes = try domain.encodePoint(domain.g)
            bytes[0] = 5
            _ = try domain.decodePoint(bytes)
            XCTFail("Expected ECException.decodePoint")
        } catch ECException.decodePoint {
        } catch {
            XCTFail("Expected ECException.decodePoint")
        }
    }

    func testDomainParameter() {
        do {
            _ = try Domain.instance(name: EC29.name, p: EC29.fp, a: BInt(2), b: BInt(4), gx: EC29.gx, gy: EC29.gy, order: EC29.order, cofactor: EC29.cofactor)
            XCTFail("Expected ECException.domainParameter")
        } catch ECException.domainParameter {
        } catch {
            XCTFail("Expected ECException.domainParameter")
        }
        do {
            _ = try Domain.instance(name: EC4.name, rp: EC4.rp, a: EC4.a, b: BInt(0), gx: EC4.gx, gy: EC4.gy, order: EC4.order, cofactor: EC4.cofactor)
            XCTFail("Expected ECException.domainParameter")
        } catch ECException.domainParameter {
        } catch {
            XCTFail("Expected ECException.domainParameter")
        }
    }

    func testEncodePoint() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            _ = try domain.encodePoint(Point(BInt(1), BInt(2)))
            XCTFail("Expected ECException.encodePoint")
        } catch ECException.encodePoint {
        } catch {
            XCTFail("Expected ECException.encodePoint")
        }
    }

    func testNotEnoughInput() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            let (_, priv) = domain.makeKeyPair()
            let xyz = Bytes(repeating: 0, count: 30)
            _ = try priv.decrypt(msg: xyz, cipher: .AES128)
            XCTFail("Expected ECException.notEnoughInput")
        } catch ECException.notEnoughInput {
        } catch {
            XCTFail("Expected ECException.notEnoughInput")
        }
    }

    func testPadding() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            let (pub, priv) = domain.makeKeyPair()
            let message = "abc".data(using: .utf8)!
            var xyz = pub.encrypt(msg: message, cipher: .AES128, mode: .ECB)
            xyz[xyz.count - 33] ^= 0xff
            _ = try priv.decrypt(msg: xyz, cipher: .AES128, mode: .ECB)
            XCTFail("Expected ECException.padding")
        } catch ECException.padding {
        } catch {
            XCTFail("Expected ECException.padding")
        }
    }

    func testPemStructure() {
        do {
            let priv521r1 =
"""
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBmrX72oofcDCHf3IWmlM1Cb4MzK4rTubdEf8UmY08EuUAFQVbYc90k1yeGCQTTDr3
qiQu3XH43rjjiPGl/JhGzDigBwYFK4EEACOhgYkDgYYABADmDj3tfXvubpMCBkDiwr1CK2iadSRS
BJ1Ih0zTull/inAHWp3DWm3kL03lNWn5X+jHTnsRZB7I1VbY0ezuk1iVmABsPeSXKe69dMouEuTC
jaIqUG0ZPxgrLNoic4S+euqwVc3o6QX4JbMVy5hqAPjAPZBqwpo41MuHCeZYxKt3FOZPwQ==
-----END EC PRIVATE KEY-----
"""
            _ = try Base64.pemDecode(priv521r1, "PRIVATE KEY")
            XCTFail("Expected ECException.pemStructure")
        } catch ECException.pemStructure {
        } catch {
            XCTFail("Expected ECException.pemStructure")
        }
    }

    func testPrivateKeyParameter() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            _ = try ECPrivateKey(domain: domain, s: domain.order)
            XCTFail("Expected ECException.privateKeyParameter")
        } catch ECException.privateKeyParameter {
        } catch {
            XCTFail("Expected ECException.privateKeyParameter")
        }
    }

    func testPublicKeyParameter() {
        do {
            let domain = Domain.instance(curve: .BP160r1)
            _ = try ECPublicKey(domain: domain, w: Point(BInt.ONE, BInt.ONE))
            XCTFail("Expected ECException.publicKeyParameter")
        } catch ECException.publicKeyParameter {
        } catch {
            XCTFail("Expected ECException.publicKeyParameter")
        }
        do {
            let domain = Domain.instance(curve: .BP160r1)
            _ = try ECPublicKey(domain: domain, w: Point.INFINITY)
            XCTFail("Expected ECException.publicKeyParameter")
        } catch ECException.publicKeyParameter {
        } catch {
            XCTFail("Expected ECException.publicKeyParameter")
        }
    }

    func testUnknownOid() {
        do {
            let _ = try Domain.instance(oid: ASN1ObjectIdentifier("1.2.3")!)
            XCTFail("Expected ECException.unknownOid")
        } catch ECException.unknownOid {
        } catch {
            XCTFail("Expected ECException.unknownOid")
        }
    }
    
    func testNotOnCurve() {
        let domain = Domain.instance(curve: .BP160r1)
        let p1 = Point(BInt.ONE, BInt.ONE)
        let p2 = Point(BInt.TWO, BInt.TWO)
        do {
            let _ = try domain.doublePoint(Point.INFINITY)
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try domain.doublePoint(p1)
            XCTFail("Expected ECException.notOnCurve")
        } catch ECException.notOnCurve {
        } catch {
            XCTFail("Expected ECException.notOnCurve")
        }
        do {
            let _ = try domain.addPoints(p1, p2)
            XCTFail("Expected ECException.notOnCurve")
        } catch ECException.notOnCurve {
        } catch {
            XCTFail("Expected ECException.notOnCurve")
        }
        do {
            let _ = try domain.subtractPoints(p1, p2)
            XCTFail("Expected ECException.notOnCurve")
        } catch ECException.notOnCurve {
        } catch {
            XCTFail("Expected ECException.notOnCurve")
        }
        do {
            let _ = try domain.negatePoint(p1)
            XCTFail("Expected ECException.notOnCurve")
        } catch ECException.notOnCurve {
        } catch {
            XCTFail("Expected ECException.notOnCurve")
        }
        do {
            let _ = try domain.multiplyPoint(p1, BInt.ONE)
            XCTFail("Expected ECException.notOnCurve")
        } catch ECException.notOnCurve {
        } catch {
            XCTFail("Expected ECException.notOnCurve")
        }
    }
    
    func testECDHParameter() {
        let domain1 = Domain.instance(curve: .BP256r1)
        let domain2 = Domain.instance(curve: .EC256r1)
        let (pub1, priv1) = domain1.makeKeyPair()
        let (pub2, _) = domain2.makeKeyPair()
        do {
            // Different domains
            let _ = try priv1.keyAgreement(pubKey: pub2, length: 20, md: .SHA2_256, sharedInfo: [])
            XCTFail("Expected ECException.keyAgreementParameter")
        } catch ECException.keyAgreementParameter {
        } catch {
            XCTFail("Expected ECException.keyAgreementParameter")
        }
        do {
            // Length is negative
            let _ = try priv1.keyAgreement(pubKey: pub1, length: -20, md: .SHA2_256, sharedInfo: [])
            XCTFail("Expected ECException.keyAgreementParameter")
        } catch ECException.keyAgreementParameter {
        } catch {
            XCTFail("Expected ECException.keyAgreementParameter")
        }
        do {
            // Length is too large
            let _ = try priv1.keyAgreement(pubKey: pub1, length: 32 * 0xffffffff, md: .SHA2_256, sharedInfo: [])
            XCTFail("Expected ECException.keyAgreementParameter")
        } catch ECException.keyAgreementParameter {
        } catch {
            XCTFail("Expected ECException.keyAgreementParameter")
        }
    }

}
