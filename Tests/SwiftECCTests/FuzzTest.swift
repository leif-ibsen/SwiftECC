//
//  FuzzTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 16/07/2021.
//

import XCTest
import BigInt
import ASN1

class FuzzTest: XCTestCase {

    // Throw weird input data at some of the methods and see if it crashes
    
    // Multiply a point by a huge number
    func testMultiply() throws {
        let b100000 = BInt.TEN ** 100000
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let n = b100000.randomLessThan()
            
            // n has about 100000 decimal digits
            
            let p = try domain.multiplyPoint(domain.g, n)
            XCTAssertEqual(p, try domain.multiplyPoint(domain.g, n.mod(domain.order)))
        }
    }

    // Decode wrong ASN1 bytes
    func testDecodePoint() throws {
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let asn1 = ASN1OctetString(domain.asn1.encode())
            
            // asn1 describes the domain - not a point
            
            do {
                let _ = try domain.asn1DecodePoint(asn1)
                XCTFail("Expected decodePoint exception")
            } catch ECException.decodePoint {
            } catch {
                XCTFail("Expected decodePoint exception")
            }
        }
    }

    // Decrypt an empty string
    func testDecrypt() throws {
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (_, priv) = domain.makeKeyPair()
            do {
                let _ = try priv.decrypt(msg: [], cipher: .AES128)
                XCTFail("Expected notEnoughInput exception")
            } catch ECException.notEnoughInput {
            } catch {
                XCTFail("Expected notEnoughInput exception")
            }
        }
    }

    // Verify with an empty and a huge signature
    func testVerify() throws {
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let (pub, _) = domain.makeKeyPair()
            XCTAssertFalse(pub.verify(signature: ECSignature(r: [], s: []), msg: [1]))
            XCTAssertFalse(pub.verify(signature: ECSignature(r: Bytes(repeating: 1, count: 100000), s: Bytes(repeating: 1, count: 100000)), msg: [1]))
            XCTAssertFalse(pub.verify(signature: ECSignature(r: [1], s: [1]), msg: []))
            XCTAssertFalse(pub.verify(signature: ECSignature(r: Bytes(repeating: 1, count: 100000), s: Bytes(repeating: 1, count: 100000)), msg: []))
        }
    }
    
    // Test with private key = 1
    func testPrivateKey1() throws {
        let message: Bytes = [1, 2, 3]
        for c in ECCurve.allCases {
            let domain = Domain.instance(curve: c)
            let privKey = try ECPrivateKey(domain: domain, s: BInt.ONE)
            let pubKey = try ECPublicKey(domain: domain, w: domain.g)
            XCTAssertTrue(pubKey.verify(signature: privKey.sign(msg: message), msg: message))
            XCTAssertEqual(message, try privKey.decrypt(msg: pubKey.encrypt(msg: message, cipher: .AES128), cipher: .AES128))
            XCTAssertEqual(message, try privKey.decrypt(msg: pubKey.encrypt(msg: message, cipher: .AES192), cipher: .AES192))
            XCTAssertEqual(message, try privKey.decrypt(msg: pubKey.encrypt(msg: message, cipher: .AES256), cipher: .AES256))
        }
    }


}
