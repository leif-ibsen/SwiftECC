//
//  EciesAESGCMTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 05/12/2022.
//

import XCTest
@testable import SwiftECC
import BigInt // for SecRandomCopyBytes

final class EciesAESGCMTest: XCTestCase {

    let message = Bytes("The quick brown fox jumps over the lazy dog".utf8)
    let aad = Bytes("This is the Additional Authenticated Data".utf8)

    func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }

    func doTest1(_ pub: ECPublicKey, _ priv: ECPrivateKey, _ cipher: AESCipher) {
        do {
            let encrypted = pub.encryptAESGCM(msg: [], cipher: cipher, aad: [])
            let decrypted = try priv.decryptAESGCM(msg: encrypted, cipher: cipher, aad: [])
            XCTAssertEqual([], decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encryptAESGCM(msg: message, cipher: cipher, aad: [])
            let decrypted = try priv.decryptAESGCM(msg: encrypted, cipher: cipher, aad: [])
            XCTAssertEqual(message, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encryptAESGCM(msg: [], cipher: cipher, aad: aad)
            let decrypted = try priv.decryptAESGCM(msg: encrypted, cipher: cipher, aad: aad)
            XCTAssertEqual([], decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encryptAESGCM(msg: message, cipher: cipher, aad: aad)
            let decrypted = try priv.decryptAESGCM(msg: encrypted, cipher: cipher, aad: aad)
            XCTAssertEqual(message, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            var randomMessage = Bytes(repeating: 0, count: 1000)
            randomBytes(&randomMessage)
            var randomAAD = Bytes(repeating: 0, count: 100)
            randomBytes(&randomAAD)
            let encrypted = pub.encryptAESGCM(msg: randomMessage, cipher: cipher, aad: randomAAD)
            let decrypted = try priv.decryptAESGCM(msg: encrypted, cipher: cipher, aad: randomAAD)
            XCTAssertEqual(randomMessage, decrypted)
        } catch {
            XCTFail("\(error)")
        }
    }

    func test() {
        for c in ECCurve.allCases {
            let (pub, priv) = Domain.instance(curve: c).makeKeyPair()
            for cipher in AESCipher.allCases {
                doTest1(pub, priv, cipher)
            }
        }
    }

}
