//
//  EciesChaChaTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 04/04/2022.
//

import XCTest
@testable import SwiftECC
import BigInt // for SecRandomCopyBytes

class EciesChaChaTest: XCTestCase {

    let message = Bytes("The quick brown fox jumps over the lazy dog".utf8)
    let aad = Bytes("This is the Additional Authenticated Data".utf8)

    func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }

    func doTest1(_ pub: ECPublicKey, _ priv: ECPrivateKey) {
        do {
            let encrypted = pub.encryptChaCha(msg: [], aad: [])
            let decrypted = try priv.decryptChaCha(msg: encrypted, aad: [])
            XCTAssertEqual([], decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encryptChaCha(msg: message, aad: [])
            let decrypted = try priv.decryptChaCha(msg: encrypted, aad: [])
            XCTAssertEqual(message, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encryptChaCha(msg: [], aad: aad)
            let decrypted = try priv.decryptChaCha(msg: encrypted, aad: aad)
            XCTAssertEqual([], decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encryptChaCha(msg: message, aad: aad)
            let decrypted = try priv.decryptChaCha(msg: encrypted, aad: aad)
            XCTAssertEqual(message, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            var randomMessage = Bytes(repeating: 0, count: 1000)
            randomBytes(&randomMessage)
            var randomAAD = Bytes(repeating: 0, count: 100)
            randomBytes(&randomAAD)
            let encrypted = pub.encryptChaCha(msg: randomMessage, aad: randomAAD)
            let decrypted = try priv.decryptChaCha(msg: encrypted, aad: randomAAD)
            XCTAssertEqual(randomMessage, decrypted)
        } catch {
            XCTFail("\(error)")
        }
    }

    func test() {
        for c in ECCurve.allCases {
            let (pub, priv) = Domain.instance(curve: c).makeKeyPair()
            doTest1(pub, priv)
        }
    }

}
