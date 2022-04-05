//
//  EciesTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest

class EciesTest: XCTestCase {

    let message = Bytes("The quick brown fox jumps over the lazy dog".utf8)
    let data: Data = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!

    func doTest1(_ cipher: AESCipher, _ mode: BlockMode, _ pub: ECPublicKey, _ priv: ECPrivateKey) {
        do {
            let encrypted = pub.encrypt(msg: message, cipher: cipher, mode: mode)
            let decrypted = try priv.decrypt(msg: encrypted, cipher: cipher, mode: mode)
            XCTAssertEqual(message, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encrypt(msg: [], cipher: cipher, mode: mode)
            let decrypted = try priv.decrypt(msg: encrypted, cipher: cipher, mode: mode)
            XCTAssertEqual([], decrypted)
        } catch {
            XCTFail("\(error)")
        }
    }

    func doTest2(_ cipher: AESCipher, _ mode: BlockMode, _ pub: ECPublicKey, _ priv: ECPrivateKey) {
        do {
            let encrypted = pub.encrypt(msg: data, cipher: cipher, mode: mode)
            let decrypted = try priv.decrypt(msg: encrypted, cipher: cipher, mode: mode)
            XCTAssertEqual(data, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        do {
            let encrypted = pub.encrypt(msg: Data(), cipher: cipher, mode: mode)
            let decrypted = try priv.decrypt(msg: encrypted, cipher: cipher, mode: mode)
            XCTAssertEqual(Data(), decrypted)
        } catch {
            XCTFail("\(error)")
        }
    }

    func doTest3(_ cipher: AESCipher, _ mode: BlockMode, _ pub: ECPublicKey, _ priv: ECPrivateKey) {
        var random = SystemRandomNumberGenerator()
        var b = Bytes(repeating: 0, count: 199)
        for i in 0 ..< b.count {
            b[i] = random.next()
        }
        do {
            let encrypted = pub.encrypt(msg: b, cipher: cipher, mode: mode)
            let decrypted = try priv.decrypt(msg: encrypted, cipher: cipher, mode: mode)
            XCTAssertEqual(b, decrypted)
        } catch {
            XCTFail("\(error)")
        }
        let d: Data = Data(b)
        do {
            let encrypted = pub.encrypt(msg: d, cipher: cipher, mode: mode)
            let decrypted = try priv.decrypt(msg: encrypted, cipher: cipher, mode: mode)
            XCTAssertEqual(d, decrypted)
        } catch {
            XCTFail("\(error)")
        }
    }

    func doTest(_ c: ECCurve) {
        let (pub, priv) = Domain.instance(curve: c).makeKeyPair()
        for aes in AESCipher.allCases {
            for mode in BlockMode.allCases {
                doTest1(aes, mode, pub, priv)
                doTest2(aes, mode, pub, priv)
                doTest3(aes, mode, pub, priv)
            }
        }
    }

    func test() {
        for c in ECCurve.allCases {
            doTest(c)
        }
    }

}
