//
//  TestHPKEExceptions.swift
//  
//
//  Created by Leif Ibsen on 10/07/2023.
//

import XCTest
@testable import SwiftECC

final class HPKEExceptionTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testPublicKeySize() throws {
        let keyBytes = Bytes(repeating: 1, count: 16)
        do {
            let _ = try HPKEPublicKey(kem: .P256, bytes: keyBytes)
            XCTFail("Expected publicKeyParameter exceptio")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
    }

    func testPrivateKeySize() throws {
        let keyBytes = Bytes(repeating: 1, count: 16)
        do {
            let _ = try HPKEPrivateKey(kem: .X448, bytes: keyBytes)
            XCTFail("Expected privateKeyParameter exceptio")
        } catch HPKEException.privateKeyParameter {
        } catch {
            XCTFail("Expected privateKeyParameter exception")
        }
    }
    
    func testPublicKeyDomain() throws {
        let domain = Domain.instance(curve: .BP160r1)
        let (ecKey, _) = domain.makeKeyPair()
        do {
            let _ = try HPKEPublicKey(ecKey: ecKey)
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
    }

    func testPrivateKeyDomain() throws {
        let domain = Domain.instance(curve: .BP160r1)
        let (_, ecKey) = domain.makeKeyPair()
        do {
            let _ = try HPKEPrivateKey(ecKey: ecKey)
            XCTFail("Expected privateKeyParameter exception")
        } catch HPKEException.privateKeyParameter {
        } catch {
            XCTFail("Expected privateKeyParameter exception")
        }
    }

    func testPskError() throws {
        let suite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)
        let (pub, priv) = try suite.makeKeyPair()
        do {
            let _ = try Sender(suite: suite, publicKey: pub, info: [], authentication: priv, psk: [], pskId: [])
            let _ = try Sender(suite: suite, publicKey: pub, info: [], authentication: priv, psk: [1], pskId: [1])
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try Sender(suite: suite, publicKey: pub, info: [], authentication: priv, psk: [1], pskId: [])
            XCTFail("Expected pskError exception")
        } catch HPKEException.pskError {
        } catch {
            XCTFail("Expected pskError exception")
        }
        do {
            let _ = try Sender(suite: suite, publicKey: pub, info: [], authentication: priv, psk: [], pskId: [1])
            XCTFail("Expected pskError exception")
        } catch HPKEException.pskError {
        } catch {
            XCTFail("Expected pskError exception")
        }
    }
    
    func testKeyMismatch() throws {
        let suite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)
        let (ecPub, _) = Domain.instance(curve: .EC384r1).makeKeyPair()
        do {
            let pub = try HPKEPublicKey(ecKey: ecPub)
            let _ = try Sender(suite: suite, publicKey: pub, info: [])
            XCTFail("Expected keyMismatch exception")
        } catch HPKEException.keyMismatch {
        } catch {
            XCTFail("Expected keyMismatch exception")
        }
    }

    func testExportOnly() throws {
        let suite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .EXPORTONLY)
        do {
            let (pub, _) = try suite.makeKeyPair()
            let _ = try suite.seal(publicKey: pub, info: [], pt: [], aad: [])
            XCTFail("Expected exportOnlyError exception")
        } catch HPKEException.exportOnlyError {
        } catch {
            XCTFail("Expected exportOnlyError exception")
        }
    }

    func doTestExportSize(_ kdf: KDF, _ kdfSize: Int) throws {
        let suite = CipherSuite(kem: .P256, kdf: kdf, aead: .CHACHAPOLY)
        let (pub, _) = try suite.makeKeyPair()
        do {
            let _ = try suite.exportSecret(publicKey: pub, info: [], context: [], L: 0)
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try suite.exportSecret(publicKey: pub, info: [], context: [], L: kdfSize * 255)
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try suite.exportSecret(publicKey: pub, info: [], context: [], L: -1)
            XCTFail("Expected exportSize exception")
        } catch HPKEException.exportSize {
        } catch {
            XCTFail("Expected exportSize exception")
        }
        do {
            let _ = try suite.exportSecret(publicKey: pub, info: [], context: [], L: kdfSize * 255 + 1)
            XCTFail("Expected exportSize exception")
        } catch HPKEException.exportSize {
        } catch {
            XCTFail("Expected exportSize exception")
        }
    }

    func testExportSize() throws {
        try doTestExportSize(.KDF256, 32)
        try doTestExportSize(.KDF384, 48)
        try doTestExportSize(.KDF512, 64)
    }

}
