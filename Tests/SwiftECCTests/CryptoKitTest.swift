//
//  CryptoKitTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 27/01/2022.
//

import XCTest
@testable import SwiftECC
import CryptoKit
import Digest

// Test compatibility with Swift CryptoKit
class CryptoKitTest: XCTestCase {

    static let message = "The quick brown fox jumps over the lazy dog!".data(using: .utf8)!

    // SwiftECC uses Base64 line size = 76
    // CryptoKit uses Base64 line size = 64
    // Convert from SwiftECC size to CryptoKit size
    func from76to64(_ s: String) -> String {
        return Base64.pemEncode(Base64.pemDecode(s, "PUBLIC KEY")!, "PUBLIC KEY", 64)
    }

    // CryptoKit signs, SwiftECC verifies
    func doTest256A() throws {
        let domain = Domain.instance(curve: .EC256r1)
        let ckPrivKey = P256.Signing.PrivateKey()
        let eccPubKey = try ECPublicKey(pem: ckPrivKey.publicKey.pemRepresentation)
        let ckSignature = try ckPrivKey.signature(for: CryptoKitTest.message)
        let rs = ckSignature.withUnsafeBytes({return Array($0)})
        let eccSignature = ECSignature(domain: domain, r: Bytes(rs[0 ..< 32]), s: Bytes(rs[32 ..< 64]))
        XCTAssertTrue(eccPubKey.verify(signature: eccSignature, msg: CryptoKitTest.message))
    }

    // SwiftECC signs, CryptoKit verifies
    func doTest256B() throws {
        let domain = Domain.instance(curve: .EC256r1)
        let (eccPubKey, eccPrivKey) = domain.makeKeyPair()
        let eccSignature = eccPrivKey.sign(msg: CryptoKitTest.message)
        let ckSignature = try P256.Signing.ECDSASignature(rawRepresentation: eccSignature.r + eccSignature.s)
        let ckPubKey = try P256.Signing.PublicKey(pemRepresentation: from76to64(eccPubKey.pem))
        XCTAssertTrue(ckPubKey.isValidSignature(ckSignature, for: CryptoKitTest.message))
    }

    // CryptoKit signs, SwiftECC verifies
    func doTest384A() throws {
        let domain = Domain.instance(curve: .EC384r1)
        let ckPrivKey = P384.Signing.PrivateKey()
        let eccPubKey = try ECPublicKey(pem: ckPrivKey.publicKey.pemRepresentation)
        let ckSignature = try ckPrivKey.signature(for: CryptoKitTest.message)
        let rs = ckSignature.withUnsafeBytes({return Array($0)})
        let eccSignature = ECSignature(domain: domain, r: Bytes(rs[0 ..< 48]), s: Bytes(rs[48 ..< 96]))
        XCTAssertTrue(eccPubKey.verify(signature: eccSignature, msg: CryptoKitTest.message))
    }

    // SwiftECC signs, CryptoKit verifies
    func doTest384B() throws {
        let domain = Domain.instance(curve: .EC384r1)
        let (eccPubKey, eccPrivKey) = domain.makeKeyPair()
        let signature = eccPrivKey.sign(msg: CryptoKitTest.message)
        let ckSignature = try P384.Signing.ECDSASignature(rawRepresentation: signature.r + signature.s)
        let ckPubKey = try P384.Signing.PublicKey(pemRepresentation: from76to64(eccPubKey.pem))
        XCTAssertTrue(ckPubKey.isValidSignature(ckSignature, for: CryptoKitTest.message))
    }

    // CryptoKit signs, SwiftECC verifies
    func doTest521A() throws {
        let domain = Domain.instance(curve: .EC521r1)
        let ckPrivKey = P521.Signing.PrivateKey()
        let eccPubKey = try ECPublicKey(pem: ckPrivKey.publicKey.pemRepresentation)
        let ckSignature = try ckPrivKey.signature(for: CryptoKitTest.message)
        let rs = ckSignature.withUnsafeBytes({return Array($0)})
        let eccSignature = ECSignature(domain: domain, r: Bytes(rs[0 ..< 66]), s: Bytes(rs[66 ..< 132]))
        XCTAssertTrue(eccPubKey.verify(signature: eccSignature, msg: CryptoKitTest.message))
    }

    // SwiftECC signs, CryptoKit verifies
    func doTest521B() throws {
        let domain = Domain.instance(curve: .EC521r1)
        let (eccPubKey, eccPrivKey) = domain.makeKeyPair()
        let eccSignature = eccPrivKey.sign(msg: CryptoKitTest.message)
        let ckSignature = try P521.Signing.ECDSASignature(rawRepresentation: eccSignature.r + eccSignature.s)
        let ckPubKey = try P521.Signing.PublicKey(pemRepresentation: from76to64(eccPubKey.pem))
        XCTAssertTrue(ckPubKey.isValidSignature(ckSignature, for: CryptoKitTest.message))
    }

    func doECDH256(_ salt: Bytes, _ info: Bytes, _ length: Int) throws {
        let domain = Domain.instance(curve: .EC256r1)
        let (eccPubKey, eccPrivKey) = domain.makeKeyPair()
        let ckPrivKey = P256.KeyAgreement.PrivateKey()
        let ckPubKey = ckPrivKey.publicKey
        
        // CryptoKit public key converted to SwiftECC format
        let eccPubKey2 = try ECPublicKey(pem: ckPubKey.pemRepresentation)

        // SwiftECC public key converted to CryptoKit format
        let pemRep = from76to64(eccPubKey.pem)
        let ckPubKey2 = try P256.KeyAgreement.PublicKey(pemRepresentation: pemRep)

        // Secret computed with CryptoKit keys
        let secret1 = try ckPrivKey.sharedSecretFromKeyAgreement(with: ckPubKey2).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: info, outputByteCount: length).withUnsafeBytes({return Array($0)})

        // Secret computed with SwiftECC keys
        let secret2 = try eccPrivKey.x963KeyAgreement(pubKey: eccPubKey2, length: length, kind: .SHA2_256, sharedInfo: info)
        XCTAssertEqual(secret1, secret2)
        
        // Secret computed with CryptoKit keys
        let secret3 = try ckPrivKey.sharedSecretFromKeyAgreement(with: ckPubKey2).hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: length).withUnsafeBytes({return Array($0)})

        // Secret computed with SwiftECC keys
        let secret4 = try eccPrivKey.hkdfKeyAgreement(pubKey: eccPubKey2, length: length, kind: .SHA2_256, sharedInfo: info, salt: salt)
        XCTAssertEqual(secret3, secret4)
    }

    func doECDH384(_ salt: Bytes, _ info: Bytes, _ length: Int) throws {
        let domain = Domain.instance(curve: .EC384r1)
        let (eccPubKey, eccPrivKey) = domain.makeKeyPair()
        let ckPrivKey = P384.KeyAgreement.PrivateKey()
        let ckPubKey = ckPrivKey.publicKey
        
        // CryptoKit public key converted to SwiftECC format
        let eccPubKey2 = try ECPublicKey(pem: ckPubKey.pemRepresentation)

        // SwiftECC public key converted to CryptoKit format
        let pemRep = from76to64(eccPubKey.pem)
        let ckPubKey2 = try P384.KeyAgreement.PublicKey(pemRepresentation: pemRep)
        
        // Secret computed with CryptoKit keys
        let secret1 = try ckPrivKey.sharedSecretFromKeyAgreement(with: ckPubKey2).x963DerivedSymmetricKey(using: SHA384.self, sharedInfo: info, outputByteCount: length).withUnsafeBytes({return Array($0)})

        // Secret computed with SwiftECC keys
        let secret2 = try eccPrivKey.x963KeyAgreement(pubKey: eccPubKey2, length: length, kind: .SHA2_384, sharedInfo: info)
        XCTAssertEqual(secret1, secret2)
        
        // Secret computed with CryptoKit keys
        let secret3 = try ckPrivKey.sharedSecretFromKeyAgreement(with: ckPubKey2).hkdfDerivedSymmetricKey(using: SHA384.self, salt: salt, sharedInfo: info, outputByteCount: length).withUnsafeBytes({return Array($0)})

        // Secret computed with SwiftECC keys
        let secret4 = try eccPrivKey.hkdfKeyAgreement(pubKey: eccPubKey2, length: length, kind: .SHA2_384, sharedInfo: info, salt: salt)
        XCTAssertEqual(secret3, secret4)
    }

    func doECDH521(_ salt: Bytes, _ info: Bytes, _ length: Int) throws {
        let domain = Domain.instance(curve: .EC521r1)
        let (eccPubKey, eccPrivKey) = domain.makeKeyPair()
        let ckPrivKey = P521.KeyAgreement.PrivateKey()
        let ckPubKey = ckPrivKey.publicKey
        
        // CryptoKit public key converted to SwiftECC format
        let eccPubKey2 = try ECPublicKey(pem: ckPubKey.pemRepresentation)

        // SwiftECC public key converted to CryptoKit format
        let pemRep = from76to64(eccPubKey.pem)
        let ckPubKey2 = try P521.KeyAgreement.PublicKey(pemRepresentation: pemRep)

        // Secret computed with CryptoKit keys
        let secret1 = try ckPrivKey.sharedSecretFromKeyAgreement(with: ckPubKey2).x963DerivedSymmetricKey(using: SHA512.self, sharedInfo: info, outputByteCount: length).withUnsafeBytes({return Array($0)})

        // Secret computed with SwiftECC keys
        let secret2 = try eccPrivKey.x963KeyAgreement(pubKey: eccPubKey2, length: length, kind: .SHA2_512, sharedInfo: info)
        XCTAssertEqual(secret1, secret2)
        
        // Secret computed with CryptoKit keys
        let secret3 = try ckPrivKey.sharedSecretFromKeyAgreement(with: ckPubKey2).hkdfDerivedSymmetricKey(using: SHA512.self, salt: salt, sharedInfo: info, outputByteCount: length).withUnsafeBytes({return Array($0)})

        // Secret computed with SwiftECC keys
        let secret4 = try eccPrivKey.hkdfKeyAgreement(pubKey: eccPubKey2, length: length, kind: .SHA2_512, sharedInfo: info, salt: salt)
        XCTAssertEqual(secret3, secret4)
    }

    func doECDH(_ salt: Bytes, _ info: Bytes, _ length: Int) throws {
        try doECDH256(salt, info, length)
        try doECDH384(salt, info, length)
        try doECDH521(salt, info, length)
    }

    func testECDH() throws {
        try doECDH([1], [], 1000)
        try doECDH([1], [], 32)
        try doECDH([1], [], 1)
        try doECDH([1], [1, 2, 3], 1000)
        try doECDH([1], [1, 2, 3], 32)
        try doECDH([1], [1, 2, 3], 1)
        try doECDH([1], Bytes(repeating: 1, count: 1000), 1000)
        try doECDH([1], Bytes(repeating: 1, count: 1000), 32)
        try doECDH([1], Bytes(repeating: 1, count: 1000), 1)
    }

    func testSignature() throws {
        for _ in 0 ..< 10 {
            try doTest256A()
            try doTest256B()
            try doTest384A()
            try doTest384B()
            try doTest521A()
            try doTest521B()
        }
    }

    func testConversion() throws {
        let d256 = Domain.instance(curve: .EC256r1)
        let (pub256, _) = d256.makeKeyPair()
        let ckPubKey256 = try P256.KeyAgreement.PublicKey(pemRepresentation: from76to64(pub256.pem))
        let pub1 = try ECPublicKey(pem: ckPubKey256.pemRepresentation)
        XCTAssertEqual(pub256.domain, pub1.domain)
        XCTAssertEqual(pub256.w, pub1.w)

        let d384 = Domain.instance(curve: .EC384r1)
        let (pub384, _) = d384.makeKeyPair()
        let ckPubKey384 = try P384.KeyAgreement.PublicKey(pemRepresentation: from76to64(pub384.pem))
        let pub2 = try ECPublicKey(pem: ckPubKey384.pemRepresentation)
        XCTAssertEqual(pub384.domain, pub2.domain)
        XCTAssertEqual(pub384.w, pub2.w)

        let d521 = Domain.instance(curve: .EC521r1)
        let (pub521, _) = d521.makeKeyPair()
        let ckPubKey521 = try P521.KeyAgreement.PublicKey(pemRepresentation: from76to64(pub521.pem))
        let pub3 = try ECPublicKey(pem: ckPubKey521.pemRepresentation)
        XCTAssertEqual(pub521.domain, pub3.domain)
        XCTAssertEqual(pub521.w, pub3.w)
    }

}
