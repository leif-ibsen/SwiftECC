//
//  KEM.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 22/06/2023.
//

import Foundation
import BigInt

struct KEMStructure {
    
    static let CurveP256 = Domain.instance(curve: .EC256r1)
    static let CurveP384 = Domain.instance(curve: .EC384r1)
    static let CurveP521 = Domain.instance(curve: .EC521r1)
    static let CurveX25519 = Curve25519()
    static let CurveX448 = Curve448()

    static let _9: Bytes = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    static let _5: Bytes = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    
    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }
    
    let kem: KEM
    let kdfStructure: KDFStructure
    let Nsecret: Int
    let Nsk: Int
    let Npk: Int
    let bitmask: Byte
    
    init(_ kem: KEM) {
        self.kem = kem
        switch kem {
        case .P256:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x10]
            self.kdfStructure = KDFStructure(.KDF256, suite_id)
            self.Nsecret = 32
            self.Npk = 65
            self.Nsk = 32
            self.bitmask = 0xff
        case .P384:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x11]
            self.kdfStructure = KDFStructure(.KDF256, suite_id)
            self.Nsecret = 48
            self.Npk = 97
            self.Nsk = 48
            self.bitmask = 0xff
        case .P521:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x12]
            self.kdfStructure = KDFStructure(.KDF512, suite_id)
            self.Nsecret = 64
            self.Npk = 133
            self.Nsk = 66
            self.bitmask = 0x01
        case .X25519:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x20]
            self.kdfStructure = KDFStructure(.KDF256, suite_id)
            self.Nsecret = 32
            self.Npk = 32
            self.Nsk = 32
            self.bitmask = 0x00
        case .X448:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x21]
            self.kdfStructure = KDFStructure(.KDF512, suite_id)
            self.Nsecret = 56
            self.Npk = 56
            self.Nsk = 56
            self.bitmask = 0x00
        }
    }
    
    func deriveKeyPair(_ ikm: Bytes) throws -> (pubKey: HPKEPublicKey, privKey: HPKEPrivateKey) {
        let dkp_prk = self.kdfStructure.labeledExtract([], Bytes("dkp_prk".utf8), ikm)
        switch self.kem {
        case .P256:
            var sk = BInt.ZERO
            var counter = 0
            while sk.isZero || sk >= KEMStructure.CurveP256.order {
                if counter > 255 {
                    throw HPKEException.derivedKeyError
                }
                var bytes =  self.kdfStructure.labeledExpand(dkp_prk, Bytes("candidate".utf8), [Byte(counter & 0xff)], self.Nsk)
                bytes[0] &= self.bitmask
                sk = BInt(magnitude: bytes)
                counter += 1
            }
            let ecPrivKey = try ECPrivateKey(domain: KEMStructure.CurveP256, s: sk)
            let ecPubKey = ECPublicKey(privateKey: ecPrivKey)
            let privKey = try HPKEPrivateKey(kem: self.kem, bytes: sk.asMagnitudeBytes())
            let pubKey = try HPKEPublicKey(kem: kem, bytes: try KEMStructure.CurveP256.encodePoint(ecPubKey.w))
            return (pubKey, privKey)
        case .P384:
            var sk = BInt.ZERO
            var counter = 0
            while sk.isZero || sk >= KEMStructure.CurveP384.order {
                if counter > 255 {
                    throw HPKEException.derivedKeyError
                }
                var bytes =  self.kdfStructure.labeledExpand(dkp_prk, Bytes("candidate".utf8), [Byte(counter & 0xff)], self.Nsk)
                bytes[0] &= self.bitmask
                sk = BInt(magnitude: bytes)
                counter += 1
            }
            let ecPrivKey = try ECPrivateKey(domain: KEMStructure.CurveP384, s: sk)
            let ecPubKey = ECPublicKey(privateKey: ecPrivKey)
            let privKey = try HPKEPrivateKey(kem: self.kem, bytes: sk.asMagnitudeBytes())
            let pubKey = try HPKEPublicKey(kem: kem, bytes: KEMStructure.CurveP384.encodePoint(ecPubKey.w))
            return (pubKey, privKey)
        case .P521:
            var sk = BInt.ZERO
            var counter = 0
            while sk.isZero || sk >= KEMStructure.CurveP521.order {
                if counter > 255 {
                    throw HPKEException.derivedKeyError
                }
                var bytes =  self.kdfStructure.labeledExpand(dkp_prk, Bytes("candidate".utf8), [Byte(counter & 0xff)], self.Nsk)
                bytes[0] &= self.bitmask
                sk = BInt(magnitude: bytes)
                counter += 1
            }
            let ecPrivKey = try ECPrivateKey(domain: KEMStructure.CurveP521, s: sk)
            let ecPubKey = ECPublicKey(privateKey: ecPrivKey)
            let privKey = try HPKEPrivateKey(kem: self.kem, bytes: sk.asMagnitudeBytes())
            let pubKey = try HPKEPublicKey(kem: kem, bytes: KEMStructure.CurveP521.encodePoint(ecPubKey.w))
            return (pubKey, privKey)
        case .X25519:
            let sk = self.kdfStructure.labeledExpand(dkp_prk, Bytes("sk".utf8), [], self.Nsk)
            return try (HPKEPublicKey(kem: .X25519, bytes: KEMStructure.CurveX25519.X25519(sk, KEMStructure._9)), HPKEPrivateKey(kem: .X25519, bytes: sk))
        case .X448:
            let sk = self.kdfStructure.labeledExpand(dkp_prk, Bytes("sk".utf8), [], self.Nsk)
            return try (HPKEPublicKey(kem: .X448, bytes: KEMStructure.CurveX448.X448(sk, KEMStructure._5)), HPKEPrivateKey(kem: .X448, bytes: sk))
        }
    }
    
    func generateKeyPair(_ ikm: Bytes) throws  -> (pubKey: HPKEPublicKey, privKey: HPKEPrivateKey) {
        var IKM: Bytes
        if ikm.count > 0 {
            IKM = ikm
        } else {
            IKM = Bytes(repeating: 0, count: self.Nsk)
            KEMStructure.randomBytes(&IKM)
        }
        return try deriveKeyPair(IKM)
    }

    func DH(_ sk: HPKEPrivateKey, _ pk: HPKEPublicKey) throws -> Bytes {
        switch self.kem {
        case .P256, .P384, .P521:
            return try sk.ecKey!.sharedSecret(pubKey: pk.ecKey!)
        case .X25519:
            return try KEMStructure.CurveX25519.X25519(sk.bytes, pk.bytes)
        case .X448:
            return try KEMStructure.CurveX448.X448(sk.bytes, pk.bytes)
        }
    }
    
    func extractAndExpand(_ dh: Bytes, _ kem_context: Bytes) -> Bytes {
        let eae_prk = self.kdfStructure.labeledExtract([], Bytes("eae_prk".utf8), dh)
        return self.kdfStructure.labeledExpand(eae_prk, Bytes("shared_secret".utf8), kem_context, self.Nsecret)
    }
    
    func encap(_ pkR: HPKEPublicKey, _ ikm: Bytes) throws -> (sharedSecret: Bytes, enc: Bytes) {
        let (pkE, skE) = try generateKeyPair(ikm)
        let dh = try DH(skE, pkR)
        let enc = pkE.bytes
        let pkRm = pkR.bytes
        let kem_context = enc + pkRm
        let shared_secret = extractAndExpand(dh, kem_context)
        return (shared_secret, enc)
    }

    func decap(_ enc: Bytes, _ skR: HPKEPrivateKey) throws -> Bytes {
        let pkE = try HPKEPublicKey(kem: self.kem, bytes: enc)
        let dh = try DH(skR, pkE)
        let pkRm = skR.publicKey.bytes
        let kem_context = enc + pkRm
        let shared_secret = extractAndExpand(dh, kem_context)
        return shared_secret
    }

    func authEncap(_ pkR: HPKEPublicKey, _ skS: HPKEPrivateKey, _ ikm: Bytes) throws -> (sharedSecret: Bytes, enc: Bytes) {
        let (pkE, skE) = try generateKeyPair(ikm)
        let dh = try DH(skE, pkR) + DH(skS, pkR)
        let enc = pkE.bytes
        let pkRm = pkR.bytes
        let pkSm = skS.publicKey.bytes
        let kem_context = enc + pkRm + pkSm
        let shared_secret = extractAndExpand(dh, kem_context)
        return (shared_secret, enc)
    }

    func authDecap(_ enc: Bytes, _ skR: HPKEPrivateKey, _ pkS: HPKEPublicKey) throws -> Bytes {
        let pkE = try HPKEPublicKey(kem: self.kem, bytes: enc)
        let dh = try DH(skR, pkE) + DH(skR, pkS)
        let pkRm = skR.publicKey.bytes
        let pkSm = pkS.bytes
        let kem_context = enc + pkRm + pkSm
        let shared_secret = extractAndExpand(dh, kem_context)
        return shared_secret
    }

}
