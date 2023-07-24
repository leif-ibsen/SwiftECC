//
//  AEAD.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 22/06/2023.
//

import CryptoKit

struct AEADStructure {

    let aead: AEAD
    
    init(_ aead: AEAD) {
        self.aead = aead
    }

    func seal(_ key: Bytes, _ nonce: Bytes, _ aad: Bytes, _ pt: Bytes) throws -> Bytes {
        switch self.aead {
        case .AESGCM128, .AESGCM256:
            let cryptoKitKey = CryptoKit.SymmetricKey(data: key)
            let cryptoKitNonce = try CryptoKit.AES.GCM.Nonce(data: nonce)
            let sealbox = try CryptoKit.AES.GCM.seal(pt, using: cryptoKitKey, nonce: cryptoKitNonce, authenticating: aad)
            return Bytes(sealbox.ciphertext + sealbox.tag)

        case .CHACHAPOLY:
            let cryptoKitKey = CryptoKit.SymmetricKey(data: key)
            let cryptoKitNonce = try CryptoKit.ChaChaPoly.Nonce(data: nonce)
            let sealbox = try CryptoKit.ChaChaPoly.seal(pt, using: cryptoKitKey, nonce: cryptoKitNonce, authenticating: aad)
            return Bytes(sealbox.ciphertext + sealbox.tag)
            
        case .EXPORTONLY:
            throw HPKEException.exportOnlyError
        }
    }

    func open(_ key: Bytes, _ aad: Bytes, _ ct: Bytes) throws -> Bytes {
        let cryptoKitKey = CryptoKit.SymmetricKey(data: key)
        switch self.aead {
        case .AESGCM128, .AESGCM256:
            return try Bytes(CryptoKit.AES.GCM.open(CryptoKit.AES.GCM.SealedBox(combined: ct), using: cryptoKitKey, authenticating: aad))

        case .CHACHAPOLY:
            return try Bytes(CryptoKit.ChaChaPoly.open(ChaChaPoly.SealedBox(combined: ct), using: cryptoKitKey, authenticating: aad))
        
        case .EXPORTONLY:
            throw HPKEException.exportOnlyError
        }
    }

}
