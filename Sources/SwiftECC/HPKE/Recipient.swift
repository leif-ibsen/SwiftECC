//
//  HPKE.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 19/06/2023.
//

///
/// Based on its CipherSuite, a Recipient instance can decrypt a sequence of messages in one of four modes:
///<ul>
///<li>Base mode</li>
///<li>Preshared key mode</li>
///<li>Authenticated mode</li>
///<li>Authenticated, preshared key mode</li>
///</ul>
/// The decryption of the messages must be done in the order in which they were encrypted
public class Recipient {
    
    let suite: CipherSuite
    let info: Bytes
    var key: Bytes = []
    var base_nonce: Bytes = []
    var nonce: Bytes = []
    var exporter_secret: Bytes = []


    // MARK: Initializers

    /// Creates a Recipient instance in base mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Recipient
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - encap: The encapsulated key
    /// - Throws: An exception if one of the keys does not match *suite*
    public init(suite: CipherSuite, privateKey: HPKEPrivateKey, info: Bytes, encap: Bytes) throws {
        try suite.checkPrivKey(privateKey)
        try suite.checkPubKey(HPKEPublicKey(kem: suite.kem, bytes: encap))
        self.suite = suite
        self.info = info
        let sharedSecret = try self.suite.kemStructure.decap(encap, privateKey)
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.BASE, sharedSecret, self.info, [], [])
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Recipient instance in preshared key mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Recipient
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Throws: An exception if one of the keys does not match *suite*
    public init(suite: CipherSuite, privateKey: HPKEPrivateKey, info: Bytes, psk: Bytes, pskId: Bytes, encap: Bytes) throws {
        try suite.checkPrivKey(privateKey)
        try suite.checkPubKey(HPKEPublicKey(kem: suite.kem, bytes: encap))
        guard CipherSuite.checkPsk(psk, pskId) else {
            throw HPKEException.pskError
        }
        self.suite = suite
        self.info = info
        let sharedSecret = try self.suite.kemStructure.decap(encap, privateKey)
        (self.key, self.base_nonce, self.exporter_secret) = suite.keySchedule(HPKE.PSK, sharedSecret, self.info, psk, pskId)
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Recipient instance in authenticated mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Recipient
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - authentication: The sender public key
    ///   - encap: The encapsulated key
    /// - Throws: An exception if one of the keys does not match *suite*
    public init(suite: CipherSuite, privateKey: HPKEPrivateKey, info: Bytes, authentication: HPKEPublicKey, encap: Bytes) throws {
        try suite.checkPrivKey(privateKey)
        try suite.checkPubKey(authentication)
        try suite.checkPubKey(HPKEPublicKey(kem: suite.kem, bytes: encap))
        self.suite = suite
        self.info = info
        let sharedSecret = try self.suite.kemStructure.authDecap(encap, privateKey, authentication)
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.AUTH, sharedSecret, self.info, [], [])
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Recipient instance in authenticated, preshared key mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Recipient
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Throws: An exception if one of the keys does not match *suite*
    public init(suite: CipherSuite, privateKey: HPKEPrivateKey, info: Bytes, authentication: HPKEPublicKey, psk: Bytes, pskId: Bytes, encap: Bytes) throws {
        try suite.checkPrivKey(privateKey)
        try suite.checkPubKey(authentication)
        try suite.checkPubKey(HPKEPublicKey(kem: suite.kem, bytes: encap))
        guard CipherSuite.checkPsk(psk, pskId) else {
            throw HPKEException.pskError
        }
        self.suite = suite
        self.info = info
        let sharedSecret = try self.suite.kemStructure.authDecap(encap, privateKey, authentication)
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.AUTH_PSK, sharedSecret, self.info, psk, pskId)
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }


    // MARK: Instance Methods

    /// Decrypts a message
    ///
    /// - Parameters:
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    /// - Returns: The plain text
    /// - Throws: An exception if decryption fails or *self.suite.aead* is EXPORTONLY
    public func open(ct: Bytes, aad: Bytes) throws -> Bytes {
        return try self.suite.aeadStructure.open(self.key, aad, computeNonce() + ct)
    }

    /// Compute an export secret
    ///
    /// - Parameters:
    ///   - context: The export context
    ///   - L: The length of the export secret
    /// - Returns: The export secret
    /// - Throws: An exception if L is negative or too large
    public func exportSecret(context: Bytes, L: Int) throws -> Bytes {
        try self.suite.checkExportSize(L)
        return self.suite.kdfStructure.labeledExpand(self.exporter_secret, Bytes("sec".utf8), context, L)
    }

    func computeNonce() -> Bytes {
        var x = self.base_nonce
        for i in 0 ..< self.nonce.count {
            x[i] ^= self.nonce[i]
        }
        for i in (0 ..< self.nonce.count).reversed() {
            self.nonce[i] &+= 1
            if self.nonce[i] > 0 {
                break
            }
        }
        return x
    }

}
