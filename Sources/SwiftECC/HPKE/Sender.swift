//
//  HPKE.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 19/06/2023.
//

///
/// Based on its CipherSuite, a Sender instance can encrypt a sequence of messages in one of four modes:
///<ul>
///<li>Base mode</li>
///<li>Preshared key mode</li>
///<li>Authenticated mode</li>
///<li>Authenticated, preshared key mode</li>
///</ul>
public class Sender {

    let suite: CipherSuite
    let info: Bytes
    var key: Bytes = []
    var base_nonce: Bytes = []
    var nonce: Bytes = []
    var exporter_secret: Bytes = []


    // MARK: Initializers

    // Only for use from the testsuite to supply ikm
    init(_ ikm: Bytes, _ suite: CipherSuite, _ publicKey: HPKEPublicKey, _ info: Bytes) throws {
        try suite.checkPubKey(publicKey)
        self.suite = suite
        self.info = info
        let (sharedSecret, enc) = try self.suite.kemStructure.encap(publicKey, ikm)
        self.encapsulatedKey = enc
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.BASE, sharedSecret, self.info, [], [])
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Sender instance in base mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Sender
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    /// - Throws: An exception if *publicKey* does not match *suite*
    public convenience init(suite: CipherSuite, publicKey: HPKEPublicKey, info: Bytes) throws {
        try self.init([], suite, publicKey, info)
    }

    // Only for use from the testsuite to supply ikm
    init(_ ikm: Bytes, _ suite: CipherSuite, _ publicKey: HPKEPublicKey, _ info: Bytes, _ psk: Bytes, _ pskId: Bytes) throws {
        try suite.checkPubKey(publicKey)
        guard CipherSuite.checkPsk(psk, pskId) else {
            throw HPKEException.pskError
        }
        self.suite = suite
        self.info = info
        let (sharedSecret, enc) = try self.suite.kemStructure.encap(publicKey, ikm)
        self.encapsulatedKey = enc
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.PSK, sharedSecret, self.info, psk, pskId)
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Sender instance in preshared key mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Sender
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Throws: An exception if *publicKey* does not match *suite* or the *psk* parameters are inconsistent
    public convenience init(suite: CipherSuite, publicKey: HPKEPublicKey, info: Bytes, psk: Bytes, pskId: Bytes) throws {
        try self.init([], suite, publicKey, info, psk, pskId)
    }

    // Only for use from the testsuite to supply ikm
    init(_ ikm: Bytes, _ suite: CipherSuite, _ publicKey: HPKEPublicKey, _ info: Bytes, _ authentication: HPKEPrivateKey) throws {
        try suite.checkPubKey(publicKey)
        try suite.checkPrivKey(authentication)
        self.suite = suite
        self.info = info
        let (sharedSecret, enc) = try self.suite.kemStructure.authEncap(publicKey, authentication, ikm)
        self.encapsulatedKey = enc
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.AUTH, sharedSecret, self.info, [], [])
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Sender instance in authenticated mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Sender
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - authentication: The sender private key
    /// - Throws: An exception if one of the keys does not match *suite*
    public convenience init(suite: CipherSuite, publicKey: HPKEPublicKey, info: Bytes, authentication: HPKEPrivateKey) throws {
        try self.init([], suite, publicKey, info, authentication)
    }

    // Only for use from the testsuite to supply ikm
    init(_ ikm: Bytes, _ suite: CipherSuite, _ publicKey: HPKEPublicKey, _ info: Bytes, _ authentication: HPKEPrivateKey, _ psk: Bytes, _ pskId: Bytes) throws {
        try suite.checkPubKey(publicKey)
        try suite.checkPrivKey(authentication)
        guard CipherSuite.checkPsk(psk, pskId) else {
            throw HPKEException.pskError
        }
        self.suite = suite
        self.info = info
        let (sharedSecret, enc) = try self.suite.kemStructure.authEncap(publicKey, authentication, ikm)
        self.encapsulatedKey = enc
        (self.key, self.base_nonce, self.exporter_secret) = self.suite.keySchedule(HPKE.AUTH_PSK, sharedSecret, self.info, psk, pskId)
        self.nonce = Bytes(repeating: 0, count: self.base_nonce.count)
    }

    /// Creates a Sender instance in authenticated, preshared key mode
    ///
    /// - Parameters:
    ///   - suite: The CipherSuite of the Sender
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - authentication: The sender private key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Throws: An exception if one of the keys does not match *suite* or the *psk* parameters are inconsistent
    public convenience init(suite: CipherSuite, publicKey: HPKEPublicKey, info: Bytes, authentication: HPKEPrivateKey, psk: Bytes, pskId: Bytes) throws {
        try self.init([], suite, publicKey, info, authentication, psk, pskId)
    }


    // MARK: Stored Properties
    
    /// The encapsulated key
    public let encapsulatedKey: Bytes


    // MARK: Instance Methods
    
    /// Encrypts a message
    ///
    /// - Parameters:
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The cipher text
    /// - Throws: An exception if encryption fails or *self.suite.aead* is EXPORTONLY
    public func seal(pt: Bytes, aad: Bytes) throws -> Bytes {
        return try self.suite.aeadStructure.seal(self.key, computeNonce(), aad, pt)
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
