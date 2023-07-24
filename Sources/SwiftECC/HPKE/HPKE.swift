//
//  HPKE.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 19/06/2023.
//

///
/// Key Encapsulation Mechanisms
///
public enum KEM: CustomStringConvertible {
    
    /// Textual description of *self*
    public var description: String {
        switch self {
        case .P256:
            return "P256"
        case .P384:
            return "P384"
        case .P521:
            return "P521"
        case .X25519:
            return "X25519"
        case .X448:
            return "X448"
        }
    }

    /// P256 - HKDF-SHA256
    case P256
    /// P384 - HKDF-SHA384
    case P384
    /// P521 - HKDF-SHA512
    case P521
    /// X25519 - HKDF-SHA256
    case X25519
    /// X448 - HKDF-SHA512
    case X448
}

///
/// Key Derivation Functions
///
public enum KDF: CustomStringConvertible {
    
    /// Textual description of *self*
    public var description: String {
        switch self {
        case .KDF256:
            return "HKDF-SHA256"
        case .KDF384:
            return "HKDF-SHA384"
        case .KDF512:
            return "HKDF-SHA512"
        }
    }

    /// HKDF-SHA256
    case KDF256
    /// HKDF-SHA384
    case KDF384
    /// HKDF-SHA512
    case KDF512
}

///
/// AEAD Encryption Algorithms
///
public enum AEAD: CustomStringConvertible {

    /// Textual description of *self*
    public var description: String {
        switch self {
        case .AESGCM128:
            return "AES-128-GCM"
        case .AESGCM256:
            return "AES-256-GCM"
        case .CHACHAPOLY:
            return "ChaCha20-Poly1305"
        case .EXPORTONLY:
            return "Export Only"
        }
    }

    /// AES-128-GCM
    case AESGCM128
    /// AES-256-GCM
    case AESGCM256
    /// ChaCha20-Poly1305
    case CHACHAPOLY
    /// Export Only
    case EXPORTONLY
}

///
/// A CipherSuite instance is a HPKE element consisting of a *Key Encapsulation Mechanism* (KEM), a *Key Derivation Function* (KDF)
/// and a *AEAD Encryption Algorithm* (AEAD).
/// It can encrypt or decrypt a single message in one of four modes:
///<ul>
///<li>Base mode</li>
///<li>Preshared key mode</li>
///<li>Authenticated mode</li>
///<li>Authenticated, preshared key mode</li>
///</ul>
public class CipherSuite: CustomStringConvertible {

    let kemStructure: KEMStructure
    let kdfStructure: KDFStructure
    let aeadStructure: AEADStructure
    let suite_id: Bytes
    let Nk: Int
    let Nn: Int
    let Nh: Int


    // MARK: Initializers
    
    /// Creates a CipherSuite instance
    ///
    /// - Parameters:
    ///   - kem: The key encapsulation mechanism
    ///   - kdf: The key derivation function
    ///   - aead: The AEAD encryption algorithm
    public init(kem: KEM, kdf: KDF, aead: AEAD) {
        var id = Bytes("HPKE".utf8)
        self.kem = kem
        self.kdf = kdf
        self.aead = aead
        switch self.kem {
        case .P256:
            id += [0x00, 0x10]
        case .P384:
            id += [0x00, 0x11]
        case .P521:
            id += [0x00, 0x12]
        case .X25519:
            id += [0x00, 0x20]
        case .X448:
            id += [0x00, 0x21]
        }
        switch self.kdf {
        case .KDF256:
            id += [0x00, 0x01]
            self.Nh = 32
        case .KDF384:
            id += [0x00, 0x02]
            self.Nh = 48
        case .KDF512:
            id += [0x00, 0x03]
            self.Nh = 64
        }
        switch self.aead {
        case .AESGCM128:
            id += [0x00, 0x01]
            self.Nk = 16
        case .AESGCM256:
            id += [0x00, 0x02]
            self.Nk = 32
        case .CHACHAPOLY:
            id += [0x00, 0x03]
            self.Nk = 32
        case .EXPORTONLY:
            id += [0xff, 0xff]
            self.Nk = 0
        }
        self.Nn = 12
        self.suite_id = id
        self.kemStructure = KEMStructure(kem)
        self.kdfStructure = KDFStructure(kdf, self.suite_id)
        self.aeadStructure = AEADStructure(aead)
    }
    

    // MARK: Stored Properties
    
    /// The key encapsulation mechanism
    public let kem: KEM
    /// The key derivation function
    public let kdf: KDF
    /// The AEAD encryption algorithm
    public let aead: AEAD


    // MARK: Computed properties

    /// A textual representation of *self*
    public var description: String { get { return "(KEM:" + self.kem.description + " KDF:" + self.kdf.description + " AEAD:" + self.aead.description + ")"} }


    // MARK: Instance Methods
    
    /// Derives a public- and private HPKE key pair for *self* based on keying material
    ///
    /// - Parameters:
    ///   - ikm: The keying material
    /// - Returns: The public key and private key pair
    /// - Throws: A *derivedKeyError* exception in extremely rare cases
    public func deriveKeyPair(ikm: Bytes) throws -> (HPKEPublicKey, HPKEPrivateKey) {
        return try self.kemStructure.deriveKeyPair(ikm)
    }

    /// Generates a public- and private HPKE key pair for *self*
    ///
    /// - Returns: The public key and private key pair
    /// - Throws: A *derivedKeyError* exception in extremely rare cases
    public func makeKeyPair() throws -> (HPKEPublicKey, HPKEPrivateKey) {
        var ikm = Bytes(repeating: 0, count: self.kemStructure.Nsk)
        KEMStructure.randomBytes(&ikm)
        return try self.deriveKeyPair(ikm: ikm)
    }


    // MARK: Instance Methods - base mode

    /// Single-shot encryption
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulated key and cipher text
    /// - Throws: An exception if *publicKey* does not match *self* or the encryption fails or *self.aead* is EXPORTONLY
    public func seal(publicKey: HPKEPublicKey, info: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption
    ///
    /// - Parameters:
    ///   - privateKey:The recipient private key
    ///   - info: The additional information
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or *self.aead* is EXPORTONLY
    public func open(privateKey: HPKEPrivateKey, info: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Compute a sender export secret
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if *publicKey* does not match *self* or L is negative or too large

    public func exportSecret(publicKey: HPKEPublicKey, info: Bytes, context: Bytes, L: Int) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        let (sharedSecret, encap) = try self.kemStructure.encap(publicKey, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Compute a recipient export secret
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or L is negative or too large
    public func exportSecret(privateKey: HPKEPrivateKey, info: Bytes, context: Bytes, L: Int, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        let sharedSecret = try self.kemStructure.decap(encap, privateKey)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }


    // MARK: Instance Methods - preshared key mode

    /// Single-shot encryption
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if *publicKey* does not match *self* or the encryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func seal(publicKey: HPKEPublicKey, info: Bytes, psk: Bytes, pskId: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, psk: psk, pskId: pskId)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption
    ///
    /// - Parameters:
    ///   - privateKey:The recipient private key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func open(privateKey: HPKEPrivateKey, info: Bytes, psk: Bytes, pskId: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, psk: psk, pskId: pskId, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Compute a sender export secret
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if *publicKey* does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func exportSecret(publicKey: HPKEPublicKey, info: Bytes, context: Bytes, L: Int, psk: Bytes, pskId: Bytes) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        let (sharedSecret, encap) = try self.kemStructure.encap(publicKey, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Compute a recipient export secret
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func exportSecret(privateKey: HPKEPrivateKey, info: Bytes, context: Bytes, L: Int, psk: Bytes, pskId: Bytes, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        let sharedSecret = try self.kemStructure.decap(encap, privateKey)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }


    // MARK: Instance Methods - authenticated mode

    /// Single-shot encryption
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - authentication: The sender private key
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if one of the keys does not match *self* or the encryption fails or *self.aead* is EXPORTONLY
    public func seal(publicKey: HPKEPublicKey, info: Bytes, authentication: HPKEPrivateKey, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, authentication: authentication)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - authentication: The sender public key
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or *self.aead* is EXPORTONLY
    public func open(privateKey: HPKEPrivateKey, info: Bytes, authentication: HPKEPublicKey, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, authentication: authentication, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Compute a sender export secret
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender private key
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if one of the keys does not match *self* or L is negative or too large
    public func exportSecret(publicKey: HPKEPublicKey, info: Bytes, context: Bytes, L: Int, authentication: HPKEPrivateKey) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        try self.checkPrivKey(authentication)
        let (sharedSecret, encap) = try self.kemStructure.authEncap(publicKey, authentication, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Compute a recipient export secret
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or L is negative or too large
    public func exportSecret(privateKey: HPKEPrivateKey, info: Bytes, context: Bytes, L: Int, authentication: HPKEPublicKey, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        try self.checkPubKey(authentication)
        let sharedSecret = try self.kemStructure.authDecap(encap, privateKey, authentication)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }


    // MARK: Instance Methods - authenticated, preshared key mode

    /// Single-shot encryption
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - authentication: The sender private key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if one of the keys does not match *self* or the encryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func seal(publicKey: HPKEPublicKey, info: Bytes, authentication: HPKEPrivateKey, psk: Bytes, pskId: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, authentication: authentication, psk: psk, pskId: pskId)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func open(privateKey: HPKEPrivateKey, info: Bytes, authentication: HPKEPublicKey, psk: Bytes, pskId: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, authentication: authentication, psk: psk, pskId: pskId, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Compute a sender export secret
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender private key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if one of the keys does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func exportSecret(publicKey: HPKEPublicKey, info: Bytes, context: Bytes, L: Int, authentication: HPKEPrivateKey, psk: Bytes, pskId: Bytes) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        try self.checkPrivKey(authentication)
        let (sharedSecret, encap) = try self.kemStructure.authEncap(publicKey, authentication, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Compute a recipient export secret
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func exportSecret(privateKey: HPKEPrivateKey, info: Bytes, context: Bytes, L: Int, authentication: HPKEPublicKey, psk: Bytes, pskId: Bytes, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        try self.checkPubKey(authentication)
        let sharedSecret = try self.kemStructure.authDecap(encap, privateKey, authentication)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }

    func keySchedule(_ mode: Byte, _ sharedSecret: Bytes, _ info: Bytes, _ psk: Bytes, _ pskId: Bytes) -> (key: Bytes, base_nonce: Bytes, exporter_secret: Bytes) {
        let psk_id_hash = self.kdfStructure.labeledExtract([], Bytes("psk_id_hash".utf8), pskId)
        let info_hash = self.kdfStructure.labeledExtract([], Bytes("info_hash".utf8), info)
        let key_schedule_context = [mode] + psk_id_hash + info_hash
        let secret = self.kdfStructure.labeledExtract(sharedSecret, Bytes("secret".utf8), psk)
        let key = self.aead == .EXPORTONLY ? [] : self.kdfStructure.labeledExpand(secret, Bytes("key".utf8), key_schedule_context, self.Nk)
        let base_nonce = self.aead == .EXPORTONLY ? [] : self.kdfStructure.labeledExpand(secret, Bytes("base_nonce".utf8), key_schedule_context, self.Nn)
        let exporter_secret = self.kdfStructure.labeledExpand(secret, Bytes("exp".utf8), key_schedule_context, self.Nh)
        return (key, base_nonce, exporter_secret)
    }
    
    func checkExportSize(_ L: Int) throws {
        if L < 0 || L > 255 * self.Nh {
            throw HPKEException.exportSize
        }
    }

    func checkPubKey(_ key: HPKEPublicKey) throws {
        if self.kem != key.kem {
            throw HPKEException.keyMismatch
        }
    }

    func checkPrivKey(_ key: HPKEPrivateKey) throws {
        if self.kem != key.kem {
            throw HPKEException.keyMismatch
        }
    }

    static func checkPsk(_ psk: Bytes, _ pskId: Bytes) -> Bool {
        return (psk.count == 0 && pskId.count == 0) || (psk.count > 0 && pskId.count > 0)
    }

}

struct HPKE {
    static let BASE = Byte(0x00)
    static let PSK = Byte(0x01)
    static let AUTH = Byte(0x02)
    static let AUTH_PSK = Byte(0x03)
}
