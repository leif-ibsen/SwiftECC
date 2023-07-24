//
//  PrivateKey.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 02/07/2023.
//

import BigInt

///
/// A HPKE private key. There are five different private keys types corresponding to the five KEM's
///<ul>
///<li>P256 - the key is a 32 byte value corresponding to curve EC256r1 private key</li>
///<li>P384 - the key is a 48 byte value corresponding to curve EC384r1 private key</li>
///<li>P521 - the key is a 66 byte value corresponding to curve EC521r1 private key</li>
///<li>X25519 - the key is a 32 byte value corresponding to curve X25519 private key</li>
///<li>X448 - the key is a 56 byte value corresponding to curve X448 private key</li>
///</ul>
public class HPKEPrivateKey: CustomStringConvertible {
    
    let kem: KEM

    // MARK: Initializers

    /// Creates a HPKEPrivateKey corresponding to an ECPrivateKey which must be of type EC256r1, EC384r1 or EC521r1
    ///
    /// - Parameters:
    ///   - ecKey: The ECPrivateKey
    /// - Throws: An exception if *ecKey* has wrong type
    public convenience init(ecKey: ECPrivateKey) throws {
        let bytes = ecKey.s.asMagnitudeBytes()
        let name = ecKey.domain.name
        if name == "secp256r1" {
            try self.init(kem: .P256, bytes: bytes)
        } else if name == "secp384r1" {
            try self.init(kem: .P384, bytes: bytes)
        } else if name == "secp521r1" {
            try self.init(kem: .P521, bytes: bytes)
        } else {
            throw HPKEException.privateKeyParameter
        }
    }

    /// Creates a HPKEPrivateKey from its type and key bytes
    ///
    /// - Parameters:
    ///   - kem: The key type
    ///   - bytes: The key bytes
    /// - Throws: An exception if *bytes* has wrong size for the key type
    public init(kem: KEM, bytes: Bytes) throws {
        var x = bytes
        self.kem = kem
        switch self.kem {
        case .P256:
            guard bytes.count <= 32 else {
                throw HPKEException.privateKeyParameter
            }
            while x.count < 32 {
                x.insert(0, at: 0)
            }
            self.bytes = x
            self.ecKey = try ECPrivateKey(domain: KEMStructure.CurveP256, s: BInt(magnitude: self.bytes))
            self.publicKey = try HPKEPublicKey(ecKey: ECPublicKey(privateKey: ecKey!))
        case .P384:
            guard bytes.count <= 48 else {
                throw HPKEException.privateKeyParameter
            }
            while x.count < 48 {
                x.insert(0, at: 0)
            }
            self.bytes = x
            self.ecKey = try ECPrivateKey(domain: KEMStructure.CurveP384, s: BInt(magnitude: self.bytes))
            self.publicKey = try HPKEPublicKey(ecKey: ECPublicKey(privateKey: ecKey!))
        case .P521:
            guard bytes.count <= 66 else {
                throw HPKEException.privateKeyParameter
            }
            while x.count < 66 {
                x.insert(0, at: 0)
            }
            self.bytes = x
            self.ecKey = try ECPrivateKey(domain: KEMStructure.CurveP521, s: BInt(magnitude: self.bytes))
            self.publicKey = try HPKEPublicKey(ecKey: ECPublicKey(privateKey: ecKey!))
        case .X25519:
            guard bytes.count == 32 else {
                throw HPKEException.privateKeyParameter
            }
            x[0] &= 0xf8
            x[31] &= 0x7f
            x[31] |= 0x40
            self.bytes = x
            self.ecKey = nil
            self.publicKey = try HPKEPublicKey(kem: .X25519, bytes: KEMStructure.CurveX25519.X25519(self.bytes, KEMStructure._9))
        case .X448:
            guard bytes.count == 56 else {
                throw HPKEException.privateKeyParameter
            }
            x[0] &= 0xfc
            x[55] |= 0x80
            self.bytes = x
            self.ecKey = nil
            self.publicKey = try HPKEPublicKey(kem: .X448, bytes: KEMStructure.CurveX448.X448(self.bytes, KEMStructure._5))
        }
    }


    // MARK: Stored Properties
    
    /// The serialized key bytes
    public let bytes: Bytes
    /// The equivalent ECPrivateKey if the key type is P256, P384 or P521, else *nil*
    public let ecKey: ECPrivateKey?
    /// The corresponding public key
    public let publicKey: HPKEPublicKey
    
    
    // MARK: Computed Properties
    
    /// A textual representation of *self*<br/>
    /// For P256, P384 and P521 the ASN1 representation<br/>
    /// For X25519 32 hexadecimal bytes<br/>
    /// For X448 56 hexadecimal bytes<br/>
    public var description: String { get {
        switch self.kem {
        case .P256, .P384, .P521:
            return self.ecKey!.description
        case .X25519:
            return HPKEPublicKey.bytes2hex(self.bytes, 32)
        case .X448:
            return HPKEPublicKey.bytes2hex(self.bytes, 56)
        } }
    }

}
