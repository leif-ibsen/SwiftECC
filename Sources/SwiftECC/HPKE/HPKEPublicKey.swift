//
//  HPKEPublicKey.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 02/07/2023.
//

import BigInt

///
/// A public key. There are five different public keys types corresponding to the five KEM's
///<ul>
///<li>P256 - the key is a 65 byte value corresponding to curve EC256r1 uncompressed public key point</li>
///<li>P384 - the key is a 97 byte value corresponding to curve EC384r1 uncompressed public key point</li>
///<li>P521 - the key is a 133 byte value corresponding to curve EC521r1 uncompressed public key point</li>
///<li>X25519 - the key is a 32 byte value corresponding to curve X25519 public key</li>
///<li>X448 - the key is a 56 byte value corresponding to curve X448 public key</li>
///</ul>
public class HPKEPublicKey: CustomStringConvertible {
    
    let kem: KEM
    
    // MARK: Initializers
    
    /// Creates a HPKEPublicKey corresponding to an ECPublicKey which must be of type EC256r1, EC384r1 or EC521r1
    ///
    /// - Parameters:
    ///   - ecKey: The ECPublicKey
    /// - Throws: An exception if *ecKey* has wrong type
    public init(ecKey: ECPublicKey) throws {
        let domain = ecKey.domain
        if domain.name == "secp256r1" {
            self.kem = .P256
        } else if domain.name == "secp384r1" {
            self.kem = .P384
        } else if domain.name == "secp521r1" {
            self.kem = .P521
        } else {
            throw HPKEException.publicKeyParameter
        }
        self.bytes = try domain.encodePoint(ecKey.w)
        self.ecKey = ecKey
    }
    
    /// Creates a HPKEPublicKey from its type and key bytes
    ///
    /// - Parameters:
    ///   - kem: The key type
    ///   - bytes: The key bytes
    /// - Throws: An exception if *bytes* has wrong size for the key type
    public init(kem: KEM, bytes: Bytes) throws {
        self.bytes = bytes
        self.kem = kem
        switch self.kem {
        case .P256:
            guard bytes.count == 65 else {
                throw HPKEException.publicKeyParameter
            }
            self.ecKey = try ECPublicKey(domain: KEMStructure.CurveP256, w: KEMStructure.CurveP256.decodePoint(bytes))
        case .P384:
            guard bytes.count == 97 else {
                throw HPKEException.publicKeyParameter
            }
            self.ecKey = try ECPublicKey(domain: KEMStructure.CurveP384, w: KEMStructure.CurveP384.decodePoint(bytes))
        case .P521:
            guard bytes.count == 133 else {
                throw HPKEException.publicKeyParameter
            }
            self.ecKey = try ECPublicKey(domain: KEMStructure.CurveP521, w: KEMStructure.CurveP521.decodePoint(bytes))
        case .X25519:
            guard bytes.count == 32 else {
                throw HPKEException.publicKeyParameter
            }
            self.ecKey = nil
            try checkZero()
        case .X448:
            guard bytes.count == 56 else {
                throw HPKEException.publicKeyParameter
            }
            self.ecKey = nil
            try checkZero()
        }
    }
    
    
    // MARK: Stored Properties
    
    /// The serialized key bytes
    public let bytes: Bytes
    /// The equivalent ECPublicKey if the key type is P256, P384 or P521, else *nil*
    public let ecKey: ECPublicKey?
    
    
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

    func checkZero() throws {
        var zz = Byte(0)
        for b in self.bytes {
            zz |= b
        }
        guard zz != 0 else {
            throw HPKEException.smallOrder
        }
    }

    static func bytes2hex(_ b: Bytes, _ n: Int) -> String {
        let x = BInt(magnitude: b)
        var s = x.asString(radix: 16)
        while s.count < n {
            s.insert("0", at: s.startIndex)
        }
        return s
    }
}
