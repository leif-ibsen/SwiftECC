//
//  PrivateKey.swift
//  SwiftECC
//
//  Created by Leif Ibsen on 18/02/2020.
//

import Foundation
import ASN1
import BigInt

///
/// An Elliptic Curve private key
///
public class ECPrivateKey: CustomStringConvertible {
    
    // MARK: Initializers
    
    /// Creates a private key
    ///
    /// - Parameters:
    ///   - domain: The domain the key belongs to
    ///   - s: The secret key value
    /// - Throws: An exception if s < 1 or s >= the domain order
    public init(domain: Domain, s: BInt) throws {
        if s < BInt.ONE || s >= domain.order {
            throw ECException.privateKeyParameter
        }
        self.domain = domain
        self.s = s
    }

    /// Creates a private key from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The DER encoding of the key
    ///   - pkcs8: *true* if the encoding is in PKCS#8 format - else *false*
    /// - Throws: An exception if the DER encoding is wrong
    public convenience init(der: Bytes, pkcs8: Bool = false) throws {
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw ECException.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw ECException.asn1Structure
        }
        var domain: Domain
        var s: BInt
        if pkcs8 {
            guard let seq1 = seq.get(1) as? ASN1Sequence else {
                throw ECException.asn1Structure
            }
            if seq1.getValue().count < 2 {
                throw ECException.asn1Structure
            }
            domain = try Domain.domainFromASN1(seq1.get(1))
            guard let octets = seq.get(2) as? ASN1OctetString else {
                throw ECException.asn1Structure
            }
            guard let seq2 = try ASN1.build(octets.value) as? ASN1Sequence else {
                throw ECException.asn1Structure
            }
            if seq2.getValue().count < 2 {
                throw ECException.asn1Structure
            }
            guard let mag = seq2.get(1) as? ASN1OctetString else {
                throw ECException.asn1Structure
            }
            s = BInt(magnitude: mag.value)
        } else {
            guard let mag = seq.get(1) as? ASN1OctetString else {
                throw ECException.asn1Structure
            }
            guard let ctx = seq.get(2) as? ASN1Ctx else {
                throw ECException.asn1Structure
            }
            guard let d = ctx.value else {
                throw ECException.asn1Structure
            }
            if d.count == 0 {
                throw ECException.asn1Structure
            }
            domain = try Domain.domainFromASN1(d[0])
            s = BInt(magnitude: mag.value)
        }
        try self.init(domain: domain, s: s)
    }
    
    /// Creates a private key from its PEM encoding.
    /// The PEM type is either 'PRIVATE KEY' meaning the format is PKCS#8,
    /// or it is 'EC PRIVATE KEY' meaning the format is not PKCS#8
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public convenience init(pem: String) throws {
        if pem.starts(with: "-----BEGIN PRIVATE KEY") {
            try self.init(der: Base64.pemDecode(pem, "PRIVATE KEY"), pkcs8: true)
        } else {
            try self.init(der: Base64.pemDecode(pem, "EC PRIVATE KEY"), pkcs8: false)
        }
    }

    
    // MARK: Stored Properties
    
    /// The domain the key belongs to
    public let domain: Domain
    /// The private value - a positive integer
    public let s: BInt

    
    // MARK: Computed Properties
    
    /// The ASN1 encoding of *self*
    public var asn1: ASN1 { get { do { return ASN1Sequence().add(ASN1.ONE).add(ASN1OctetString(self.domain.align(self.s.asMagnitudeBytes()))).add(ASN1Ctx(0, [self.domain.asn1])).add(ASN1Ctx(1, [try ASN1BitString(self.domain.encodePoint(self.domain.multiplyG(self.s)), 0)])) } catch { return ASN1.NULL } } }
    /// The DER encoding of *self*
    public var der: Bytes { get { return self.asn1.encode() } }
    /// The PEM base 64 encoding of *self*
    public var pem: String { get { return Base64.pemEncode(self.der, "EC PRIVATE KEY") } }
    /// The DER encoding of *self* in PKCS#8 format
    public var derPkcs8: Bytes { get { return ASN1Sequence()
            .add(ASN1.ZERO)
            .add(ASN1Sequence().add(Domain.OID_EC).add(self.domain.asn1))
            .add(ASN1OctetString(self.asn1.encode())).encode() } }
    /// The PEM base 64 encoding of *self* in PKCS#8 format
    public var pemPkcs8: String { get { return Base64.pemEncode(self.derPkcs8, "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of *self*
    public var description: String { get { return self.asn1.description } }


    // MARK: Instance Methods
    
    /// Signs a byte array message with ECDSA
    ///
    /// - Parameters:
    ///   - msg: The message to sign
    ///   - deterministic: If *true* generate a deterministic signature according to RFC-6979, if *false* generate a non-deterministic signature - *false* is default
    /// - Returns: The signature
    public func sign(msg: Bytes, deterministic: Bool = false) -> ECSignature {
        let md = MessageDigest.instance(self.domain)
        md.update(msg)
        let digest = md.digest()
        let order = self.domain.order
        let k = deterministic ? DeterministicK(md, order, self.s).makeK(digest) : (order - BInt.ONE).randomLessThan() + BInt.ONE
        let R = self.domain.multiplyG(k)
        var h = BInt(magnitude: digest)
        let d = digest.count * 8 - order.bitWidth
        if d > 0 {
            h >>= d
        }
        let r = R.x.mod(order)
        let s = (k.modInverse(order) * (h + r * self.s)).mod(order)
        return ECSignature(domain: domain, r: self.domain.align(r.asMagnitudeBytes()), s: self.domain.align(s.asMagnitudeBytes()))
    }
    
    /// Signs a Data message with ECDSA
    ///
    /// - Parameters:
    ///   - msg: The message to sign
    ///   - deterministic: If *true* generate a deterministic signature according to RFC-6979, if *false* generate a non-deterministic signature - *false* is default
    /// - Returns: The signature
    public func sign(msg: Data, deterministic: Bool = false) -> ECSignature {
        return self.sign(msg: Bytes(msg), deterministic: deterministic)
    }

    /// Decrypts a byte array message with ECIES
    ///
    /// - Parameters:
    ///   - msg: The bytes to decrypt
    ///   - cipher: The AES cipher to use
    ///   - mode: The block mode to use - GCM is default
    /// - Returns: The decrypted message
    /// - Throws: An exception if the message authentication fails or the message is too short
    public func decrypt(msg: Bytes, cipher: AESCipher, mode: BlockMode = .GCM) throws -> Bytes {
        let bwl = 2 * ((self.domain.p.bitWidth + 7) / 8) + 1
        let tagLength = mode == .GCM ? 16 : 32
        if msg.count < bwl + tagLength {
            throw ECException.notEnoughInput
        }
        let R = Bytes(msg[0 ..< bwl])
        let S = try self.domain.multiplyPoint(self.domain.decodePoint(R), self.s).x
        let tag1 = Bytes(msg[msg.count - tagLength ..< msg.count])
        var result = Bytes(msg[bwl ..< msg.count - tagLength])
        let cipher = Cipher.instance(cipher, mode, self.domain.align(S.asMagnitudeBytes()), R)
        let tag2 = try cipher.decrypt(&result)
        if tag1 != tag2 {
            throw ECException.authentication
        }
        return result

    }
    
    /// Decrypts a Data message with ECIES
    ///
    /// - Parameters:
    ///   - msg: The data to decrypt
    ///   - cipher: The AES cipher to use
    ///   - mode: The block mode to use - GCM is default
    /// - Returns: The decrypted message
    /// - Throws: An exception if the message authentication fails or the message is too short
    public func decrypt(msg: Data, cipher: AESCipher, mode: BlockMode = .GCM) throws -> Data {
        return try Data(self.decrypt(msg: Bytes(msg), cipher: cipher, mode: mode))
    }
    
    /// Constructs a shared secret key using Diffie-Hellman key agreement - please refer [SEC 1] section 3.3.1
    ///
    /// - Parameters:
    ///   - pubKey: The other party's public key
    ///   - length: The required length of the shared secret
    ///   - md: The message digest algorithm to use
    ///   - sharedInfo: Information shared with the other party
    ///   - cofactor: Use cofactor version - *false* is default
    /// - Returns: A byte array which is the shared secret key
    /// - Throws: An exception if *this* and *pubKey* do not belong to the same domain or *length* is negative
    public func keyAgreement(pubKey: ECPublicKey, length: Int, md: MessageDigestAlgorithm, sharedInfo: Bytes, cofactor: Bool = false) throws -> Bytes {
        if self.domain != pubKey.domain {
            throw ECException.keyAgreementParameter
        }
        let mda = MessageDigest(md)
        if length >= mda.digestLength * 0xffffffff || length < 0 {
            throw ECException.keyAgreementParameter
        }
        var Z = try self.domain.multiplyPoint(pubKey.w, (cofactor ? self.domain.cofactor : 1) * self.s).x.asMagnitudeBytes()
        Z = self.domain.align(Z)
        
        // [SEC 1] - section 3.6.1

        var k: Bytes = []
        var counter: Bytes = [0, 0, 0, 1]
        let n = length == 0 ? 0 : (length - 1) / mda.digestLength + 1
        for _ in 0 ..< n {
            mda.update(Z)
            mda.update(counter)
            mda.update(sharedInfo)
            k += mda.digest()
            counter[3] &+= 1
            if counter[3] == 0 {
                counter[2] &+= 1
                if counter[2] == 0 {
                    counter[1] &+= 1
                    if counter[1] == 0 {
                        counter[0] &+= 1
                    }
                }
            }
        }
        return Bytes(k[0 ..< length])
    }

}
