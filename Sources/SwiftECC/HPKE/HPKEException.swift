//
//  Exception.swift
//  SwiftECC
//
//  Created by Leif Ibsen on 18/02/2020.
//

///
/// Elliptic curve exceptions
///
public enum HPKEException: Error, CustomStringConvertible {
    
    /// Textual description of *self*
    public var description: String {
        switch self {
        case .smallOrder:
            return "X25519, X448 small order error"
        case .pskError:
            return "Inconsistent PSK parameters"
        case .privateKeyParameter:
            return "Invalid parameter to HPKEPrivateKey constructor"
        case .publicKeyParameter:
            return "Invalid parameter to HPKEPublicKey constructor"
        case .keyMismatch:
            return "CipherSuite key mismatch"
        case .derivedKeyError:
            return "Derived key error"
        case .exportOnlyError:
            return "Export only error"
        case .exportSize:
            return "Export size is negative or too large"
        }
    }
        
    /// Derived key error
    case derivedKeyError

    /// Export only error
    case exportOnlyError

    /// Export size is negative or too large
    case exportSize

    /// CipherSuite key mismatch
    case keyMismatch

    /// Invalid parameter to HPKEPrivateKey constructor
    case privateKeyParameter

    /// Inconsistent PSK parameters
    case pskError

    /// Invalid parameter to HPKEPublicKey constructor
    case publicKeyParameter

    /// X25519, X448 small order error
    case smallOrder

}
