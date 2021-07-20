//
//  VerifyTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 11/07/2021.
//

import XCTest
import BigInt

class VerifyTest: XCTestCase {

    // Test vectors from the Wycheproof project
    
    // BP224r1
    let BP224r1KeyPem1 = "-----BEGIN PUBLIC KEY-----\nMFIwFAYHKoZIzj0CAQYJKyQDAwIIAQEFAzoABFcuq3N20FLfxAkj2yU0LqnL/OS4\nWB4QSkyPN8lKcA7F3AWkgbK2lTIMbxrS3YYoYzzbdakSRcJl\n-----END PUBLIC KEY-----"
    let BP224r1KeyPem2 = "-----BEGIN PUBLIC KEY-----\nMFIwFAYHKoZIzj0CAQYJKyQDAwIIAQEFAzoABMw1KsSKrLZJXsODGyHM1NMZcTYp\nK/byDyKAJWZkMhmR5n99vCJgLsvbMSLtzl/4XZIxQ87MDU9t\n-----END PUBLIC KEY-----"
    let BP224r1Message = "313233343030"
    let BP224r1Signature1 = "cb68ac9765c7641785df237e9951e1429581879af2631460048961d3139c78243a6e36e124d5f5e14b4cb8754abdf20ff1a501d5666a428f"
    let BP224r1Signature2 = "01a329e1418c0aca9daff753a40f22dcdb669843e66041d103aa30f57200c424bc85ebd52fa505423a442a8443238658ca3b7c39bace3f3d5110"
    let BP224r1Signature9 = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    let BP224r1Signature10 = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    let BP224r1Signature11 = "00000000000000000000000000000000000000000000000000000000d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f"
    let BP224r1Signature15 = "00000000000000000000000000000000000000000000000000000000d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c100"
    let BP224r1Signature16 = "0000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000"
    let BP224r1Signature94 = "0000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000003"
    let BP224r1Signature95 = "0103"
    let BP224r1Signature96 = "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a793a000000000000000000000000000000000000000000000000000000003"

    // EC256r1
    let EC256r1KeyPem1 = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKSexBRK64+3c/kZ4KBKLrSkDJpkZ\n9whgacjE32xzKDjHeHlk6qwA5ZIfsUmKYPRgZ2az2WhQAVWNGpdOc0FRPg==\n-----END PUBLIC KEY-----"
    let EC256r1Message1 = "313233343030"
    let EC256r1Message58 = "3639383139"
    let EC256r1Message59 = "343236343739373234"
    let EC256r1Signature1 = "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76"
    let EC256r1Signature2 = "012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf536900b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db"
    let EC256r1Signature10 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    let EC256r1Signature11 = "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    let EC256r1Signature58 = "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b"
    let EC256r1Signature59 = "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9"
         
    // EC384r1
    let EC384r1KeyPem1 = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELaV92hCJJ2pUP5/9rAv/DZdsrXHrcoDn\n2b/Z/uS9svIPR/+IgnQ4l3LZjMV1ITiqS20FTWnc8+JexJ34cHFeNIg7GDYZfXb4\nrZYuePZXG7x0B7DWCR+eTYjwFCdEBhdP\n-----END PUBLIC KEY-----"
    let EC384r1Message1 = "313233343030"
    let EC384r1Message58 = "3133323237"
    let EC384r1Message59 = "31373530353531383135"
    let EC384r1Signature1 = "12b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d71840da9fc1d2f8f8900cf485d5413b8c2574ee3a8d4ca03995ca30240e09513805bf6209b58ac7aa9cff54eecd82b9f1"
    let EC384r1Signature2 = "0112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19a25617aad7485e6312a8589714f647acf7a94cffbe8a724a00e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82"
    let EC384r1Signature9 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    let EC384r1Signature10 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    let EC384r1Signature11 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    let EC384r1Signature58 = "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cdf565684bd770d3ee4beadbabe7ca46e8c4702783435228d46e2dd360e322fe61c86926fa49c8116ec940f72ac8c30d9beb3e12f"
    let EC384r1Signature59 = "d3298a0193c4316b34e3833ff764a82cff4ef57b5dd79ed6237b51ff76ceab13bf92131f41030515b7e012d2ba857830bfc7518d2ad20ed5f58f3be79720f1866f7a23b3bd1bf913d3916819d008497a071046311d3c2fd05fc284c964a39617"
    
    // EC521r1
    let EC521r1KeyPem1 = "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAXGRX7AiNUy9IIJOWWuU8zQflVu1Z\n4q+UXNjHqVwcZE+KVqioo813OS3dhh6Kkk2smcaQaQk71SpS+mxWAEoHRQgAeHjW\n1C5LTdHpwGlss+GfYwM8PbTmDUcyWbPr4Hmq8KmG7mF3+CF6eMaLgT9+FJpOVv2V\nYsB/7T2JWULX0QHLg/Y=\n-----END PUBLIC KEY-----"
    let EC521r1Message1 = "313233343030"
    let EC521r1Message58 = "39353032"
    let EC521r1Message59 = "33393439313934313732"
    let EC521r1Signature1 = "004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd515720b0ec5cd736f9b73bdf864501d74a2f6d95be8d4cb64f02d16d6b785a1246b4ebd206dc596818bb953253245f5a27a24a1aae1e218fdccd8cd7d4990b666d4bf4902b84fdad123f941fe906d948"
    let EC521r1Signature2 = "024e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbe97b3367122fa4a20584c271233f3ec3b7f7b31b0faa4d340b92a6b0d5cd17ea4e0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1"
    let EC521r1Signature56 = "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    let EC521r1Signature57 = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    let EC521r1Signature58 = "00b4b10646a668c385e1c4da613eb6592c0976fc4df843fc446f20673be5ac18c7d8608a943f019d96216254b09de5f20f3159402ced88ef805a4154f780e093e0440065cd4e7f2d8b752c35a62fc11a4ab745a91ca80698a226b41f156fb764b79f4d76548140eb94d2c477c0a9be3e1d4d1acbf9cf449701c10bd47c2e3698b3287934"
    let EC521r1Signature59 = "01209e6f7b6f2f764261766d4106c3e4a43ac615f645f3ef5c7139651e86e4a177f9c2ab68027afbc6784ccb78d05c258a8b9b18fb1c0f28be4d024da90738fbd37401ade5d2cb6bf79d80583aeb11ac3254fc151fa363305508a0f121457d00911f8f5ef6d4ec27460d26f3b56f4447f434ff9abe6a91e5055e7fe7707345e562983d64"
           

    func string2Bytes(_ string: String) -> Bytes {
        return BInt(string, radix: 16)!.asMagnitudeBytes()
    }

    func string2Signature(_ string: String) -> ECSignature {
        let n = string.lengthOfBytes(using: .utf8)
        var r = ""
        var s = ""
        var i = 0
        for c in string {
            if i < n / 2 {
                r += String(c)
            } else {
                s += String(c)
            }
            i += 1
        }
        return ECSignature(r: BInt(r, radix: 16)!.asMagnitudeBytes(), s: BInt(s, radix: 16)!.asMagnitudeBytes())
    }

    func doTest(_ key: ECPublicKey, _ message: String, _ sig: String, _ ok: Bool) throws {
        XCTAssertEqual(key.verify(signature: string2Signature(sig), msg: string2Bytes(message)), ok)
    }

    func testBP224r1() throws {
        let key1 = try ECPublicKey(pem: BP224r1KeyPem1)
        try doTest(key1, BP224r1Message, BP224r1Signature1, true)
        try doTest(key1, BP224r1Message, BP224r1Signature2, false)
        try doTest(key1, BP224r1Message, BP224r1Signature9, false)
        try doTest(key1, BP224r1Message, BP224r1Signature10, false)
        try doTest(key1, BP224r1Message, BP224r1Signature11, false)
        try doTest(key1, BP224r1Message, BP224r1Signature15, false)
        try doTest(key1, BP224r1Message, BP224r1Signature16, false)
        let key2 = try ECPublicKey(pem: BP224r1KeyPem2)
        try doTest(key2, BP224r1Message, BP224r1Signature94, true)
        try doTest(key2, BP224r1Message, BP224r1Signature95, true)
        try doTest(key2, BP224r1Message, BP224r1Signature96, false)
    }

    func testEC256r1() throws {
        let key1 = try ECPublicKey(pem: EC256r1KeyPem1)
        try doTest(key1, EC256r1Message1, EC256r1Signature1, true)
        try doTest(key1, EC256r1Message1, EC256r1Signature2, false)
        try doTest(key1, EC256r1Message1, EC256r1Signature10, false)
        try doTest(key1, EC256r1Message1, EC256r1Signature11, false)
        try doTest(key1, EC256r1Message58, EC256r1Signature58, true)
        try doTest(key1, EC256r1Message59, EC256r1Signature59, true)
    }
    
    func testEC384r1() throws {
        let key1 = try ECPublicKey(pem: EC384r1KeyPem1)
        try doTest(key1, EC384r1Message1, EC384r1Signature1, true)
        try doTest(key1, EC384r1Message1, EC384r1Signature2, false)
        try doTest(key1, EC384r1Message1, EC384r1Signature9, false)
        try doTest(key1, EC384r1Message1, EC384r1Signature10, false)
        try doTest(key1, EC384r1Message1, EC384r1Signature11, false)
        try doTest(key1, EC384r1Message58, EC384r1Signature58, true)
        try doTest(key1, EC384r1Message59, EC384r1Signature59, true)
    }

    func testEC521r1() throws {
        let key1 = try ECPublicKey(pem: EC521r1KeyPem1)
        try doTest(key1, EC521r1Message1, EC521r1Signature1, true)
        try doTest(key1, EC521r1Message1, EC521r1Signature2, false)
        try doTest(key1, EC521r1Message1, EC521r1Signature56, false)
        try doTest(key1, EC521r1Message1, EC521r1Signature57, false)
        try doTest(key1, EC521r1Message58, EC521r1Signature58, true)
        try doTest(key1, EC521r1Message59, EC521r1Signature59, true)
    }

}
