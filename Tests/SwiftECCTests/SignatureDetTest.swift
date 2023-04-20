//
//  SignatureDetTest.swift
//  SwiftECCTests
//
//  Created by Leif Ibsen on 19/02/2020.
//

import XCTest
@testable import SwiftECC
import BigInt

class SignatureDetTest: XCTestCase {
    
    // RFC 6979 test vectors

    let text = Bytes("sample".utf8)

    func doTest(_ c: ECCurve, _ x: String, _ r: String, _ s: String) throws {
        let domain = Domain.instance(curve: c)
        let X = BInt(x, radix: 16)!
        let privKey = try ECPrivateKey(domain: domain, s: X)
        let pubKey = try ECPublicKey(domain: domain, w: domain.multiplyG(X))
        let signature = privKey.sign(msg: text, deterministic: true)
        XCTAssertEqual((domain.p.bitWidth + 7) / 8, signature.r.count)
        XCTAssertEqual((domain.p.bitWidth + 7) / 8, signature.s.count)
        XCTAssert(pubKey.verify(signature: signature, msg: text))
        XCTAssertEqual(BInt(r, radix: 16), BInt(magnitude: signature.r))
        XCTAssertEqual(BInt(s, radix: 16), BInt(magnitude: signature.s))
    }

    func test163k1() throws {
        let x = "09a4d6792295a7f730fc3f2b49cbc0f62e862272f"
        let rSHA224 = "38a2749f7ea13bd5da0c76c842f512d5a65ffaf32"
        let sSHA224 = "064f841f70112b793fd773f5606bfa5ac2a04c1e8"
        try doTest(.EC163k1, x, rSHA224, sSHA224)
    }
    
    func test163r2() throws {
        let x = "35318fc447d48d7e6bc93b48617dddedf26aa658f"
        let rSHA224 = "0a379e69c44f9c16ea3215ea39eb1a9b5d58cc955"
        let sSHA224 = "04baff5308da2a7fe2c1742769265ad3ed1d24e74"
        try doTest(.EC163r2, x, rSHA224, sSHA224)
    }

    func test192r1() throws {
        let x = "6fab034934e4c0fc9ae67f5b5659a9d7d1fefd187ee09fd4"
        let rSHA224 = "a1f00dad97aeec91c95585f36200c65f3c01812aa60378f5"
        let sSHA224 = "e07ec1304c7c6c9debbe980b9692668f81d4de7922a0f97a"
        try doTest(.EC192r1, x, rSHA224, sSHA224)
    }

    func test224r1() throws {
        let x = "f220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1"
        let rSHA224 = "1cdfe6662dde1e4a1ec4cdedf6a1f5a2fb7fbd9145c12113e6abfd3e"
        let sSHA224 = "a6694fd7718a21053f225d3f46197ca699d45006c06f871808f43ebc"
        try doTest(.EC224r1, x, rSHA224, sSHA224)
    }

    func test233k1() throws {
        let x = "103b2142bdc2a3c3b55080d09df1808f79336da2399f5ca7171d1be9b0"
        let rSHA256 = "38ad9c1d2cb29906e7d63c24601ac55736b438fb14f4093d6c32f63a10"
        let sSHA256 = "647aad2599c21b6ee89be7ff957d98f684b7921de1fd3cc82c079624f4"
        try doTest(.EC233k1, x, rSHA256, sSHA256)
    }

    func test233r1() throws {
        let x = "07adc13dd5bf34d1ddeeb50b2ce23b5f5e6d18067306d60c5f6ff11e5d3"
        let rSHA256 = "0a797f3b8aefce7456202df1e46ccc291ea5a49da3d4bdda9a4b62d5e0d"
        let sSHA256 = "01f6f81da55c22da4152134c661588f4bd6f82fdbaf0c5877096b070dc2"
        try doTest(.EC233r1, x, rSHA256, sSHA256)
    }

    func test256r1() throws {
        let x = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
        let rSHA256 = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        let sSHA256 = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        try doTest(.EC256r1, x, rSHA256, sSHA256)
    }

    func test283k1() throws {
        let x = "06a0777356e87b89ba1ed3a3d845357be332173c8f7a65bdc7db4fab3c4cc79acc8194e"
        let rSHA384 = "0f8c1ca9c221ad9907a136f787d33ba56b0495a40e86e671c940fd767edd75eb6001a49"
        let sSHA384 = "1071a56915dee89e22e511975aa09d00cdc4aa7f5054cbe83f5977ee6f8e1cc31ec43fd"
        try doTest(.EC283k1, x, rSHA384, sSHA384)
    }

    func test283r1() throws {
        let x = "14510d4bc44f2d26f4553942c98073c1bd35545ceabb5cc138853c5158d2729ea408836"
        let rSHA384 = "2f00689c1bfcd2a8c7a41e0de55ae182e6463a152828ef89fe3525139b6603294e69353"
        let sSHA384 = "1744514fe0a37447250c8a329eaaada81572226caba16f39270ee5dd03f27b1f665eb5d"
        try doTest(.EC283r1, x, rSHA384, sSHA384)
    }

    func test384r1() throws {
        let x = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5"
        let rSHA384 = "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46"
        let sSHA384 = "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8"
        try doTest(.EC384r1, x, rSHA384, sSHA384)
    }
    
    func test409k1() throws {
        let x = "29c16768f01d1b8a89fda85e2efd73a09558b92a178a2931f359e4d70ad853e569cdaf16daa569758fb4e73089e4525d8bbfcf"
        let rSHA512 = "16c7e7fb33b5577f7cf6f77762f0f2d531c6e7a3528bd2cf582498c1a48f200789e9df7b754029da0d7e3ce96a2dc760932606"
        let sSHA512 = "2729617efbf80da5d2f201ac7910d3404a992c39921c2f65f8cf4601392dfe933e6457eafdbd13dfe160d243100378b55c290a"
        try doTest(.EC409k1, x, rSHA512, sSHA512)
    }

    func test409r1() throws {
        let x = "0494994cc325b08e7b4ce038bd9436f90b5e59a2c13c3140cd3ae07c04a01fc489f572ce0569a6db7b8060393de76330c624177"
        let rSHA512 = "05d178decafd2d02a3da0d8ba1c4c1d95ee083c760df782193a9f7b4a8be6fc5c21fd60613bca65c063a61226e050a680b3abd4"
        let sSHA512 = "013b7581e98f6a63fbbcb3e49bcda60f816db230b888506d105dc229600497c3b46588c784be3aa9343bef82f7c9c80aeb63c3b"
        try doTest(.EC409r1, x, rSHA512, sSHA512)
    }

    func test521r1() throws {
        let x = "0fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538"
        let rSHA512 = "0c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa"
        let sSHA512 = "0617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a"
        try doTest(.EC521r1, x, rSHA512, sSHA512)
    }
    
    func test571k1() throws {
        let x = "0c16f58550d824ed7b95569d4445375d3a490bc7e0194c41a39deb732c29396cdf1d66de02dd1460a816606f3bec0f32202c7bd18a32d87506466aa92032f1314ed7b19762b0d22"
        let rSHA512 = "086c9e048eadd7d3d2908501086f3af449a01af6beb2026dc381b39530bcddbe8e854251cbd5c31e6976553813c11213e4761cb8ca2e5352240ad9fb9c635d55fab13ae42e4ee4f"
        let sSHA512 = "09fee0a68f322b380217fcf6abff15d78c432bd8dd82e18b6ba877c01c860e24410f5150a44f979920147826219766ecb4e2e11a151b6a15bb8e2e825ac95bcca228d8a1c9d3568"
        try doTest(.EC571k1, x, rSHA512, sSHA512)
    }

    func test571r1() throws {
        let x = "028a04857f24c1c082df0d909c0e72f453f2e2340ccb071f0e389bca2575da19124198c57174929ad26e348cf63f78d28021ef5a9bf2d5cbeaf6b7ccb6c4da824dd5c82cfb24e11"
        let rSHA512 = "1c26f40d940a7eaa0eb1e62991028057d91feda0366b606f6c434c361f04e545a6a51a435e26416f6838ffa260c617e798e946b57215284182be55f29a355e6024fe32a47289cf0"
        let sSHA512 = "3691de4369d921fe94edda67cb71fbbec9a436787478063eb1cc778b3dcdc1c4162662752d28deedf6f32a269c82d1db80c87ce4d3b662e03ac347806e3f19d18d6d4de7358df7e"
        try doTest(.EC571r1, x, rSHA512, sSHA512)
    }


}
