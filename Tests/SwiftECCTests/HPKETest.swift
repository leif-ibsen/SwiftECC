//
//  TestHPKE.swift
//  
//
//  Created by Leif Ibsen on 06/07/2023.
//

import XCTest
@testable import SwiftECC

// Testcases from RFC 9180

final class HPKETest: XCTestCase {
    
    static func bytes2hex(_ x: Bytes) -> String {
        let hexDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }
    
    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }
    
    let pt = HPKETest.hex2bytes("4265617574792069732074727574682c20747275746820626561757479")
    let info = HPKETest.hex2bytes("4f6465206f6e2061204772656369616e2055726e")
    let aad0 = HPKETest.hex2bytes("436f756e742d30")
    let aad1 = HPKETest.hex2bytes("436f756e742d31")
    let aad2 = HPKETest.hex2bytes("436f756e742d32")
    let aad4 = HPKETest.hex2bytes("436f756e742d34")
    let aad255 = HPKETest.hex2bytes("436f756e742d323535")
    let aad256 = HPKETest.hex2bytes("436f756e742d323536")
    let expCtx = HPKETest.hex2bytes("54657374436f6e74657874")
    let psk = HPKETest.hex2bytes("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
    let psk_id = HPKETest.hex2bytes("456e6e796e20447572696e206172616e204d6f726961")

    struct hpkeTest {
        
        let kem: KEM
        let kdf: KDF
        let aead: AEAD
        let ikm: Bytes
        let pkR: Bytes
        let skR: Bytes
        let pkS: Bytes
        let skS: Bytes
        let enc: Bytes
        let ct0: Bytes
        let ct1: Bytes
        let ct2: Bytes
        let ct4: Bytes
        let ct255: Bytes
        let ct256: Bytes
        let exp1: Bytes
        let exp2: Bytes
        let exp3: Bytes
        
        init(_ kem: KEM, _ kdf: KDF, _ aead: AEAD, _ ikm: String, _ pkR: String, _ skR: String, _ pkS: String, _ skS: String, _ enc: String,
             _ ct0: String, _ ct1: String, _ ct2: String, _ ct4: String, _ ct255: String, _ ct256: String, _ exp1: String, _ exp2: String, _ exp3: String) {
            self.kem = kem
            self.kdf = kdf
            self.aead = aead
            self.ikm = HPKETest.hex2bytes(ikm)
            self.pkR = HPKETest.hex2bytes(pkR)
            self.skR = HPKETest.hex2bytes(skR)
            self.pkS = HPKETest.hex2bytes(pkS)
            self.skS = HPKETest.hex2bytes(skS)
            self.enc = HPKETest.hex2bytes(enc)
            self.ct0 = HPKETest.hex2bytes(ct0)
            self.ct1 = HPKETest.hex2bytes(ct1)
            self.ct2 = HPKETest.hex2bytes(ct2)
            self.ct4 = HPKETest.hex2bytes(ct4)
            self.ct255 = HPKETest.hex2bytes(ct255)
            self.ct256 = HPKETest.hex2bytes(ct256)
            self.exp1 = HPKETest.hex2bytes(exp1)
            self.exp2 = HPKETest.hex2bytes(exp2)
            self.exp3 = HPKETest.hex2bytes(exp3)
        }
    }
    
    let testCases1: [hpkeTest] = [
        // Testcase A1.1
        hpkeTest(.X25519, .KDF256, .AESGCM128,
                 "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
                 "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
                 "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
                 "",
                 "",
                 "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
                 
                 "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
                 "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
                 "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
                 "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
                 "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
                 "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
                 
                 "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
                 "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
                 "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"
                ),
        // Testcase A2.1
        hpkeTest(.X25519, .KDF256, .CHACHAPOLY,
                 "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
                 "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
                 "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
                 "",
                 "",
                 "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
                 "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
                 "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c",
                 "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b",
                 "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16",
                 "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c",
                 "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b",
                 
                 "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e",
                 "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69",
                 "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53"
                ),
        // Testcase A3.1
        hpkeTest(.P256, .KDF256, .AESGCM128,
                 "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
                 "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
                 "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
                 "",
                 "",
                 "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
                 
                 "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
                 "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82",
                 "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec",
                 "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f",
                 "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd",
                 "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2",
                 
                 "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d",
                 "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796",
                 "d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a"
                ),
        // Testcase A4.1
        hpkeTest(.P256, .KDF512, .AESGCM128,
                 "4ab11a9dd78c39668f7038f921ffc0993b368171d3ddde8031501ee1e08c4c9a",
                 "04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd",
                 "3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38",
                 "",
                 "",
                 "0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580",
                 
                 "d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba",
                 "d14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f124e0acc62d",
                 "9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37da4aafa800",
                 "a531c0655342be013bf32112951f8df1da643602f1866749519f5dcb09cc68432579de305a77e6864e862a7600",
                 "be5da649469efbad0fb950366a82a73fefeda5f652ec7d3731fac6c4ffa21a7004d2ab8a04e13621bd3629547d",
                 "62092672f5328a0dde095e57435edf7457ace60b26ee44c9291110ec135cb0e14b85594e4fea11247d937deb62",
                 
                 "a32186b8946f61aeead1c093fe614945f85833b165b28c46bf271abf16b57208",
                 "84998b304a0ea2f11809398755f0abd5f9d2c141d1822def79dd15c194803c2a",
                 "93fb9411430b2cfa2cf0bed448c46922a5be9beff20e2e621df7e4655852edbc"
                ),
        // Testcase A5.1
        hpkeTest(.P256, .KDF256, .CHACHAPOLY,
                 "f1f1a3bc95416871539ecb51c3a8f0cf608afb40fbbe305c0a72819d35c33f1f",
                 "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006",
                 "a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b",
                 "",
                 "",
                 "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",
                 
                 "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b",
                 "f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374",
                 "39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592ff87c3f310c",
                 "bc104a14fbede0cc79eeb826ea0476ce87b9c928c36e5e34dc9b6905d91473ec369a08b1a25d305dd45c6c5f80",
                 "8f2814a2c548b3be50259713c6724009e092d37789f6856553d61df23ebc079235f710e6af3c3ca6eaba7c7c6c",
                 "b45b69d419a9be7219d8c94365b89ad6951caf4576ea4774ea40e9b7047a09d6537d1aa2f7c12d6ae4b729b4d0",
                 
                 "9b13c510416ac977b553bf1741018809c246a695f45eff6d3b0356dbefe1e660",
                 "6c8b7be3a20a5684edecb4253619d9051ce8583baf850e0cb53c402bdcaf8ebb",
                 "477a50d804c7c51941f69b8e32fe8288386ee1a84905fe4938d58972f24ac938"
                ),
        // Testcase A6.1
        hpkeTest(.P521, .KDF512, .AESGCM256,
                 "7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a986688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904",
                 "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64",
                 "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847",
                 "",
                 "",
                 "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0",
                 
                 "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
                 "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256",
                 "142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a",
                 "3bb3a5a07100e5a12805327bf3b152df728b1c1be75a9fd2cb2bf5eac0cca1fb80addb37eb2a32938c7268e3e5",
                 "4f268d0930f8d50b8fd9d0f26657ba25b5cb08b308c92e33382f369c768b558e113ac95a4c70dd60909ad1adc7",
                 "dbbfc44ae037864e75f136e8b4b4123351d480e6619ae0e0ae437f036f2f8f1ef677686323977a1ccbb4b4f16a",
                 
                 "05e2e5bd9f0c30832b80a279ff211cc65eceb0d97001524085d609ead60d0412",
                 "fca69744bb537f5b7a1596dbf34eaa8d84bf2e3ee7f1a155d41bd3624aa92b63",
                 "f389beaac6fcf6c0d9376e20f97e364f0609a88f1bc76d7328e9104df8477013"
                ),
    ]
    let testCases2: [hpkeTest] = [
        // Testcase A1.2
        hpkeTest(.X25519, .KDF256, .AESGCM128,
                 "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b",
                 "9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366",
                 "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd",
                 "",
                 "",
                 "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b",
                 
                 "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea",
                 "49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22cd62437c8ba",
                 "257ca6a08473dc851fde45afd598cc83e326ddd0abe1ef23baa3baa4dd8cde99fce2c1e8ce687b0b47ead1adc9",
                 "a71d73a2cd8128fcccbd328b9684d70096e073b59b40b55e6419c9c68ae21069c847e2a70f5d8fb821ce3dfb1c",
                 "55f84b030b7f7197f7d7d552365b6b932df5ec1abacd30241cb4bc4ccea27bd2b518766adfa0fb1b71170e9392",
                 "c5bf246d4a790a12dcc9eed5eae525081e6fb541d5849e9ce8abd92a3bc1551776bea16b4a518f23e237c14b59",
                 
                 "dff17af354c8b41673567db6259fd6029967b4e1aad13023c2ae5df8f4f43bf6",
                 "6a847261d8207fe596befb52928463881ab493da345b10e1dcc645e3b94e2d95",
                 "8aff52b45a1be3a734bc7a41e20b4e055ad4c4d22104b0c20285a7c4302401cd"
                ),
        // Testcase A2.2
        hpkeTest(.X25519, .KDF256, .CHACHAPOLY,
                 "35706a0b09fb26fb45c39c2f5079c709c7cf98e43afa973f14d88ece7e29c2e3",
                 "13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062",
                 "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879",
                 "",
                 "",
                 "2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04",
                 
                 "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff",
                 "5c3cabae2f0b3e124d8d864c116fd8f20f3f56fda988c3573b40b09997fd6c769e77c8eda6cda4f947f5b704a8",
                 "14958900b44bdae9cbe5a528bf933c5c990dbb8e282e6e495adf8205d19da9eb270e3a6f1e0613ab7e757962a4",
                 "c2a7bc09ddb853cf2effb6e8d058e346f7fe0fb3476528c80db6b698415c5f8c50b68a9a355609e96d2117f8d3",
                 "2414d0788e4bc39a59a26d7bd5d78e111c317d44c37bd5a4c2a1235f2ddc2085c487d406490e75210c958724a7",
                 "c567ae1c3f0f75abe1dd9e4532b422600ed4a6e5b9484dafb1e43ab9f5fd662b28c00e2e81d3cde955dae7e218",
                 
                 "813c1bfc516c99076ae0f466671f0ba5ff244a41699f7b2417e4c59d46d39f40",
                 "2745cf3d5bb65c333658732954ee7af49eb895ce77f8022873a62a13c94cb4e1",
                 "ad40e3ae14f21c99bfdebc20ae14ab86f4ca2dc9a4799d200f43a25f99fa78ae"
                ),
        // Testcase A3.2
        hpkeTest(.P256, .KDF256, .AESGCM128,
                 "2afa611d8b1a7b321c761b483b6a053579afa4f767450d3ad0f84a39fda587a6",
                 "040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1",
                 "438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661",
                 "",
                 "",
                 "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f",
                 
                 "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb",
                 "9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a1073a7102c27",
                 "adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc880dd81cceb7c1d0c7781465b2",
                 "1f4cc9b7013d65511b1f69c050b7bd8bbd5a5c16ece82b238fec4f30ba2400e7ca8ee482ac5253cffb5c3dc577",
                 "cdc541253111ed7a424eea5134dc14fc5e8293ab3b537668b8656789628e45894e5bb873c968e3b7cdcbb654a4",
                 "faf985208858b1253b97b60aecd28bc18737b58d1242370e7703ec33b73a4c31a1afee300e349adef9015bbbfd",
                 
                 "a115a59bf4dd8dc49332d6a0093af8efca1bcbfd3627d850173f5c4a55d0c185",
                 "4517eaede0669b16aac7c92d5762dd459c301fa10e02237cd5aeb9be969430c4",
                 "164e02144d44b607a7722e58b0f4156e67c0c2874d74cf71da6ca48a4cbdc5e0"
                ),
        // Testcase A4.2
        hpkeTest(.P256, .KDF512, .AESGCM128,
                 "c11d883d6587f911d2ddbc2a0859d5b42fb13bf2c8e89ef408a25564893856f5",
                 "043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabdd84d7f45dabfc1f55664b888a7e86d594853a6cccdc9b189b57839cbbe3b90b55873",
                 "bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522",
                 "",
                 "",
                 "04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c35057f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371",
                 
                 "57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a45b9faa88de39e8306da41d4cc",
                 "159d6b4c24bacaf2f5049b7863536d8f3ffede76302dace42080820fa51925d4e1c72a64f87b14291a3057e00a",
                 "bd24140859c99bf0055075e9c460032581dd1726d52cf980d308e9b20083ca62e700b17892bcf7fa82bac751d0",
                 "93ddd55f82e9aaaa3cfc06840575f09d80160b20538125c2549932977d1238dde8126a4a91118faf8632f62cb8",
                 "377a98a3c34bf716581b05a6b3fdc257f245856384d5f2241c8840571c52f5c85c21138a4a81655edab8fe227d",
                 "cc161f5a179831d456d119d2f2c19a6817289c75d1c61cd37ac8a450acd9efba02e0ac00d128c17855931ff69a",
                 
                 "8158bea21a6700d37022bb7802866edca30ebf2078273757b656ef7fc2e428cf",
                 "6a348ba6e0e72bb3ef22479214a139ef8dac57be34509a61087a12565473da8d",
                 "2f6d4f7a18ec48de1ef4469f596aada4afdf6d79b037ed3c07e0118f8723bffc"
                ),
        // Testcase A5.2
        hpkeTest(.P256, .KDF256, .CHACHAPOLY,
                 "e1a4e1d50c4bfcf890f2b4c7d6b2d2aca61368eddc3c84162df2856843e1057a",
                 "041eb8f4f20ab72661af369ff3231a733672fa26f385ffb959fd1bae46bfda43ad55e2d573b880831381d9367417f554ce5b2134fbba5235b44db465feffc6189e",
                 "12ecde2c8bc2d5d7ed2219c71f27e3943d92b344174436af833337c557c300b3",
                 "",
                 "",
                 "04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa805c1fec955e562663e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a7246",
                 
                 "21433eaff24d7706f3ed5b9b2e709b07230e2b11df1f2b1fe07b3c70d5948a53d6fa5c8bed194020bd9df0877b",
                 "c74a764b4892072ea8c2c56b9bcd46c7f1e9ca8cb0a263f8b40c2ba59ac9c857033f176019562218769d3e0452",
                 "dc8cd68863474d6e9cbb6a659335a86a54e036249d41acf909e738c847ff2bd36fe3fcacda4ededa7032c0a220",
                 "cd54a8576353b1b9df366cb0cc042e46eef6f4cf01e205fe7d47e306b2fdd90f7185f289a26c613ca094e3be10",
                 "6324570c9d542c70c7e70570c1d8f4c52a89484746bf0625441890ededcc80c24ef2301c38bfd34d689d19f67d",
                 "1ea6326c8098ed0437a553c466550114fb2ca1412cca7de98709b9ccdf19206e52c3d39180e2cf62b3e9f4baf4",
                 
                 "530bbc2f68f078dccc89cc371b4f4ade372c9472bafe4601a8432cbb934f528d",
                 "6e25075ddcc528c90ef9218f800ca3dfe1b8ff4042de5033133adb8bd54c401d",
                 "6f6fbd0d1c7733f796461b3235a856cc34f676fe61ed509dfc18fa16efe6be78"
                ),
        // Testcase A6.2
        hpkeTest(.P521, .KDF512, .AESGCM256,
                 "f3ebfa9a69a924e672114fcd9e06fa9559e937f7eccce4181a2b506df53dbe514be12f094bb28e01de19dd345b4f7ede5ad7eaa6b9c3019592ec68eaae9a14732ce0",
                 "04006917e049a2be7e1482759fb067ddb94e9c4f7f5976f655088dec45246614ff924ed3b385fc2986c0ecc39d14f907bf837d7306aada59dd5889086125ecd038ead400603394b5d81f89ebfd556a898cc1d6a027e143d199d3db845cb91c5289fb26c5ff80832935b0e8dd08d37c6185a6f77683347e472d1edb6daa6bd7652fea628fae",
                 "011bafd9c7a52e3e71afbdab0d2f31b03d998a0dc875dd7555c63560e142bde264428de03379863b4ec6138f813fa009927dc5d15f62314c56d4e7ff2b485753eb72",
                 "",
                 "",
                 "040085eff0835cc84351f32471d32aa453cdc1f6418eaaecf1c2824210eb1d48d0768b368110fab21407c324b8bb4bec63f042cfa4d0868d19b760eb4beba1bff793b30036d2c614d55730bd2a40c718f9466faf4d5f8170d22b6df98dfe0c067d02b349ae4a142e0c03418f0a1479ff78a3db07ae2c2e89e5840f712c174ba2118e90fdcb",
                 
                 "de69e9d943a5d0b70be3359a19f317bd9aca4a2ebb4332a39bcdfc97d5fe62f3a77702f4822c3be531aa7843a1",
                 "77a16162831f90de350fea9152cfc685ecfa10acb4f7994f41aed43fa5431f2382d078ec88baec53943984553e",
                 "f1d48d09f126b9003b4c7d3fe6779c7c92173188a2bb7465ba43d899a6398a333914d2bb19fd769d53f3ec7336",
                 "829b11c082b0178082cd595be6d73742a4721b9ac05f8d2ef8a7704a53022d82bd0d8571f578c5c13b99eccff8",
                 "a3ee291e20f37021e82df14d41f3fbe98b27c43b318a36cacd8471a3b1051ab12ee055b62ded95b72a63199a3f",
                 "eecc2173ce1ac14b27ee67041e90ed50b7809926e55861a579949c07f6d26137bf9cf0d097f60b5fd2fbf348ec",
                 
                 "62691f0f971e34de38370bff24deb5a7d40ab628093d304be60946afcdb3a936",
                 "76083c6d1b6809da088584674327b39488eaf665f0731151128452e04ce81bff",
                 "0c7cfc0976e25ae7680cf909ae2de1859cd9b679610a14bec40d69b91785b2f6"
                ),
    ]
    let testCases3: [hpkeTest] = [
        // Testcase 1.3
        hpkeTest(.X25519, .KDF256, .AESGCM128,
                 "6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7",
                 "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e",
                 "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e",
                 "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b",
                 "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd",
                 "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76",
                 
                 "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b",
                 "d3736bb256c19bfa93d79e8f80b7971262cb7c887e35c26370cfed62254369a1b52e3d505b79dd699f002bc8ed",
                 "122175cfd5678e04894e4ff8789e85dd381df48dcaf970d52057df2c9acc3b121313a2bfeaa986050f82d93645",
                 "dae12318660cf963c7bcbef0f39d64de3bf178cf9e585e756654043cc5059873bc8af190b72afc43d1e0135ada",
                 "55d53d85fe4d9e1e97903101eab0b4865ef20cef28765a47f840ff99625b7d69dee927df1defa66a036fc58ff2",
                 "42fa248a0e67ccca688f2b1d13ba4ba84755acf764bd797c8f7ba3b9b1dc3330326f8d172fef6003c79ec72319",
                 
                 "28c70088017d70c896a8420f04702c5a321d9cbf0279fba899b59e51bac72c85",
                 "25dfc004b0892be1888c3914977aa9c9bbaf2c7471708a49e1195af48a6f29ce",
                 "5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64"
                ),
        // Testcase 2.3
        hpkeTest(.X25519, .KDF256, .CHACHAPOLY,
                 "938d3daa5a8904540bc24f48ae90eed3f4f7f11839560597b55e7c9598c996c0",
                 "1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44",
                 "3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82",
                 "f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b",
                 "2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05",
                 "f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e",
                 
                 "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf",
                 "3265c7807ffff7fdace21659a2c6ccffee52a26d270c76468ed74202a65478bfaedfff9c2b7634e24f10b71016",
                 "3aadee86ad2a05081ea860033a9d09dbccb4acac2ded0891da40f51d4df19925f7a767b076a5cbc9355c8fd35e",
                 "502ecccd5c2be3506a081809cc58b43b94f77cbe37b8b31712d9e21c9e61aa6946a8e922f54eae630f88eb8033",
                 "652e597ba20f3d9241cda61f33937298b1169e6adf72974bbe454297502eb4be132e1c5064702fc165c2ddbde8",
                 "3be14e8b3bbd1028cf2b7d0a691dbbeff71321e7dec92d3c2cfb30a0994ab246af76168480285a60037b4ba13a",
                 
                 "070cffafd89b67b7f0eeb800235303a223e6ff9d1e774dce8eac585c8688c872",
                 "2852e728568d40ddb0edde284d36a4359c56558bb2fb8837cd3d92e46a3a14a8",
                 "1df39dc5dd60edcbf5f9ae804e15ada66e885b28ed7929116f768369a3f950ee"
                ),
        // Testcase 3.3
        hpkeTest(.P256, .KDF256, .AESGCM128,
                 "798d82a8d9ea19dbc7f2c6dfa54e8a6706f7cdc119db0813dacf8440ab37c857",
                 "04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d",
                 "d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e",
                 "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73",
                 "1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9",
                 "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454",
                 
                 "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099ed3289ffe19",
                 "b0a705a54532c7b4f5907de51c13dffe1e08d55ee9ba59686114b05945494d96725b239468f1229e3966aa1250",
                 "8dc805680e3271a801790833ed74473710157645584f06d1b53ad439078d880b23e25256663178271c80ee8b7c",
                 "04c8f7aae1584b61aa5816382cb0b834a5d744f420e6dffb5ddcec633a21b8b3472820930c1ea9258b035937a2",
                 "4a319462eaedee37248b4d985f64f4f863d31913fe9e30b6e13136053b69fe5d70853c84c60a84bb5495d5a678",
                 "28e874512f8940fafc7d06135e7589f6b4198bc0f3a1c64702e72c9e6abaf9f05cb0d2f11b03a517898815c934",
                 
                 "837e49c3ff629250c8d80d3c3fb957725ed481e59e2feb57afd9fe9a8c7c4497",
                 "594213f9018d614b82007a7021c3135bda7b380da4acd9ab27165c508640dbda",
                 "14fe634f95ca0d86e15247cca7de7ba9b73c9b9deb6437e1c832daf7291b79d5"
                ),
        // Testcase 4.3
        hpkeTest(.P256, .KDF512, .AESGCM128,
                 "6bb031aa9197562da0b44e737db2b9e61f6c3ea1138c37de28fc37ac29bc7350",
                 "04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0eee8adf84c8deba3155c9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec96276",
                 "1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236",
                 "0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a259b9b98a34ad17e21617d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d9529",
                 "02b266d66919f7b08f42ae0e7d97af4ca98b2dae3043bb7e0740ccadc1957579",
                 "04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd59178084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6",
                 
                 "2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154157fa9eb44f2fa4d7b38a9236e",
                 "10cd81e3a816d29942b602a92884348171a31cbd0f042c3057c65cd93c540943a5b05115bd520c09281061935b",
                 "920743a88d8cf6a09e1a3098e8be8edd09db136e9d543f215924043af8c7410f68ce6aa64fd2b1a176e7f6b3fd",
                 "6b11380fcc708fc8589effb5b5e0394cbd441fa5e240b5500522150ca8265d65ff55479405af936e2349119dcd",
                 "d084eca50e7554bb97ba34c4482dfe32c9a2b7f3ab009c2d1b68ecbf97bee2d28cd94b6c829b96361f2701772d",
                 "247da592cc4ce834a94de2c79f5730ee49342470a021e4a4bc2bb77c53b17413e94d94f57b4fdaedcf97cfe7b1",
                 
                 "f03fbc82f321a0ab4840e487cb75d07aafd8e6f68485e4f7ff72b2f55ff24ad6",
                 "1ce0cadec0a8f060f4b5070c8f8888dcdfefc2e35819df0cd559928a11ff0891",
                 "70c405c707102fd0041ea716090753be47d68d238b111d542846bd0d84ba907c"
                ),
        // Testcase 5.3
        hpkeTest(.P256, .KDF256, .CHACHAPOLY,
                 "0ecd212019008138a31f9104d5dba76b9f8e34d5b996041fff9e3df221dd0d5d",
                 "0444f6ee41818d9fe0f8265bffd016b7e2dd3964d610d0f7514244a60dbb7a11ece876bb110a97a2ac6a9542d7344bf7d2bd59345e3e75e497f7416cf38d296233",
                 "3cb2c125b8c5a81d165a333048f5dcae29a2ab2072625adad66dbb0f48689af9",
                 "04265529a04d4f46ab6fa3af4943774a9f1127821656a75a35fade898a9a1b014f64d874e88cddb24c1c3d79004d3a587db67670ca357ff4fba7e8b56ec013b98b",
                 "39b19402e742d48d319d24d68e494daa4492817342e593285944830320912519",
                 "040d5176aedba55bc41709261e9195c5146bb62d783031280775f32e507d79b5cbc5748b6be6359760c73cfe10ca19521af704ca6d91ff32fc0739527b9385d415",
                 
                 "25881f219935eec5ba70d7b421f13c35005734f3e4d959680270f55d71e2f5cb3bd2daced2770bf3d9d4916872",
                 "653f0036e52a376f5d2dd85b3204b55455b7835c231255ae098d09ed138719b97185129786338ab6543f753193",
                 "60878706117f22180c788e62df6a595bc41906096a11a9513e84f0141e43239e81a98d7a235abc64112fcb8ddd",
                 "0f9094dd08240b5fa7a388b824d19d5b4b1e126cebfd67a062c32f9ba9f1f3866cc38de7df2702626e2ab65c0f",
                 "dd29319e08135c5f8401d6537a364e92172c0e3f095f3fd18923881d11c0a6839345dd0b54acd0edd8f8344792",
                 "e2276ec5047bc4b6ed57d6da7da2fb47a77502f0a30f17d040247c73da336d722bc6c89adf68396a0912c6d152",
                 
                 "56c4d6c1d3a46c70fd8f4ecda5d27c70886e348efb51bd5edeaa39ff6ce34389",
                 "d2d3e48ed76832b6b3f28fa84be5f11f09533c0e3c71825a34fb0f1320891b51",
                 "eb0d312b6263995b4c7761e64b688c215ffd6043ff3bad2368c862784cbe6eff"
                ),
        // Testcase 6.3
        hpkeTest(.P521, .KDF512, .AESGCM256,
                 "fe1c589c2a05893895a537f38c7cb4300b5a7e8fef3d6ccb8f07a498029c61e90262e009dc254c7f6235f9c6b2fd6aeff0a714db131b09258c16e217b7bd2aa619b0",
                 "04007d419b8834e7513d0e7cc66424a136ec5e11395ab353da324e3586673ee73d53ab34f30a0b42a92d054d0db321b80f6217e655e304f72793767c4231785c4a4a6e008f31b93b7a4f2b8cd12e5fe5a0523dc71353c66cbdad51c86b9e0bdfcd9a45698f2dab1809ab1b0f88f54227232c858accc44d9a8d41775ac026341564a2d749f4",
                 "013ef326940998544a899e15e1726548ff43bbdb23a8587aa3bef9d1b857338d87287df5667037b519d6a14661e9503cfc95a154d93566d8c84e95ce93ad05293a0b",
                 "04015cc3636632ea9a3879e43240beae5d15a44fba819282fac26a19c989fafdd0f330b8521dff7dc393101b018c1e65b07be9f5fc9a28a1f450d6a541ee0d76221133001e8f0f6a05ab79f9b9bb9ccce142a453d59c5abebb5674839d935a3ca1a3fbc328539a60b3bc3c05fed22838584a726b9c176796cad0169ba4093332cbd2dc3a9f",
                 "001018584599625ff9953b9305849850d5e34bd789d4b81101139662fbea8b6508ddb9d019b0d692e737f66beae3f1f783e744202aaf6fea01506c27287e359fe776",
                 "04017de12ede7f72cb101dab36a111265c97b3654816dcd6183f809d4b3d111fe759497f8aefdc5dbb40d3e6d21db15bdc60f15f2a420761bcaeef73b891c2b117e9cf01e29320b799bbc86afdc5ea97d941ea1c5bd5ebeeac7a784b3bab524746f3e640ec26ee1bd91255f9330d974f845084637ee0e6fe9f505c5b87c86a4e1a6c3096dd",
                 
                 "0116aeb3a1c405c61b1ce47600b7ecd11d89b9c08c408b7e2d1e00a4d64696d12e6881dc61688209a8207427f9",
                 "37ece0cf6741f443e9d73b9966dc0b228499bb21fbf313948327231e70a18380e080529c0267f399ba7c539cc6",
                 "d17b045cac963e45d55fd3692ec17f100df66ac06d91f3b6af8efa7ed3c8895550eb753bc801fe4bd27005b4bd",
                 "50c523ae7c64cada96abea16ddf67a73d2914ec86a4cedb31a7e6257f7553ed244626ef79a57198192b2323384",
                 "53d422295a6ce8fcc51e6f69e252e7195e64abf49252f347d8c25534f1865a6a17d949c65ce618ddc7d816111f",
                 "0dfcfc22ea768880b4160fec27ab10c75fb27766c6bb97aed373a9b6eae35d31afb08257401075cbb602ac5abb",
                 
                 "8d78748d632f95b8ce0c67d70f4ad1757e61e872b5941e146986804b3990154b",
                 "80a4753230900ea785b6c80775092801fe91183746479f9b04c305e1db9d1f4d",
                 "620b176d737cf366bcc20d96adb54ec156978220879b67923689e6dca36210ed"
                ),
    ]
    let testCases4: [hpkeTest] = [
        // Testcase A1.4
        hpkeTest(.X25519, .KDF256, .AESGCM128,
                 "4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84",
                 "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976",
                 "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423",
                 "2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e",
                 "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4",
                 "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c",
                 
                 "a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001697737533e",
                 "4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ffe0c8f57a0a4c5ab9da127435d9",
                 "0c085a365fbfa63409943b00a3127abce6e45991bc653f182a80120868fc507e9e4d5e37bcc384fc8f14153b24",
                 "000a3cd3a3523bf7d9796830b1cd987e841a8bae6561ebb6791a3f0e34e89a4fb539faeee3428b8bbc082d2c1a",
                 "576d39dd2d4cc77d1a14a51d5c5f9d5e77586c3d8d2ab33bdec6379e28ce5c502f0b1cbd09047cf9eb9269bb52",
                 "13239bab72e25e9fd5bb09695d23c90a24595158b99127505c8a9ff9f127e0d657f71af59d67d4f4971da028f9",
                 
                 "08f7e20644bb9b8af54ad66d2067457c5f9fcb2a23d9f6cb4445c0797b330067",
                 "52e51ff7d436557ced5265ff8b94ce69cf7583f49cdb374e6aad801fc063b010",
                 "a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d"
                ),
        // Testcase A2.4
        hpkeTest(.X25519, .KDF256, .CHACHAPOLY,
                 "49d6eac8c6c558c953a0a252929a818745bb08cd3d29e15f9f5db5eb2e7d4b84",
                 "a5099431c35c491ec62ca91df1525d6349cb8aa170c51f9581f8627be6334851",
                 "7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c",
                 "3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45",
                 "90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418",
                 "656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02",
                 
                 "9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597",
                 "59460bacdbe7a920ef2806a74937d5a691d6d5062d7daafcad7db7e4d8c649adffe575c1889c5c2e3a49af8e3e",
                 "5688ff6a03ba26ae936044a5c800f286fb5d1eccdd2a0f268f6ff9773b51169318d1a1466bb36263415071db00",
                 "d936b7a01f5c7dc4c3dc04e322cc694684ee18dd71719196874e5235aed3cfb06cadcd3bc7da0877488d7c551d",
                 "4d4c462f7b9b637eaf1f4e15e325b7bc629c0af6e3073422c86064cc3c98cff87300f054fd56dd57dc34358beb",
                 "9b7f84224922d2a9edd7b2c2057f3bcf3a547f17570575e626202e593bfdd99e9878a1af9e41ded58c7fb77d2f",
                 
                 "c23ebd4e7a0ad06a5dddf779f65004ce9481069ce0f0e6dd51a04539ddcbd5cd",
                 "ed7ff5ca40a3d84561067ebc8e01702bc36cf1eb99d42a92004642b9dfaadd37",
                 "d3bae066aa8da27d527d85c040f7dd6ccb60221c902ee36a82f70bcd62a60ee4"
                ),
        // Testcase A3.4
        hpkeTest(.P256, .KDF256, .AESGCM128,
                 "3c1fceb477ec954c8d58ef3249e4bb4c38241b5925b95f7486e4d9f1d0d35fbb",
                 "04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3",
                 "bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394",
                 "049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e",
                 "b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240",
                 "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401",
                 
                 "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f4ff81b9246",
                 "51788c4e5d56276771032749d015d3eea651af0c7bb8e3da669effffed299ea1f641df621af65579c10fc09736",
                 "3b5a2be002e7b29927f06442947e1cf709b9f8508b03823127387223d712703471c266efc355f1bc2036f3027c",
                 "8ddbf1242fe5c7d61e1675496f3bfdb4d90205b3dfbc1b12aab41395d71a82118e095c484103107cf4face5123",
                 "6de25ceadeaec572fbaa25eda2558b73c383fe55106abaec24d518ef6724a7ce698f83ecdc53e640fe214d2f42",
                 "f380e19d291e12c5e378b51feb5cd50f6d00df6cb2af8393794c4df342126c2e29633fe7e8ce49587531affd4d",
                 
                 "595ce0eff405d4b3bb1d08308d70a4e77226ce11766e0a94c4fdb5d90025c978",
                 "110472ee0ae328f57ef7332a9886a1992d2c45b9b8d5abc9424ff68630f7d38d",
                 "18ee4d001a9d83a4c67e76f88dd747766576cac438723bad0700a910a4d717e6"
                ),
        // Testcase A4.4
        hpkeTest(.P256, .KDF512, .AESGCM128,
                 "37ae06a521cd555648c928d7af58ad2aa4a85e34b8cabd069e94ad55ab872cc8",
                 "04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9a111cbf6f7385fac55edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43e9",
                 "00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e",
                 "04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23f2165b5bb1f07a6240dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d60",
                 "d743b20821e6326f7a26684a4beed7088b35e392114480ca9f6c325079dcf10b",
                 "04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0aef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d138",
                 
                 "840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa910fc4296828cb9d862c2fd7d16",
                 "d4680a48158d9a75fd09355878d6e33997a36ee01d4a8f22032b22373b795a941b7b9c5205ff99e0ff284beef4",
                 "c45eb6597de2bac929a0f5d404ba9d2dc1ea031880930f1fd7a283f0a0cbebb35eac1a9ee0d1225f5e0f181571",
                 "4ee2482ad8d7d1e9b7e651c78b6ca26d3c5314d0711710ca62c2fd8bb8996d7d8727c157538d5493da696b61f8",
                 "65596b731df010c76a915c6271a438056ce65696459432eeafdae7b4cadb6290dd61e68edd4e40b659d2a8cbcc",
                 "9f659482ebc52f8303f9eac75656d807ec38ce2e50c72e3078cd13d86b30e3f890690a873277620f8a6a42d836",
                 
                 "c8c917e137a616d3d4e4c9fcd9c50202f366cb0d37862376bc79f9b72e8a8db9",
                 "33a5d4df232777008a06d0684f23bb891cfaef702f653c8601b6ad4d08dddddf",
                 "bed80f2e54f1285895c4a3f3b3625e6206f78f1ed329a0cfb5864f7c139b3c6a"
                ),
        // Testcase A5.4
        hpkeTest(.P256, .KDF256, .CHACHAPOLY,
                 "f3a07f194703e321ef1f753a1b9fe27a498dfdfa309151d70bedd896c239c499",
                 "04d383fd920c42d018b9d57fd73a01f1eee480008923f67d35169478e55d2e8817068daf62a06b10e0aad4a9e429fa7f904481be96b79a9c231a33e956c20b81b6",
                 "c29fc577b7e74d525c0043f1c27540a1248e4f2c8d297298e99010a92e94865c",
                 "0492cf8c9b144b742fe5a63d9a181a19d416f3ec8705f24308ad316564823c344e018bd7c03a33c926bb271b28ef5bf28c0ca00abff249fee5ef7f33315ff34fdb",
                 "53541bd995f874a67f8bfd8038afa67fd68876801f42ff47d0dc2a4deea067ae",
                 "043539917ee26f8ae0aa5f784a387981b13de33124a3cde88b94672030183110f331400115855808244ff0c5b6ca6104483ac95724481d41bdcd9f15b430ad16f6",
                 
                 "9eadfa0f954835e7e920ffe56dec6b31a046271cf71fdda55db72926e1d8fae94cc6280fcfabd8db71eaa65c05",
                 "e357ad10d75240224d4095c9f6150a2ed2179c0f878e4f2db8ca95d365d174d059ff8c3eb38ea9a65cfc8eaeb8",
                 "2fa56d00f8dd479d67a2ec3308325cf3bbccaf102a64ffccdb006bd7dcb932685b9a7b49cdc094a85fec1da5ef",
                 "1fe9d6db14965003ed81a39abf240f9cd7c5a454bca0d69ef9a2de16d537364fbbf110b9ef11fa4a7a0172f0ce",
                 "eaf4041a5c9122b22d1f8d698eeffe45d64b4ae33d0ddca3a4cdf4a5f595acc95a1a9334d06cc4d000df6aaad6",
                 "fb857f4185ce5286c1a52431867537204963ea66a3eee8d2a74419fd8751faee066d08277ac7880473aa4143ba",
                 
                 "c52b4592cd33dd38b2a3613108ddda28dcf7f03d30f2a09703f758bfa8029c9a",
                 "2f03bebc577e5729e148554991787222b5c2a02b77e9b1ac380541f710e5a318",
                 "e01dd49e8bfc3d9216abc1be832f0418adf8b47a7b5a330a7436c31e33d765d7"
                ),
        // Testcase A6.4
        hpkeTest(.P521, .KDF512, .AESGCM256,
                 "54272797b1fbc128a6967ff1fd606e0c67868f7762ce1421439cbc9e90ce1b28d566e6c2acbce712e48eebf236696eb680849d6873e9959395b2931975d61d38bd6c",
                 "0401655b5d3b7cfafaba30851d25edc44c6dd17d99410efbed8591303b4dbeea8cb1045d5255f9a60384c3bbd4a3386ae6e6fab341dc1f8db0eed5f0ab1aaac6d7838e00dadf8a1c2c64b48f89c633721e88369e54104b31368f26e35d04a442b0b428510fb23caada686add16492f333b0f7ba74c391d779b788df2c38d7a7f4778009d91",
                 "0053c0bc8c1db4e9e5c3e3158bfdd7fc716aef12db13c8515adf821dd692ba3ca53041029128ee19c8556e345c4bcb840bb7fd789f97fe10f17f0e2c6c2528072843",
                 "040013761e97007293d57de70962876b4926f69a52680b4714bee1d4236aa96c19b840c57e80b14e91258f0a350e3f7ba59f3f091633aede4c7ec4fa8918323aa45d5901076dec8eeb22899fda9ab9e1960003ff0535f53c02c40f2ae4cdc6070a3870b85b4bdd0bb77f1f889e7ee51f465a308f08c666ad3407f75dc046b2ff5a24dbe2ed",
                 "003f64675fc8914ec9e2b3ecf13585b26dbaf3d5d805042ba487a5070b8c5ac1d39b17e2161771cc1b4d0a3ba6e866f4ea4808684b56af2a49b5e5111146d45d9326",
                 "04000a5096a6e6e002c83517b494bfc2e36bfb8632fae8068362852b70d0ff71e560b15aff96741ecffb63d8ac3090c3769679009ac59a99a1feb4713c5f090fc0dbed01ad73c45d29d369e36744e9ed37d12f80700c16d816485655169a5dd66e4ddf27f2acffe0f56f7f77ea2b473b4bf0518b975d9527009a3d14e5a4957e3e8a9074f8",
                 
                 "942a2a92e0817cf032ce61abccf4f3a7c5d21b794ed943227e07b7df2d6dd92c9b8a9371949e65cca262448ab7",
                 "c0a83b5ec3d7933a090f681717290337b4fede5bfaa0a40ec29f93acad742888a1513c649104c391c78d1d7f29",
                 "2847b2e0ce0b9da8fca7b0e81ff389d1682ee1b388ed09579b145058b5af6a93a85dd50d9f417dc88f2c785312",
                 "fbd9948ab9ac4a9cb9e295c07273600e6a111a3a89241d3e2178f39d532a2ec5c15b9b0c6937ac84c88e0ca76f",
                 "63113a870131b567db8f39a11b4541eafbd2d3cf3a9bf9e5c1cfcb41e52f9027310b82a4868215959131694d15",
                 "24f9d8dadd2107376ccd143f70f9bafcd2b21d8117d45ff327e9a78f603a32606e42a6a8bdb57a852591d20907",
                 
                 "a39502ef5ca116aa1317bd9583dd52f15b0502b71d900fc8a622d19623d0cb5d",
                 "749eda112c4cfdd6671d84595f12cd13198fc3ef93ed72369178f344fe6e09c3",
                 "f8b4e72cefbff4ca6c4eabb8c0383287082cfcbb953d900aed4959afd0017095"
                ),
    ]
    let testCasesExportOnly1: [hpkeTest] = [
        // Testcase A7.1
        hpkeTest(.X25519, .KDF256, .EXPORTONLY,
                 "55bc245ee4efda25d38f2d54d5bb6665291b99f8108a8c4b686c2b14893ea5d9",
                 "194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664",
                 "33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848",
                 "",
                 "",
                 "e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918",

                 "",
                 "",
                 "",
                 "",
                 "",
                 "",

                 "7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36",
                 "d5535b87099c6c3ce80dc112a2671c6ec8e811a2f284f948cec6dd1708ee33f0",
                 "ffaabc85a776136ca0c378e5d084c9140ab552b78f039d2e8775f26efff4c70e"
                ),
    ]
    let testCasesExportOnly2: [hpkeTest] = [
        // Testcase A7.2
        hpkeTest(.X25519, .KDF256, .EXPORTONLY,
                 "c51211a8799f6b8a0021fcba673d9c4067a98ebc6794232e5b06cb9febcbbdf5",
                 "d53af36ea5f58f8868bb4a1333ed4cc47e7a63b0040eb54c77b9c8ec456da824",
                 "98f304d4ecb312689690b113973c61ffe0aa7c13f2fbe365e48f3ed09e5a6a0c",
                 "",
                 "",
                 "d3805a97cbcd5f08babd21221d3e6b362a700572d14f9bbeb94ec078d051ae3d",

                 "",
                 "",
                 "",
                 "",
                 "",
                 "",

                 "be6c76955334376aa23e936be013ba8bbae90ae74ed995c1c6157e6f08dd5316",
                 "1721ed2aa852f84d44ad020c2e2be4e2e6375098bf48775a533505fd56a3f416",
                 "7c9d79876a288507b81a5a52365a7d39cc0fa3f07e34172984f96fec07c44cba"
                ),
    ]
    let testCasesExportOnly3: [hpkeTest] = [
        // Testcase A7.3
        hpkeTest(.X25519, .KDF256, .EXPORTONLY,
                 "43b078912a54b591a7b09b16ce89a1955a9dd60b29fb611e044260046e8b061b",
                 "ffd7ac24694cb17939d95feb7c4c6539bb31621deb9b96d715a64abdd9d14b10",
                 "ed88cda0e91ca5da64b6ad7fc34a10f096fa92f0b9ceff9d2c55124304ed8b4a",
                 "89eb1feae431159a5250c5186f72a15962c8d0debd20a8389d8b6e4996e14306",
                 "c85f136e06d72d28314f0e34b10aadc8d297e9d71d45a5662c2b7c3b9f9f9405",
                 "5ac1671a55c5c3875a8afe74664aa8bc68830be9ded0c5f633cd96400e8b5c05",

                 "",
                 "",
                 "",
                 "",
                 "",
                 "",

                 "83c1bac00a45ed4cb6bd8a6007d2ce4ec501f55e485c5642bd01bf6b6d7d6f0a",
                 "08a1d1ad2af3ef5bc40232a64f920650eb9b1034fac3892f729f7949621bf06e",
                 "ff3b0e37a9954247fea53f251b799e2edd35aac7152c5795751a3da424feca73"
                ),
    ]
    let testCasesExportOnly4: [hpkeTest] = [
        // Testcase A7.4
        hpkeTest(.X25519, .KDF256, .EXPORTONLY,
                 "94efae91e96811a3a49fd1b20eb0344d68ead6ac01922c2360779aa172487f40",
                 "f47cd9d6993d2e2234eb122b425accfb486ee80f89607b087094e9f413253c2d",
                 "c4962a7f97d773a47bdf40db4b01dc6a56797c9e0deaab45f4ea3aa9b1d72904",
                 "29a5bf3867a6128bbdf8e070abe7fe70ca5e07b629eba5819af73810ee20112f",
                 "6175b2830c5743dff5b7568a7e20edb1fe477fb0487ca21d6433365be90234d0",
                 "81cbf4bd7eee97dd0b600252a1c964ea186846252abb340be47087cc78f3d87c",

                 "",
                 "",
                 "",
                 "",
                 "",
                 "",

                 "dafd8beb94c5802535c22ff4c1af8946c98df2c417e187c6ccafe45335810b58",
                 "7346bb0b56caf457bcc1aa63c1b97d9834644bdacac8f72dbbe3463e4e46b0dd",
                 "84f3466bd5a03bde6444324e63d7560e7ac790da4e5bbab01e7c4d575728c34a"
                ),
    ]

    func test1() throws {
        for test in testCases1 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info)
            XCTAssertEqual(test.enc, hpkeS.encapsulatedKey)
            XCTAssertEqual(test.ct0, try hpkeS.seal(pt: pt, aad: aad0))
            XCTAssertEqual(test.ct1, try hpkeS.seal(pt: pt, aad: aad1))
            XCTAssertEqual(test.ct2, try hpkeS.seal(pt: pt, aad: aad2))
            _ = try hpkeS.seal(pt: pt, aad: [])
            XCTAssertEqual(test.ct4, try hpkeS.seal(pt: pt, aad: aad4))
            for _ in 0 ..< 250 {
                _ = try hpkeS.seal(pt: pt, aad: [])
            }
            XCTAssertEqual(test.ct255, try hpkeS.seal(pt: pt, aad: aad255))
            XCTAssertEqual(test.ct256, try hpkeS.seal(pt: pt, aad: aad256))
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
        for test in testCases2 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info, psk, psk_id)
            XCTAssertEqual(test.enc, hpkeS.encapsulatedKey)
            XCTAssertEqual(test.ct0, try hpkeS.seal(pt: pt, aad: aad0))
            XCTAssertEqual(test.ct1, try hpkeS.seal(pt: pt, aad: aad1))
            XCTAssertEqual(test.ct2, try hpkeS.seal(pt: pt, aad: aad2))
            _ = try hpkeS.seal(pt: pt, aad: [])
            XCTAssertEqual(test.ct4, try hpkeS.seal(pt: pt, aad: aad4))
            for _ in 0 ..< 250 {
                _ = try hpkeS.seal(pt: pt, aad: [])
            }
            XCTAssertEqual(test.ct255, try hpkeS.seal(pt: pt, aad: aad255))
            XCTAssertEqual(test.ct256, try hpkeS.seal(pt: pt, aad: aad256))
            
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
        for test in testCases3 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info, HPKEPrivateKey(kem: test.kem, bytes: test.skS))
            XCTAssertEqual(test.enc, hpkeS.encapsulatedKey)
            XCTAssertEqual(test.ct0, try hpkeS.seal(pt: pt, aad: aad0))
            XCTAssertEqual(test.ct1, try hpkeS.seal(pt: pt, aad: aad1))
            XCTAssertEqual(test.ct2, try hpkeS.seal(pt: pt, aad: aad2))
            _ = try hpkeS.seal(pt: pt, aad: [])
            XCTAssertEqual(test.ct4, try hpkeS.seal(pt: pt, aad: aad4))
            for _ in 0 ..< 250 {
                _ = try hpkeS.seal(pt: pt, aad: [])
            }
            XCTAssertEqual(test.ct255, try hpkeS.seal(pt: pt, aad: aad255))
            XCTAssertEqual(test.ct256, try hpkeS.seal(pt: pt, aad: aad256))
            
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
        for test in testCases4 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info, HPKEPrivateKey(kem: test.kem, bytes: test.skS), psk, psk_id)
            XCTAssertEqual(test.enc, hpkeS.encapsulatedKey)
            XCTAssertEqual(test.ct0, try hpkeS.seal(pt: pt, aad: aad0))
            XCTAssertEqual(test.ct1, try hpkeS.seal(pt: pt, aad: aad1))
            XCTAssertEqual(test.ct2, try hpkeS.seal(pt: pt, aad: aad2))
            _ = try hpkeS.seal(pt: pt, aad: [])
            XCTAssertEqual(test.ct4, try hpkeS.seal(pt: pt, aad: aad4))
            for _ in 0 ..< 250 {
                _ = try hpkeS.seal(pt: pt, aad: [])
            }
            XCTAssertEqual(test.ct255, try hpkeS.seal(pt: pt, aad: aad255))
            XCTAssertEqual(test.ct256, try hpkeS.seal(pt: pt, aad: aad256))
            
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
    }
    
    func test2() throws {
        let n = 100
        for test in testCases1 {
            var ct: [Bytes] = [Bytes](repeating: [], count: n)
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(suite: suite, publicKey: HPKEPublicKey(kem: test.kem, bytes: test.pkR), info: info)
            for i in 0 ..< n {
                ct[i] = try hpkeS.seal(pt: pt, aad: [Byte(i)])
            }
            let hpkeR = try Recipient(suite: suite, privateKey: HPKEPrivateKey(kem: test.kem, bytes: test.skR), info: info, encap: hpkeS.encapsulatedKey)
            for i in 0 ..< n {
                let ptx = try hpkeR.open(ct: ct[i], aad: [Byte(i)])
                XCTAssertEqual(ptx, pt)
            }
        }
        for test in testCases2 {
            var ct: [Bytes] = [Bytes](repeating: [], count: n)
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(suite: suite, publicKey: HPKEPublicKey(kem: test.kem, bytes: test.pkR), info: info, psk: psk, pskId: psk_id)
            for i in 0 ..< n {
                ct[i] = try hpkeS.seal(pt: pt, aad: [Byte(i)])
            }
            let hpkeR = try Recipient(suite: suite, privateKey: HPKEPrivateKey(kem: test.kem, bytes: test.skR), info: info, psk: psk, pskId: psk_id, encap: hpkeS.encapsulatedKey)
            for i in 0 ..< n {
                let ptx = try hpkeR.open(ct: ct[i], aad: [Byte(i)])
                XCTAssertEqual(ptx, pt)
            }
        }
        for test in testCases3 {
            var ct: [Bytes] = [Bytes](repeating: [], count: n)
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(suite: suite, publicKey: HPKEPublicKey(kem: test.kem, bytes: test.pkR), info: info, authentication: HPKEPrivateKey(kem: test.kem, bytes: test.skS))
            for i in 0 ..< n {
                ct[i] = try hpkeS.seal(pt: pt, aad: [Byte(i)])
            }
            let hpkeR = try Recipient(suite: suite, privateKey: HPKEPrivateKey(kem: test.kem, bytes: test.skR), info: info, authentication: HPKEPublicKey(kem: test.kem, bytes: test.pkS), encap: hpkeS.encapsulatedKey)
            for i in 0 ..< n {
                let ptx = try hpkeR.open(ct: ct[i], aad: [Byte(i)])
                XCTAssertEqual(ptx, pt)
            }
        }
        for test in testCases4 {
            var ct: [Bytes] = [Bytes](repeating: [], count: n)
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(suite: suite, publicKey: HPKEPublicKey(kem: test.kem, bytes: test.pkR), info: info, authentication: HPKEPrivateKey(kem: test.kem, bytes: test.skS), psk: psk, pskId: psk_id)
            for i in 0 ..< n {
                ct[i] = try hpkeS.seal(pt: pt, aad: [Byte(i)])
            }
            let hpkeR = try Recipient(suite: suite, privateKey: HPKEPrivateKey(kem: test.kem, bytes: test.skR), info: info, authentication: HPKEPublicKey(kem: test.kem, bytes: test.pkS), psk: psk, pskId: psk_id, encap: hpkeS.encapsulatedKey)
            for i in 0 ..< n {
                let ptx = try hpkeR.open(ct: ct[i], aad: [Byte(i)])
                XCTAssertEqual(ptx, pt)
            }
        }
    }
    
    func testSingleShot() throws {
        for test in testCases1 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let pubKey = try HPKEPublicKey(kem: test.kem, bytes: test.pkR)
            let privKey = try HPKEPrivateKey(kem: test.kem, bytes: test.skR)
            for i in 0 ..< 3 {
                let (enc, ct) = try suite.seal(publicKey: pubKey, info: info, pt: pt, aad: [Byte(i)])
                let ptx = try suite.open(privateKey: privKey, info: info, ct: ct, aad: [Byte(i)], encap: enc)
                XCTAssertEqual(ptx, pt)
            }
        }
        for test in testCases2 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let pubKey = try HPKEPublicKey(kem: test.kem, bytes: test.pkR)
            let privKey = try HPKEPrivateKey(kem: test.kem, bytes: test.skR)
            for i in 0 ..< 3 {
                let (enc, ct) = try suite.seal(publicKey: pubKey, info: info, psk: psk, pskId: psk_id, pt: pt, aad: [Byte(i)])
                let ptx = try suite.open(privateKey: privKey, info: info, psk: psk, pskId: psk_id, ct: ct, aad: [Byte(i)], encap: enc)
                XCTAssertEqual(ptx, pt)
            }
        }
        for test in testCases3 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let pubKey = try HPKEPublicKey(kem: test.kem, bytes: test.pkR)
            let privKey = try HPKEPrivateKey(kem: test.kem, bytes: test.skR)
            let authPubKey = try HPKEPublicKey(kem: test.kem, bytes: test.pkS)
            let authPrivKey = try HPKEPrivateKey(kem: test.kem, bytes: test.skS)
            for i in 0 ..< 3 {
                let (enc, ct) = try suite.seal(publicKey: pubKey, info: info, authentication: authPrivKey, pt: pt, aad: [Byte(i)])
                let ptx = try suite.open(privateKey: privKey, info: info, authentication: authPubKey, ct: ct, aad: [Byte(i)], encap: enc)
                XCTAssertEqual(ptx, pt)
            }
            let (encap, secret) = try suite.exportSecret(publicKey: pubKey, info: info, context: expCtx, L: 10, authentication: authPrivKey)
            let secret1 = try suite.exportSecret(privateKey: privKey, info: info, context: expCtx, L: 10, authentication: authPubKey, encap: encap)
            XCTAssertEqual(secret, secret1)
        }
        for test in testCases4 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let pubKey = try HPKEPublicKey(kem: test.kem, bytes: test.pkR)
            let privKey = try HPKEPrivateKey(kem: test.kem, bytes: test.skR)
            let authPubKey = try HPKEPublicKey(kem: test.kem, bytes: test.pkS)
            let authPrivKey = try HPKEPrivateKey(kem: test.kem, bytes: test.skS)
            for i in 0 ..< 3 {
                let (enc, ct) = try suite.seal(publicKey: pubKey, info: info, authentication: authPrivKey, psk: psk, pskId: psk_id, pt: pt, aad: [Byte(i)])
                let ptx = try suite.open(privateKey: privKey, info: info, authentication: authPubKey, psk: psk, pskId: psk_id, ct: ct, aad: [Byte(i)], encap: enc)
                XCTAssertEqual(ptx, pt)
            }
            let (encap, secret) = try suite.exportSecret(publicKey: pubKey, info: info, context: expCtx, L: 10, authentication: authPrivKey, psk: psk, pskId: psk_id)
            let secret1 = try suite.exportSecret(privateKey: privKey, info: info, context: expCtx, L: 10, authentication: authPubKey, psk: psk, pskId: psk_id, encap: encap)
            XCTAssertEqual(secret, secret1)
        }
    }
    
    func testExportOnly() throws {
        for test in testCasesExportOnly1 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info)
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
        for test in testCasesExportOnly2 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info, psk, psk_id)
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
        for test in testCasesExportOnly3 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info, HPKEPrivateKey(kem: test.kem, bytes: test.skS))
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
        for test in testCasesExportOnly4 {
            let suite = CipherSuite(kem: test.kem, kdf: test.kdf, aead: test.aead)
            let hpkeS = try Sender(test.ikm, suite, HPKEPublicKey(kem: test.kem, bytes: test.pkR), info, HPKEPrivateKey(kem: test.kem, bytes: test.skS), psk, psk_id)
            XCTAssertEqual(try hpkeS.exportSecret(context: [], L: 32), test.exp1)
            XCTAssertEqual(try hpkeS.exportSecret(context: [0], L: 32), test.exp2)
            XCTAssertEqual(try hpkeS.exportSecret(context: expCtx, L: 32), test.exp3)
        }
    }

    // P384 test
    
    let skR384 = HPKETest.hex2bytes("a00232a333024664927a9d16493f15929ede6300d4bb3655c323eee42c0b5fb9483b6e6b6593f3c6e2d7ed0f32b606c4")
    let pkR384 = HPKETest.hex2bytes(
        "043b738e3b529c67021a444dde81fb7a81bd0b2b4165d631da563f099ae0ae9c51ed0bddc37dc913a6adc337aa907ce103317346ee83fd7c10244ef93ed4b754a8e607bc3e9ac5ad9fb914e91a7b45e7000e6ff266fa44fe8f05893f0c66080117")
    
    func test384() throws {
        let n = 100
        var ct: [Bytes] = [Bytes](repeating: [], count: n)
        let suite1 = CipherSuite(kem: .P384, kdf: .KDF256, aead: .AESGCM128)
        let hpkeS1 = try Sender(suite: suite1, publicKey: HPKEPublicKey(kem: .P384, bytes: pkR384), info: info)
        for i in 0 ..< n {
            ct[i] = try hpkeS1.seal(pt: pt, aad: [Byte(i)])
        }
        let hpkeR1 = try Recipient(suite: suite1, privateKey: HPKEPrivateKey(kem: .P384, bytes: skR384), info: info, encap: hpkeS1.encapsulatedKey)
        for i in 0 ..< n {
            let ptx = try hpkeR1.open(ct: ct[i], aad: [Byte(i)])
            XCTAssertEqual(ptx, pt)
        }
        let suite2 = CipherSuite(kem: .P384, kdf: .KDF256, aead: .CHACHAPOLY)
        let hpkeS2 = try Sender(suite: suite2, publicKey: HPKEPublicKey(kem: .P384, bytes: pkR384), info: info)
        for i in 0 ..< n {
            ct[i] = try hpkeS2.seal(pt: pt, aad: [Byte(i)])
        }
        let hpkeR2 = try Recipient(suite: suite2, privateKey: HPKEPrivateKey(kem: .P384, bytes: skR384), info: info, encap: hpkeS2.encapsulatedKey)
        for i in 0 ..< n {
            let ptx = try hpkeR2.open(ct: ct[i], aad: [Byte(i)])
            XCTAssertEqual(ptx, pt)
        }

        // single-shot test
        for i in 0 ..< 3 {
            let (enc, ct) = try suite1.seal(publicKey: HPKEPublicKey(kem: .P384, bytes: pkR384), info: info, pt: pt, aad: [Byte(i)])
            let ptx = try suite1.open(privateKey: HPKEPrivateKey(kem: .P384, bytes: skR384), info: info, ct: ct, aad: [Byte(i)], encap: enc)
            XCTAssertEqual(ptx, pt)
        }
        for i in 0 ..< 3 {
            let (enc, ct) = try suite2.seal(publicKey: HPKEPublicKey(kem: .P384, bytes: pkR384), info: info, pt: pt, aad: [Byte(i)])
            let ptx = try suite2.open(privateKey: HPKEPrivateKey(kem: .P384, bytes: skR384), info: info, ct: ct, aad: [Byte(i)], encap: enc)
            XCTAssertEqual(ptx, pt)
        }
        
    }
    
    // X448 test
    
    let skR448 = HPKETest.hex2bytes("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
    let pkR448 = HPKETest.hex2bytes("078dc8e73158e3a63345f6729d0a386435b4d7ad2e033aa413985a60b443956007427dd89e81a36dc0db81752cc338824369985b4ae58c7d")
    
    func test448() throws {
        let n = 100
        var ct: [Bytes] = [Bytes](repeating: [], count: n)
        let suite1 = CipherSuite(kem: .X448, kdf: .KDF256, aead: .AESGCM128)
        let hpkeS1 = try Sender(suite: suite1, publicKey: HPKEPublicKey(kem: .X448, bytes: pkR448), info: info)
        for i in 0 ..< n {
            ct[i] = try hpkeS1.seal(pt: pt, aad: [Byte(i)])
        }
        let hpkeR1 = try Recipient(suite: suite1, privateKey: HPKEPrivateKey(kem: .X448, bytes: skR448), info: info, encap: hpkeS1.encapsulatedKey)
        for i in 0 ..< n {
            let ptx = try hpkeR1.open(ct: ct[i], aad: [Byte(i)])
            XCTAssertEqual(ptx, pt)
        }
        let suite2 = CipherSuite(kem: .X448, kdf: .KDF256, aead: .CHACHAPOLY)
        let hpkeS2 = try Sender(suite: suite2, publicKey: HPKEPublicKey(kem: .X448, bytes: pkR448), info: info)
        for i in 0 ..< n {
            ct[i] = try hpkeS2.seal(pt: pt, aad: [Byte(i)])
        }
        let hpkeR2 = try Recipient(suite: suite2, privateKey: HPKEPrivateKey(kem: .X448, bytes: skR448), info: info, encap: hpkeS2.encapsulatedKey)
        for i in 0 ..< n {
            let ptx = try hpkeR2.open(ct: ct[i], aad: [Byte(i)])
            XCTAssertEqual(ptx, pt)
        }

        // single-shot test
        for i in 0 ..< 3 {
            let (enc, ct) = try suite1.seal(publicKey: HPKEPublicKey(kem: .X448, bytes: pkR448), info: info, pt: pt, aad: [Byte(i)])
            let ptx = try suite1.open(privateKey: HPKEPrivateKey(kem: .X448, bytes: skR448), info: info, ct: ct, aad: [Byte(i)], encap: enc)
            XCTAssertEqual(ptx, pt)
        }
        for i in 0 ..< 3 {
            let (enc, ct) = try suite2.seal(publicKey: HPKEPublicKey(kem: .X448, bytes: pkR448), info: info, pt: pt, aad: [Byte(i)])
            let ptx = try suite2.open(privateKey: HPKEPrivateKey(kem: .X448, bytes: skR448), info: info, ct: ct, aad: [Byte(i)], encap: enc)
            XCTAssertEqual(ptx, pt)
        }
    }

}
