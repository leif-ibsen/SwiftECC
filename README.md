<h2><b>SwiftECC</b></h2>
<h3><b>Contents:</b></h3>
<ul>
<li><a href="#use">Usage</a></li>
<li><a href="#basic">Basics</a>
<ul>
	<li><a href="#basic1">Creating New Keys</a></li>
	<li><a href="#basic2">Loading Existing Keys</a></li>
	<li><a href="#basic3">Encrypted Private Keys</a></li>
	<li><a href="#basic9">ChaChaPoly Encryption and Decryption</a></li>
	<li><a href="#basic4">AES Encryption and Decryption</a></li>
	<li><a href="#basic5">Signing and Verifying</a></li>
	<li><a href="#basic6">Secret Key Agreement</a></li>
	<li><a href="#basic7">Creating New Domains</a></li>
	<li><a href="#basic8">Elliptic Curve Arithmetic</a></li>
</ul></li>
<li><a href="#keydev">Key Derivation</a></li>
<li><a href="#perf">Performance</a></li>
<li><a href="#dep">Dependencies</a></li>
<li><a href="#ref">References</a></li>
<li><a href="#ack">Acknowledgement</a></li>
</ul>
SwiftECC provides elliptic curve cryptography in Swift.
This encompasses:
<ul>
<li>Encryption and decryption using the ECIES algorithm based on the AES block cipher or the ChaCha20/Poly1305 cipher/message authentication</li>
<li>Signature signing and verifying using the ECDSA algorithm, including the option of deterministic signatures</li>
<li>Secret key agreement using the Diffie-Hellman key agreement algorithm - ECDH</li>
<li>Ability to create your own domains</li>
<li>General elliptic curve arithmetic</li>
</ul>
SwiftECC requires Swift 5.0. It also requires that the Int and UInt types be 64 bit types.
<h2 id="use"><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftECC", from: "3.4.0"),
	  ]

<h2 id="basic"><b>Basics</b></h2>
The basic concept in SwiftECC is the Elliptic Curve Domain, represented by the Domain class.
Please, refer section 3.1 in [SEC 1] that describes the domain concept in detail.

There are 18 predefined NIST domains
and 14 predefined Brainpool domains in SwiftECC,
and it is possible to create your own characteristic 2, and odd prime characteristic domains.

You need a public key in order to encrypt a message or verify a signature, and you need a private key in order to decrypt a message or sign a message.
Given a domain, you can generate public/private key pairs or you can load them from the PEM- or DER encoding of existing keys.

<h3 id="basic1"><b>Creating New Keys</b></h3>
For a given domain it is possible to generate a public/private key pair. For example:

    let domain = Domain.instance(curve: .EC384r1)
    let (pubKey, privKey) = domain.generateKeyPair()

The private key is simply a random positive integer less than the domain order. The public key is the domain generator point multiplied by the private key.
Given a private key, say 'privKey', you can generate the corresponding public key, like

    let pubKey = ECPublicKey(privateKey: privKey)

Given a domain, say 'dom' and a curve point, say 'pt', you can generate a public key, like

    let pubKey = try ECPublicKey(domain: dom, w: pt)

<h3 id="basic2"><b>Loading Existing Keys</b></h3>
It is possible to create keys from their PEM encodings. For example

    // Public key encoding - EC384r1 domain
    let pubKeyPem =
    """
    -----BEGIN PUBLIC KEY-----
    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQW/MahMwMTFjwY95uOEdfBVC7HrQhTGG
    TwxiPlgDiARqC6y6EQ1Ajkuhe4A02WOltRYQRXKytzspOR25UfgtagURAwxVFYzR
    9cmi6FRmvvq/Tsigd/dAi4FNjniR7/Pg
    -----END PUBLIC KEY-----
    """
    let pubKey = try ECPublicKey(pem: pubKeyPem)
    
    // Private key encoding in PKCS#8 format - EC384r1 domain
    let privKeyPem =
    """
    -----BEGIN PRIVATE KEY-----
    MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDBmpNziSYmGoWwl7apJ
    M9ZdDBxkJqmxMScHGXG45ZQXSv7fIuJlsSwxK76nUiiO7gigBwYFK4EEACKhZANi
    AARBb8xqEzAxMWPBj3m44R18FULsetCFMYZPDGI+WAOIBGoLrLoRDUCOS6F7gDTZ
    Y6W1FhBFcrK3Oyk5HblR+C1qBREDDFUVjNH1yaLoVGa++r9OyKB390CLgU2OeJHv
    8+A=
    -----END PRIVATE KEY-----
    """
    let privKey = try ECPrivateKey(pem: privKeyPem)
    
    // See the key ASN1 structures
    print(pubKey)
    print(privKey)

giving:

    Sequence (2):
      Sequence (2):
        Object Identifier: 1.2.840.10045.2.1
        Object Identifier: 1.3.132.0.34
      Bit String (776): 00000100 01000001 01101111 11001100 01101010 00010011 00110000 00110001 00110001 01100011 11000001 10001111 01111001 10111000 11100001 00011101 01111100 00010101 01000010 11101100 01111010 11010000 10000101 00110001 10000110 01001111 00001100 01100010 00111110 01011000 00000011 10001000 00000100 01101010 00001011 10101100 10111010 00010001 00001101 01000000 10001110 01001011 10100001 01111011 10000000 00110100 11011001 01100011 10100101 10110101 00010110 00010000 01000101 01110010 10110010 10110111 00111011 00101001 00111001 00011101 10111001 01010001 11111000 00101101 01101010 00000101 00010001 00000011 00001100 01010101 00010101 10001100 11010001 11110101 11001001 10100010 11101000 01010100 01100110 10111110 11111010 10111111 01001110 11001000 10100000 01110111 11110111 01000000 10001011 10000001 01001101 10001110 01111000 10010001 11101111 11110011 11100000

    Sequence (4):
      Integer: 1
      Octet String (48): 66 a4 dc e2 49 89 86 a1 6c 25 ed aa 49 33 d6 5d 0c 1c 64 26 a9 b1 31 27 07 19 71 b8 e5 94 17 4a fe df 22 e2 65 b1 2c 31 2b be a7 52 28 8e ee 08
      [0]:
        Object Identifier: 1.3.132.0.34
      [1]:
        Bit String (776): 00000100 01000001 01101111 11001100 01101010 00010011 00110000 00110001 00110001 01100011 11000001 10001111 01111001 10111000 11100001 00011101 01111100 00010101 01000010 11101100 01111010 11010000 10000101 00110001 10000110 01001111 00001100 01100010 00111110 01011000 00000011 10001000 00000100 01101010 00001011 10101100 10111010 00010001 00001101 01000000 10001110 01001011 10100001 01111011 10000000 00110100 11011001 01100011 10100101 10110101 00010110 00010000 01000101 01110010 10110010 10110111 00111011 00101001 00111001 00011101 10111001 01010001 11111000 00101101 01101010 00000101 00010001 00000011 00001100 01010101 00010101 10001100 11010001 11110101 11001001 10100010 11101000 01010100 01100110 10111110 11111010 10111111 01001110 11001000 10100000 01110111 11110111 01000000 10001011 10000001 01001101 10001110 01111000 10010001 11101111 11110011 11100000

<h3 id="basic3"><b>Encrypted Private Keys</b></h3>
Private keys can be encrypted as described in [PKCS#5] using the PBES2 scheme. For example:

    let pw = Bytes("MySecret".utf8)
    let domain = Domain.instance(curve: .EC384r1)
    let (_, priv) = domain.makeKeyPair()
    let encryptedKey = priv.pemEncrypted(password: pw, cipher: .AES256)
    print(encryptedKey)

giving (for example):

    -----BEGIN ENCRYPTED PRIVATE KEY-----
    MIIBHjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI3id2VFlFxXUCAggA
    MB0GCWCGSAFlAwQBKgQQlJJQtcZ23p1Q4fXmvpS6hgSB0DBuxL/sCUc/c9NDhrHK
    /R2sbtS7rs5a9zUFwcMNV1nVUCK1SSbaCg8/BxHPfqKlAw4RcnsQtN+YD7hz5pxF
    YDcYk4mEZo7ODFkRxhKF7vLsUsRZAl2XYGIJflp03+fAWdsiNisjo/4Y/5xxWvCe
    OBzfjRpsDT4HjRgcxTtxrzvInzrJkQwyDBAkPMudIshkPOQ1LEoXhi0gVFl9jGN+
    eSLv5Wba2chf/kQcw7R4B3iiE5787wE2fWvvh4ek3oSYcLCvO/gkwgUhyA2hk3rn
    01k=
    -----END ENCRYPTED PRIVATE KEY-----

The implied encryption parameters are cipher block mode = CBC, iteration count = 2048 and salt = 8 random bytes.
The password is simply a byte array, any possible interpretation of it as a string is unspecified.
The encrypted private key is compatible with, and is readable by OpenSSL.

Private keys can be created from their PEM encodings in encrypted form.
In the example the encrypted private key was created by OpenSSL using the AES-256 cipher in CBC mode with password 'abcd'.

    let encryptedPem =
    """
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAg7pgGVDlE/xgICCAAw
    HQYJYIZIAWUDBAEqBBCFF4KWxWqhOB5Q8dOwdcPkBIGQbuj2TvlhtpMZ3ZhLBBBx
    kJfY1l09yNcJNEcvS8RX4/STXZkt5gMBgtY2DvGAKI0wkpbim+kXSjM6/hmNxY5b
    jhQapm8l8jbVGkETtYfseZXpvIT5lnBy9KtO8o3OmlRTV3xXu3KeDZakDoimfQ8G
    N7SldmFRcz171yMoIQ17ZU95uneZoogsRuMVMVUJXEh7
    -----END ENCRYPTED PRIVATE KEY-----
    """
    let privKey = try ECPrivateKey(pem: encryptedPem, password: Bytes("abcd".utf8))
    print(privKey)

giving:

    Sequence (4):
      Integer: 1
      Octet String (32): 1e 4d c5 de 0f 47 66 6b 7e 4c b8 ee e5 0f f9 6c 4a d3 4f 6f 2e 07 f7 fc e7 c8 24 dd 17 18 fd fa
      [0]:
        Object Identifier: 1.2.840.10045.3.1.7
      [1]:
        Bit String (520): 00000100 00101110 10100100 10110110 10001111 11111010 00111111 00000111 01011010 01011101 01110000 01100001 10110000 10101110 01011010 10011100 10001111 00110100 11010000 11111101 10010110 11001110 00101011 10001111 11000001 10101001 11000000 00001101 00011101 11011101 11001011 10101110 10011000 11001011 10000101 01110001 10100010 11100000 01100011 01101010 11110100 11011101 00011000 01011101 10010110 01010101 10110011 00101101 01010000 10100010 00110001 10000100 11011001 00111001 00011000 01100100 10001110 11011111 10011100 00010100 10110101 11011010 00111010 10101100 11111100

SwiftECC can read encrypted private key files provided they were encrypted with one of the ciphers AES-128, AES-192 or AES-256 in CBC mode.
<h3 id="basic4"><b>ChaChaPoly Encryption and Decryption</b></h3>
Encryption and decryption is done using the ECIES algorithm based on the ChaCha20 cipher.
Message authentication - possibly including additional authenticated data - uses Poly1305 message authentication.</br>
The encryption and decryption speed for domain EC256k1 (the bitcoin domain) measured on an iMac 2021, Apple M1 chip is about 250 Megabytes per second.
<h4><b>Example</b></h4>

    let plainText = "Hi, there!"
    let aaData = "This is the additional authenticated data"
    
    let (pub, priv) = Domain.instance(curve: .EC256k1).makeKeyPair()
    let cipherText = pub.encryptChaCha(msg: Bytes(plainText.utf8), aad: Bytes(aaData.utf8))
    
    do {
        let text = try priv.decryptChaCha(msg: cipherText, aad: Bytes(aaData.utf8))
        print(String(bytes: text, encoding: .utf8)!)
    } catch {
        print("Exception: \(error)")
    }

giving:

    Hi, there!

<h3 id="basic4"><b>AES Encryption and Decryption</b></h3>
Encryption and decryption is done using the ECIES algorithm based on the AES block cipher using one of
AES-128, AES-192 or AES-256 ciphers, depending on your choice.</br>
The following cipher block modes are supported:
<ul>
<li>GCM - Galois Counter mode. This is the default mode</li>
<li>ECB - Electronic Codebook mode with PKCS#7 padding</li>
<li>CBC - Cipher Block Chaining mode with PKCS#7 padding</li>
<li>CFB - Cipher Feedback mode</li>
<li>CTR - Counter mode</li>
<li>OFB - Output Feedback mode</li>
</ul>
The encryption and decryption speed for domain EC256k1 (the bitcoin domain) measured on an iMac 2021, Apple M1 chip
using AES-128 are shown below - units are Megabytes per second.
<table width="80%">
<tr><th align="left" width="20%">Block Mode</th><th align="right" width="40%">Encrypt</th><th align="right" width="40%">Decrypt</th></tr>
<tr><td>GCM</td><td align="right">53 MByte/Sec</td><td align="right">53 MByte/Sec</td></tr>
<tr><td>ECB</td><td align="right">30 MByte/Sec</td><td align="right">30 MByte/Sec</td></tr>
<tr><td>CBC</td><td align="right">24 MByte/Sec</td><td align="right">25 MByte/Sec</td></tr>
<tr><td>CFB</td><td align="right">23 MByte/Sec</td><td align="right">23 MByte/Sec</td></tr>
<tr><td>CTR</td><td align="right">30 MByte/Sec</td><td align="right">30 MByte/Sec</td></tr>
<tr><td>OFB</td><td align="right">29 MByte/Sec</td><td align="right">29 MByte/Sec</td></tr>
</table>
<h4><b>BlueECC Compatibility</b></h4>
Data encrypted by SwiftECC in the EC256r1 domain with AES128/GCM, in the EC384r1 domain with AES256/GCM
and in the EC521r1 domain with AES256/GCM can be decrypted with IBM's BlueECC product using curve prime256v1,
secp384r1, and secp521r1, respectively.
Likewise, data encrypted by BlueECC with curve prime256v1, secp384r1 and secp521,
can be decrypted by SwiftECC using EC256r1 with AES128/GCM, EC384r1 with AES256/GCM and EC521r1 with AES256/GCM, respectively.
<h4><b>Example</b></h4>

	import SwiftECC
	
	// You need a public key to encrypt a message and the corresponding private key to decrypt it,
	// for example from the EC163k1 domain
	
	let pemPublic163k1 =
	"""
	-----BEGIN PUBLIC KEY-----
	MEAwEAYHKoZIzj0CAQYFK4EEAAEDLAAEA6txn7CCae0d9AiGj3Rk5m9XflTCB81oe1fKZi4F4oip
	SF2u79k8TD5J
	-----END PUBLIC KEY-----
	"""
	
	let pemPrivate163k1 =
	"""
	-----BEGIN EC PRIVATE KEY-----
	MFICAQEEFNfflqz2oOd9WpxuMZ9wJTFO1sjgoAcGBSuBBAABoS4DLAAEA6txn7CCae0d9AiGj3Rk
	5m9XflTCB81oe1fKZi4F4oipSF2u79k8TD5J
	-----END EC PRIVATE KEY-----
	"""
	
	let text = "The quick brown fox jumps over the lazy dog!"
	
	do {
	  let pubKey = try ECPublicKey(pem: pemPublic163k1)
	  let privKey = try ECPrivateKey(pem: pemPrivate163k1)
	  let encryptedData = pubKey.encrypt(msg: text.data(using: .utf8)!, cipher: .AES128)
	  let decryptedData = try privKey.decrypt(msg: encryptedData, cipher: .AES128)
	  print(String(data: decryptedData, encoding: .utf8)!)
	} catch {
	  print("\(error)")
	}

giving<br/>
	
	The quick brown fox jumps over the lazy dog!

<h3 id="basic5"><b>Signing and Verifying</b></h3>
Signing data and verifying signatures is performed using the ECDSA algorithm. It is possible to generate
deterministic signatures as specificed in [RFC-6979] by setting the <i>deterministic</i> parameter to <i>true</i> in the sign operation.

The message digest used in the process is determined from the domain field size as follows:
<ul>
<li>field size <= 224: SHA2-224</li>
<li>224 < field size <= 256: SHA2-256</li>
<li>256 < field size <= 384: SHA2-384</li>
<li>384 < field size: SHA2-512</li>
</ul>
<h4><b>BlueECC Compatibility</b></h4>
Signatures created by SwiftECC in the EC256r1, EC384r1 and EC521r1 domains can be verified by IBM's BlueECC product
using curve prime256v1, secp384r1 and secp521r1, respectively. Likewise, signatures created by BlueECC with one of the curves
prime256v1, secp384r1 and secp521r1 can be verified by SwiftECC using domains EC256r1, EC384r1 and EC521r1, respectively.
<h4><b>CryptoKit Compatibility</b></h4>
Signatures created by SwiftECC in the EC256r1, EC384r1 and EC521r1 domains can be verified by Swift CryptoKit
using curve P256, P384 and P521, respectively. Likewise, signatures created by Swift CryptoKit with one of the curves
P256, P384 and P521 can be verified by SwiftECC using domains EC256r1, EC384r1 and EC521r1, respectively.
<h4><b>Example</b></h4>

	import SwiftECC
	
	// Get a predefined domain - for example brainpool BP160r1
	
	let domain = Domain.instance(curve: .BP160r1)
	
	// Create your own keys
	
	let (pubKey, privKey) = domain.makeKeyPair()
	
	// See how they look
	
	print(pubKey.asn1)
	print(privKey.asn1)
	
	// Store them in PEM format for future use
	
	let pubPEM = pubKey.pem
	let privPEM = privKey.pem
	
	let message = "The quick brown fox jumps over the lazy dog!".data(using: .utf8)!
	
	let sig = privKey.sign(msg: message)
	let ok = pubKey.verify(signature: sig, msg: message)
	print("Signature is", ok ? "good" : "wrong")

giving (for example):<br/>

	Sequence (2):
		Sequence (2):
			Object Identifier: 1.2.840.10045.2.1
			Object Identifier: 1.3.36.3.3.2.8.1.1.1
		Bit String (328): 00000100 00000011 00000111 00110011 01010100 00000001 10111100 01101111 10100001 01001000 11101000 01111100 10001111 00000110 00010010 11100111 11111010 10010001 00100100 01001000 11000110 01110001 00110100 01001000 10011110 01011110 11000000 10010001 01000110 01011010 01001110 01110000 00011011 01010111 10101011 01101010 00011011 01101100 01100100 01000100 01111101
	
	Sequence (4):
		Integer: 1
		Octet String (20): 32 96 e0 c4 d7 f5 cb 03 0c 95 63 b1 a2 c1 2f 64 4c dc d6 4c
		[0]:
			Object Identifier: 1.3.36.3.3.2.8.1.1.1
		[1]:
			Bit String (328): 00000100 00000011 00000111 00110011 01010100 00000001 10111100 01101111 10100001 01001000 11101000 01111100 10001111 00000110 00010010 11100111 11111010 10010001 00100100 01001000 11000110 01110001 00110100 01001000 10011110 01011110 11000000 10010001 01000110 01011010 01001110 01110000 00011011 01010111 10101011 01101010 00011011 01101100 01100100 01000100 01111101
	
	Signature is good

<h3 id="basic6"><b>Secret Key Agreement</b></h3>
Given your own private key and another party's public key, you can generate a byte array that can be used as a symmetric encryption key.
The other party can generate the same byte array by using his own private key and your public key.
<h4><b>Example</b></h4>

	import SwiftECC
	
	do {
		let domain = Domain.instance(curve: .EC256r1)
	
		// Party A's keys
		let (pubA, privA) = domain.makeKeyPair()
	
		// Party B's keys
		let (pubB, privB) = domain.makeKeyPair()
	
		let info: Bytes = [1, 2, 3]
		let secretA = try privA.keyAgreement(pubKey: pubB, length: 16, md: .SHA2_256, sharedInfo: info)
		let secretB = try privB.keyAgreement(pubKey: pubA, length: 16, md: .SHA2_256, sharedInfo: info)
		print(secretA)
		print(secretB)
	} catch {
		print("Exception: \(error)")
	}

giving (for example):</br>

	[92, 161, 137, 44, 47, 30, 6, 26, 43, 183, 199, 130, 19, 254, 232, 106]
	[92, 161, 137, 44, 47, 30, 6, 26, 43, 183, 199, 130, 19, 254, 232, 106]

For the key agreement to work, the two parties must agree on which domain to use, which message digest to use
and which shared information (possibly none) to use.
<h4><b>CryptoKit Compatibility</b></h4>
SwiftECC key agreement is compatible with Swift CryptoKit key agreement
in that the EC256r1, EC384r1 and EC521r1 domains correspond to CryptoKit's P256, P384 and P521 curves,
and the SHA2_256, SHA2_384 and SHA2_512 message digests correspond to CryptoKit's SHA256, SHA384 and SHA512 message digests.

To convert a CryptoKit public key - e.g. 'pubKey' - to the corresponding SwiftECC public key:</br>

	let eccKey = try ECPublickey(pem: pubKey.pemRepresentation)

To convert a SwiftECC public key - e.g. 'pubKey' - to the corresponding CryptoKit public key:</br>

	let ckKey = try P256.KeyAgreement.PublicKey(pemRepresentation: pubKey.pem)

<h3 id="basic7"><b>Creating New Domains</b></h3>
You can create your own domains as illustrated by the two examples below.
<h4><b>Example</b></h4>

This is example 3.5 from [GUIDE]. It shows how to make your own prime characteristic domain.

    import SwiftECC
    import BigInt
    
    // Create the domain
    let domain = try Domain.instance(name: "EC29", p: BInt(29), a: BInt(4), b: BInt(20), gx: BInt(1), gy: BInt(5), order: BInt(37), cofactor: 1)
	
    let p1 = Point(BInt(5), BInt(22))
    let p2 = Point(BInt(16), BInt(27))
	
    print("p1 + p2 =", try domain.addPoints(p1, p2))
    print("p1 * 2  =", try domain.multiplyPoint(p1, BInt(2)))
	
    // Inspect the domain - please refer [SEC 1] appendix C.2
    print(domain.asn1Explicit())

giving<br/>

    p1 + p2 = Point(13, 6)
    p1 * 2  = Point(14, 6)
    Sequence (6):
      Integer: 1
      Sequence (2):
        Object Identifier: 1.2.840.10045.1.1
        Integer: 29
      Sequence (2):
        Octet String (1): 04
        Octet String (1): 14
      Octet String (3): 04 01 05
      Integer: 37
      Integer: 1

<h4><b>Example</b></h4>

This is example 3.6 from [GUIDE]. It shows how to make your own characteristic 2 domain.

    import SwiftECC
    import BigInt
	
    // Reduction polynomial for x^4 + x^1 + 1    
    let rp = RP(4, 1)
    // Create the domain
    let domain = try Domain.instance(name: "EC4", rp: rp, a: BInt(8), b: BInt(9), gx: BInt(1), gy: BInt(1), order: BInt(22), cofactor: 2)
	
    let p1 = Point(BInt(2), BInt(15))
    let p2 = Point(BInt(12), BInt(12))
	
    print("p1 + p2 =", try domain.addPoints(p1, p2))
    print("p1 * 2  =", try domain.multiplyPoint(p1, BInt(2)))
	
    // Inspect the domain - please refer [SEC 1] appendix C.2
    print(domain.asn1Explicit())

giving<br/>

    p1 + p2 = Point(1, 1)
    p1 * 2  = Point(11, 2)
    Sequence (6):
      Integer: 1
      Sequence (2):
        Object Identifier: 1.2.840.10045.1.2
        Sequence (2):
          Integer: 4
          Integer: 1
      Sequence (2):
        Octet String (1): 08
        Octet String (1): 09
      Octet String (3): 04 01 01
      Integer: 22
      Integer: 2

<h3 id="basic8"><b>Elliptic Curve Arithmetic</b></h3>
SwiftECC implements the common elliptic curve arithmetic operations:
<ul>
<li>Point multiplication</li>
<li>Point addition</li>
<li>Point doubling</li>
<li>Point subtraction</li>
<li>Point negation</li>
<li>Is Point on curve?</li>
</ul>
It is also possible to encode curve points in either compressed- or uncompressed format,
as well as to do the reverse decoding.

<h2 id="keydev"><b>Key Derivation</b></h2>
SwiftECC uses the X9.63 Key Derivation Function to derive block cipher keying materiel. Please refer [SEC 1] section 3.6.
Seven cases are considered:

<h4><b>ChaCha20/Poly1305</b></h4>
KDF generates 44 bytes.

Encryption/decryption key = bytes 0 ..< 32</br>
Nonce = bytes 32 ..< 44</br>

<h4><b>AES-128/GCM block mode</b></h4>
KDF generates 32 bytes.

AES encryption/decryption key = bytes 0 ..< 16</br>
Initialization vector = bytes 16 ..< 32</br>

<h4><b>AES-192/GCM block mode</b></h4>
KDF generates 40 bytes.

AES encryption/decryption key = bytes 0 ..< 24</br>
Initialization vector = bytes 24 ..< 40</br>

<h4><b>AES-256/GCM block mode</b></h4>
KDF generates 48 bytes.

AES encryption/decryption key = bytes 0 ..< 32</br>
Initialization vector = bytes 32 ..< 48</br>

<h4><b>AES-128/Non-GCM block mode</b></h4>
KDF generates 48 bytes.

AES encryption/decryption key = bytes 0 ..< 16</br>
HMAC key = bytes 16 ..< 48</br>

<h4><b>AES-192/Non-GCM block mode</b></h4>
KDF generates 56 bytes.

AES encryption/decryption key = bytes 0 ..< 24</br>
HMAC key = bytes 24 ..< 56</br>

<h4><b>AES-256/Non-GCM block mode</b></h4>
KDF generates 64 bytes.

AES encryption/decryption key = bytes 0 ..< 32</br>
HMAC key = bytes 32 ..< 64</br>

The AES key and HMAC key can be retrieved with the ECPrivateKey method 'getKeyAndMac'.

For block modes CBC, CFB, CTR, and OFB the initialization vector (IV) is 16 zero bytes.

<h2 id="perf"><b>Performance</b></h2>
To assess the performance of SwiftECC, the signature generation and verification time and the keypair generation time
was measured on an iMac 2021, Apple M1 chip. The results are shown in the table below - units are milliseconds. The columns mean:
<ul>
<li>Sign: The time it takes to sign a short message</li>
<li>Verify: The time it takes to verify a signature for a short message</li>
<li>Keypair Generation: The time it takes to generate a public/private keypair</li>
</ul>

<table width="80%">
<tr><th align="left" width="16%">Curve</th><th align="right" width="28%">Sign</th><th align="right" width="28%">Verify</th><th align="right" width="28%">Keypair Generation</th></tr>
<tr><td>brainpoolP160r1</td><td align="right">0.7 mSec</td><td align="right">1.3 mSec</td><td align="right">2.9 mSec</td></tr>
<tr><td>brainpoolP160t1</td><td align="right">0.7 mSec</td><td align="right">1.4 mSec</td><td align="right">2.9 mSec</td></tr>
<tr><td>brainpoolP192r1</td><td align="right">0.96 mSec</td><td align="right">1.8 mSec</td><td align="right">3.9 mSec</td></tr>
<tr><td>brainpoolP192t1</td><td align="right">0.96 mSec</td><td align="right">1.9 mSec</td><td align="right">3.9 mSec</td></tr>
<tr><td>brainpoolP224r1</td><td align="right">1.3 mSec</td><td align="right">2.6 mSec</td><td align="right">5.7 mSec</td></tr>
<tr><td>brainpoolP224t1</td><td align="right">1.3 mSec</td><td align="right">2.6 mSec</td><td align="right">5.7 mSec</td></tr>
<tr><td>brainpoolP256r1</td><td align="right">1.7 mSec</td><td align="right">3.3 mSec</td><td align="right">7.4 mSec</td></tr>
<tr><td>brainpoolP256t1</td><td align="right">1.7 mSec</td><td align="right">3.3 mSec</td><td align="right">7.4 mSec</td></tr>
<tr><td>brainpoolP320r1</td><td align="right">2.9 mSec</td><td align="right">5.7 mSec</td><td align="right">13 mSec</td></tr>
<tr><td>brainpoolP320t1</td><td align="right">2.9 mSec</td><td align="right">5.5 mSec</td><td align="right">13 mSec</td></tr>
<tr><td>brainpoolP384r1</td><td align="right">4.5 mSec</td><td align="right">8.6 mSec</td><td align="right">21 mSec</td></tr>
<tr><td>brainpoolP384t1</td><td align="right">4.4 mSec</td><td align="right">8.7 mSec</td><td align="right">21 mSec</td></tr>
<tr><td>brainpoolP512r1</td><td align="right">9.2 mSec</td><td align="right">19 mSec</td><td align="right">44 mSec</td></tr>
<tr><td>brainpoolP512t1</td><td align="right">9.3 mSec</td><td align="right">18 mSec</td><td align="right">44 mSec</td></tr>
<tr><td>secp192k1</td><td align="right">0.96 mSec</td><td align="right">1.8 mSec</td><td align="right">4.0 mSec</td></tr>
<tr><td>secp192r1</td><td align="right">0.96 mSec</td><td align="right">1.9 mSec</td><td align="right">3.9 mSec</td></tr>
<tr><td>secp224k1</td><td align="right">1.3 mSec</td><td align="right">2.6 mSec</td><td align="right">5.8 mSec</td></tr>
<tr><td>secp224r1</td><td align="right">1.3 mSec</td><td align="right">2.6 mSec</td><td align="right">5.7 mSec</td></tr>
<tr><td>secp256k1</td><td align="right">1.7 mSec</td><td align="right">3.2 mSec</td><td align="right">7.4 mSec</td></tr>
<tr><td>secp256r1</td><td align="right">1.7 mSec</td><td align="right">3.3 mSec</td><td align="right">7.5 mSec</td></tr>
<tr><td>secp384r1</td><td align="right">4.5 mSec</td><td align="right">8.9 mSec</td><td align="right">21 mSec</td></tr>
<tr><td>secp521r1</td><td align="right">9.8 mSec</td><td align="right">19 mSec</td><td align="right">47 mSec</td></tr>
<tr><td>sect163k1</td><td align="right">1.2 mSec</td><td align="right">2.2 mSec</td><td align="right">5.1 mSec</td></tr>
<tr><td>sect163r2</td><td align="right">1.2 mSec</td><td align="right">2.3 mSec</td><td align="right">5.1 mSec</td></tr>
<tr><td>sect233k1</td><td align="right">2.3 mSec</td><td align="right">4.5 mSec</td><td align="right">11 mSec</td></tr>
<tr><td>sect233r1</td><td align="right">2.3 mSec</td><td align="right">4.5 mSec</td><td align="right">11 mSec</td></tr>
<tr><td>sect283k1</td><td align="right">3.5 mSec</td><td align="right">7.0 mSec</td><td align="right">17 mSec</td></tr>
<tr><td>sect283r1</td><td align="right">3.5 mSec</td><td align="right">7.1 mSec</td><td align="right">17 mSec</td></tr>
<tr><td>sect409k1</td><td align="right">8.0 mSec</td><td align="right">16 mSec</td><td align="right">41 mSec</td></tr>
<tr><td>sect409r1</td><td align="right">8.0 mSec</td><td align="right">16 mSec</td><td align="right">42 mSec</td></tr>
<tr><td>sect571k1</td><td align="right">17 mSec</td><td align="right">35 mSec</td><td align="right">92 mSec</td></tr>
<tr><td>sect571r1</td><td align="right">17 mSec</td><td align="right">34 mSec</td><td align="right">92 mSec</td></tr>
</table>

<h2 id="dep"><b>Dependencies</b></h2>

The SwiftECC package depends on the ASN1 and BigInt packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.0.1"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.2.12"),
    ],

<h2 id="ref"><b>References</b></h2>

Algorithms from the following books and papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[FILIPPO] - Filippo Valsorda: A GO IMPLEMENTATION OF POLY1305 THAT MAKES SENSE, April 2019</li>
<li>[FIPS 180-4] - FIPS PUB 180-4 - Secure Hash Standard (SHS), August 2015</li>
<li>[GCM] - The Galois/Counter Mode of Operation (GCM)</li>
<li>[GUIDE] - Hankerson, Menezes, Vanstone: Guide to Elliptic Curve Cryptography. Springer 2004</li>
<li>[KNUTH] - Donald E. Knuth: Seminumerical Algorithms. Addison-Wesley 1971</li>
<li>[NIST] - NIST Special Publication 800-38D, November 2007</li>
<li>[PKCS#5] - Password-Based Cryptography Specification - Version 2.0, September 2000</li>
<li>[RFC-6979] - Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA), August 2013</li>
<li>[RFC-8439] - ChaCha20 and Poly1305 for IETF Protocols, June 2018</li>
<li>[SAVACS] - E. Savacs, C.K. Koc: The Montgomery Modular Inverse - Revisited, July 2000</li>
<li>[SEC 1] - Standards for Efficient Cryptography 1 (SEC 1), Certicom Corp. 2009</li>
<li>[SEC 2] - Standards for Efficient Cryptography 2 (SEC 2), Certicom Corp. 2010</li>
<li>[WARREN] - Henry S. Warren, Jr.: Montgomery Multiplication, July 2012</li>
<li>[X9.62] - X9.62 - Public Key Cryptography For The Financial Services Industry, 1998</li>
</ul>
<h2 id="ack"><b>Acknowledgement</b></h2>
The AES block cipher implementation is essentially a translation to Swift of the Go Language implementation of AES.</br>
The Poly1305 implementation is based on the description in [FILIPPO].
