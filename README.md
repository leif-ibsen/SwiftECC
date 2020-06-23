<h2><b>Description</b></h2>

SwiftECC provides elliptic curve cryptography in Swift.
This encompasses:
<ul>
<li>Encryption and decryption using the ECIES algorithm based on the AES block cipher</li>
<li>Signature signing and verifying using the ECDSA algorithm, including the option of deterministic signatures</li>
<li>General elliptic curve arithmetic</li>
</ul>
<h2><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftECC", from: "1.0.1"),
	  ]

<h2><b>Basics</b></h2>
The basic concept in SwiftECC is the Elliptic Curve Domain, represented by the Domain class.
Please, refer section 3.1 in [SEC 1] that describes the domain concept in detail.

There are 18 predefined NIST domains
and 14 predefined Brainpool domains in SwiftECC,
and it is possible to create your own characteristic 2, and odd prime characteristic domains.

You need a public key in order to encrypt a message or verify a signature, and you need a private key in order to decrypt a message or sign a message.
Given a domain, you can generate public/private key pairs or you can load them from the PEM- or DER encoding of existing keys.

<h3><b>Encryption and Decryption</b></h3>
Encryption and decryption is done using the ECIES algorithm based on AES block cipher. The algorithm uses one of
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
The encryption and decryption speed for domain EC256k1 (the bitcoin domain) was measured on a MacBook Pro 2018, 2,2 GHz 6-Core Intel Core i7.
The results using AES-128 are shown in the table below - units are Megabytes per second.
<table width="80%">
<tr><th align="left" width="20%">Block Mode</th><th align="right" width="40%">Encrypt</th><th align="right" width="40%">Decrypt</th></tr>
<tr><td>GCM</td><td align="right">26 MByte/Sec</td><td align="right">26 MByte/Sec</td></tr>
<tr><td>ECB</td><td align="right">19 MByte/Sec</td><td align="right">19 MByte/Sec</td></tr>
<tr><td>CBC</td><td align="right">14 MByte/Sec</td><td align="right">16 MByte/Sec</td></tr>
<tr><td>CFB</td><td align="right">20 MByte/Sec</td><td align="right">20 MByte/Sec</td></tr>
<tr><td>CTR</td><td align="right">21 MByte/Sec</td><td align="right">21 MByte/Sec</td></tr>
<tr><td>OFB</td><td align="right">25 MByte/Sec</td><td align="right">26 MByte/Sec</td></tr>
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

<h3><b>Signing and Verifying</b></h3>
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
<h4><b>Example</b></h4>

	import SwiftECC
	
	// Get a predefined domain - for example brainpoolP160r1
	
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

<h3><b>Creating Domains</b></h3>
You can create your own domains as illustrated by the two examples below.
<h4><b>Example</b></h4>

This is example 3.5 from [GUIDE]. It shows how to make your own prime characteristic domain.

    import SwiftECC
    import BigInt
    
    // Create the domain
    let domain = try Domain.instance(name: "EC29", p: BInt(29), a: BInt(4), b: BInt(20), gx: BInt(1), gy: BInt(5), order: BInt(37), cofactor: 1)
	
    let p1 = Point(BInt(5), BInt(22))
    let p2 = Point(BInt(16), BInt(27))
	
    print("p1 + p2 =", domain.add(p1, p2))
    print("p1 * 2  =", domain.multiply(p1, BInt(2)))
	
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
	
    // Reduction polynomial for x^4 + x + 1    
    let rp = RP(4, 1)
    // Create the domain
    let domain = try Domain.instance(name: "EC4", rp: rp, a: BInt(8), b: BInt(9), gx: BInt(1), gy: BInt(1), order: BInt(22), cofactor: 2)
	
    let p1 = Point(BInt(2), BInt(15))
    let p2 = Point(BInt(12), BInt(12))
	
    print("p1 + p2 =", domain.add(p1, p2))
    print("p1 * 2  =", domain.multiply(p1, BInt(2)))
	
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

<h3><b>Elliptic Curve Arithmetic</b></h3>
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

<h2><b>Key Derivation</b></h2>
SwiftECC uses the X9.63 Key Derivation Function to derive block cipher keying materiel. Please refer [SEC 1] section 3.6.
Six cases are considered:

<h4><b>AES-128/GCM block mode</b></h4>
KDF generates 32 bytes.

Encryption/decryption key = bytes 0 ..< 16</br>
Initialization vector = bytes 16 ..< 32</br>

<h4><b>AES-192/GCM block mode</b></h4>
KDF generates 40 bytes.

Encryption/decryption key = bytes 0 ..< 24</br>
Initialization vector = bytes 24 ..< 40</br>

<h4><b>AES-256/GCM block mode</b></h4>
KDF generates 48 bytes.

Encryption/decryption key = bytes 0 ..< 32</br>
Initialization vector = bytes 32 ..< 48</br>

<h4><b>AES-128/Non-GCM block mode</b></h4>
KDF generates 48 bytes.

Encryption/decryption key = bytes 0 ..< 16</br>
HMAC key = bytes 16 ..< 48</br>

<h4><b>AES-192/Non-GCM block mode</b></h4>
KDF generates 56 bytes.

Encryption/decryption key = bytes 0 ..< 24</br>
HMAC key = bytes 24 ..< 56</br>

<h4><b>AES-256/Non-GCM block mode</b></h4>
KDF generates 64 bytes.

Encryption/decryption key = bytes 0 ..< 32</br>
HMAC key = bytes 32 ..< 64</br>

For block modes CBC, CFB, CTR, and OFB the initialization vector (IV) is 16 zero bytes.

<h2><b>Performance</b></h2>
To assess the performance of SwiftECC, the signature generation and verification time and the keypair generation time
was measured on a MacBook Pro 2018, 2,2 GHz 6-Core Intel Core i7. The results are shown in the table below - units are milliseconds. The columns mean:
<ul>
<li>Sign: The time it takes to sign a short message</li>
<li>Verify: The time it takes to verify a signature for a short message</li>
<li>Keypair Generation: The time it takes to generate a public/private keypair</li>
</ul>

<table width="80%">
<tr><th align="left" width="16%">Curve</th><th align="right" width="28%">Sign</th><th align="right" width="28%">Verify</th><th align="right" width="28%">Keypair Generation</th></tr>
<tr><td>brainpoolP160r1</td><td align="right">1.4 mSec</td><td align="right">2.5 mSec</td><td align="right">5.1 mSec</td></tr>
<tr><td>brainpoolP160t1</td><td align="right">1.4 mSec</td><td align="right">2.4 mSec</td><td align="right">5.1 mSec</td></tr>
<tr><td>brainpoolP192r1</td><td align="right">1.7 mSec</td><td align="right">3.0 mSec</td><td align="right">6.3 mSec</td></tr>
<tr><td>brainpoolP192t1</td><td align="right">1.7 mSec</td><td align="right">3.1 mSec</td><td align="right">6.4 mSec</td></tr>
<tr><td>brainpoolP224r1</td><td align="right">2.3 mSec</td><td align="right">4.3 mSec</td><td align="right">9.4 mSec</td></tr>
<tr><td>brainpoolP224t1</td><td align="right">2.3 mSec</td><td align="right">4.3 mSec</td><td align="right">9.4 mSec</td></tr>
<tr><td>brainpoolP256r1</td><td align="right">2.7 mSec</td><td align="right">5.1 mSec</td><td align="right">11 mSec</td></tr>
<tr><td>brainpoolP256t1</td><td align="right">2.7 mSec</td><td align="right">5.0 mSec</td><td align="right">11 mSec</td></tr>
<tr><td>brainpoolP320r1</td><td align="right">4.2 mSec</td><td align="right">7.7 mSec</td><td align="right">18 mSec</td></tr>
<tr><td>brainpoolP320t1</td><td align="right">4.2 mSec</td><td align="right">7.8 mSec</td><td align="right">18 mSec</td></tr>
<tr><td>brainpoolP384r1</td><td align="right">6.0 mSec</td><td align="right">11 mSec</td><td align="right">27 mSec</td></tr>
<tr><td>brainpoolP384t1</td><td align="right">6.1 mSec</td><td align="right">11 mSec</td><td align="right">27 mSec</td></tr>
<tr><td>brainpoolP512r1</td><td align="right">11 mSec</td><td align="right">21 mSec</td><td align="right">52 mSec</td></tr>
<tr><td>brainpoolP512t1</td><td align="right">11 mSec</td><td align="right">21 mSec</td><td align="right">52 mSec</td></tr>
<tr><td>secp192k1</td><td align="right">1.6 mSec</td><td align="right">3.0 mSec</td><td align="right">6.2 mSec</td></tr>
<tr><td>secp192r1</td><td align="right">1.6 mSec</td><td align="right">3.0 mSec</td><td align="right">6.3 mSec</td></tr>
<tr><td>secp224k1</td><td align="right">2.3 mSec</td><td align="right">4.2 mSec</td><td align="right">9.5 mSec</td></tr>
<tr><td>secp224r1</td><td align="right">2.3 mSec</td><td align="right">4.2 mSec</td><td align="right">9.4 mSec</td></tr>
<tr><td>secp256k1</td><td align="right">2.7 mSec</td><td align="right">5.2 mSec</td><td align="right">11 mSec</td></tr>
<tr><td>secp256r1</td><td align="right">2.7 mSec</td><td align="right">5.0 mSec</td><td align="right">11 mSec</td></tr>
<tr><td>secp384r1</td><td align="right">6.1 mSec</td><td align="right">11 mSec</td><td align="right">27 mSec</td></tr>
<tr><td>secp521r1</td><td align="right">11 mSec</td><td align="right">21 mSec</td><td align="right">51 mSec</td></tr>
<tr><td>sect163k1</td><td align="right">1.9 mSec</td><td align="right">3.6 mSec</td><td align="right">7.8 mSec</td></tr>
<tr><td>sect163r2</td><td align="right">1.9 mSec</td><td align="right">3.6 mSec</td><td align="right">7.9 mSec</td></tr>
<tr><td>sect233k1</td><td align="right">3.5 mSec</td><td align="right">6.9 mSec</td><td align="right">15 mSec</td></tr>
<tr><td>sect233r1</td><td align="right">3.5 mSec</td><td align="right">6.4 mSec</td><td align="right">15 mSec</td></tr>
<tr><td>sect283k1</td><td align="right">5.3 mSec</td><td align="right">10 mSec</td><td align="right">25 mSec</td></tr>
<tr><td>sect283r1</td><td align="right">5.3 mSec</td><td align="right">9.8 mSec</td><td align="right">25 mSec</td></tr>
<tr><td>sect409k1</td><td align="right">11 mSec</td><td align="right">22 mSec</td><td align="right">57 mSec</td></tr>
<tr><td>sect409r1</td><td align="right">11 mSec</td><td align="right">21 mSec</td><td align="right">58 mSec</td></tr>
<tr><td>sect571k1</td><td align="right">23 mSec</td><td align="right">45 mSec</td><td align="right">126 mSec</td></tr>
<tr><td>sect571r1</td><td align="right">23 mSec</td><td align="right">46 mSec</td><td align="right">126 mSec</td></tr>
</table>

<h2><b>Dependencies</b></h2>

SwiftECC requires Swift 5.0.

The SwiftECC package depends on the ASN1 and BigInt packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "1.2.1"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.1.2"),
    ],

<h2><b>References</b></h2>

Algorithms from the following books and papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[CRANDALL] - Crandall and Pomerance: Prime Numbers - A Computational Perspective. Second Edition, Springer 2005</li>
<li>[GUIDE] - Hankerson, Menezes, Vanstone: Guide to Elliptic Curve Cryptography. Springer 2004</li>
<li>[KNUTH] - Donald E. Knuth: Seminumerical Algorithms. Addison-Wesley 1971</li>
<li>[RFC-6979] - Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA), August 2013</li>
<li>[SAVACS] - E. Savacs, C.K. Koc: The Montgomery Modular Inverse - Revisited, July 2000</li>
<li>[SEC 1] - Standards for Efficient Cryptography 1 (SEC 1), Certicom Corp. 2009</li>
<li>[SEC 2] - Standards for Efficient Cryptography 2 (SEC 2), Certicom Corp. 2010</li>
<li>[WARREN] - Henry S. Warren, Jr.: Montgomery Multiplication, July 2012</li>
<li>[X9.62] - X9.62 - Public Key Cryptography For The Financial Services Industry, 1998</li>
</ul>
<h2><b>Acknowledgement</b></h2>
The AES block cipher implementation is essentially a translation to Swift of the Go Language implementation of AES.
