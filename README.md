<h2><b>SwiftECC</b></h2>

SwiftECC provides elliptic curve cryptography in Swift.
This encompasses:
<ul>
<li>Creating, loading and storing public and private keys</li>
<li>Encryption and decryption using the ECIES algorithm based on the AES block cipher and six different block modes</li>
<li>AEAD (Authenticated Encryption with Associated Data) encryption and decryption using the ECIES algorithm with the ChaCha20/Poly1305 or the AES/GCM cipher</li>
<li>Signature signing and verifying using the ECDSA algorithm, including the option of deterministic signatures</li>
<li>Secret key agreement using the Diffie-Hellman key agreement algorithm - ECDH</li>
<li>Ability to create your own domains</li>
<li>General elliptic curve arithmetic</li>
</ul>
SwiftECC requires Swift 5.0. It also requires that the Int and UInt types be 64 bit types.
Its documentation is build with Apple's DocC tool and published on GitHub Pages at this location

https://leif-ibsen.github.io/SwiftECC/documentation/swiftecc

The documentation is also available in the SwiftECC.doccarchive file.

