# Performance

## 
To assess the performance of SwiftECC, the signature generation and verification time and the keypair generation time
was measured on an iMac 2021, Apple M1 chip. The results are shown in the table below - units are milliseconds. The columns mean:

* **Sign:** The time it takes to sign a short message
* **Verify:** The time it takes to verify a signature for a short message
* **Keypair Generation:** The time it takes to generate a public / private keypair

| Curve           | Sign      | Verify   | Keypair Generation |
|:----------------|----------:|---------:|-------------------:|
| brainpoolP160r1 | 0.7 mSec  | 1.3 mSec | 2.9 mSec           |
| brainpoolP160t1 | 0.7 mSec  | 1.4 mSec | 2.9 mSec           |
| brainpoolP192r1 | 0.96 mSec | 1.8 mSec | 3.9 mSec           |
| brainpoolP192t1 | 0.96 mSec | 1.9 mSec | 3.9 mSec           |
| brainpoolP224r1 | 1.3 mSec  | 2.6 mSec | 5.7 mSec           |
| brainpoolP224t1 | 1.3 mSec  | 2.6 mSec | 5.7 mSec           |
| brainpoolP256r1 | 1.7 mSec  | 3.3 mSec | 7.4 mSec           |
| brainpoolP256t1 | 1.7 mSec  | 3.3 mSec | 7.4 mSec           |
| brainpoolP320r1 | 2.9 mSec  | 5.7 mSec | 13 mSec            |
| brainpoolP320t1 | 2.9 mSec  | 5.5 mSec | 13 mSec            |
| brainpoolP384r1 | 4.5 mSec  | 8.6 mSec | 21 mSec            |
| brainpoolP384t1 | 4.4 mSec  | 8.7 mSec | 21 mSec            |
| brainpoolP512r1 | 9.2 mSec  | 19 mSec  | 44 mSec            |
| brainpoolP512t1 | 9.3 mSec  | 18 mSec  | 44 mSec            |
| secp192k1       | 0.96 mSec | 1.8 mSec | 4.0 mSec           |
| secp192r1       | 0.96 mSec | 1.9 mSec | 3.9 mSec           |
| secp224k1       | 1.3 mSec  | 2.6 mSec | 5.8 mSec           |
| secp224r1       | 1.3 mSec  | 2.6 mSec | 5.7 mSec           |
| secp256k1       | 1.7 mSec  | 3.2 mSec | 7.4 mSec           |
| secp256r1       | 1.7 mSec  | 3.3 mSec | 7.5 mSec           |
| secp384r1       | 4.5 mSec  | 8.9 mSec | 21 mSec            |
| secp521r1       | 9.8 mSec  | 19 mSec  | 47 mSec            |
| sect163k1       | 1.2 mSec  | 2.2 mSec | 5.1 mSec           |
| sect163r2       | 1.2 mSec  | 2.3 mSec | 5.1 mSec           |
| sect233k1       | 2.3 mSec  | 4.5 mSec | 11 mSec            |
| sect233r1       | 2.3 mSec  | 4.5 mSec | 11 mSec            |
| sect283k1       | 3.5 mSec  | 7.0 mSec | 17 mSec            |
| sect283r1       | 3.5 mSec  | 7.1 mSec | 17 mSec            |
| sect409k1       | 8.0 mSec  | 16 mSec  | 41 mSec            |
| sect409r1       | 8.0 mSec  | 16 mSec  | 42 mSec            |
| sect571k1       | 17 mSec   | 35 mSec  | 92 mSec            |
| sect571r1       | 17 mSec   | 34 mSec  | 92 mSec            |

