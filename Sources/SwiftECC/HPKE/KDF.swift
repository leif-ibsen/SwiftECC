//
//  KDF.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 20/06/2023.
//

struct KDFStructure {
    
    let md: MessageDigest
    let suite_id: Bytes
    
    init(_ kdf: KDF, _ suite_id: Bytes) {
        switch kdf {
        case .KDF256:
            self.md = MessageDigest(.SHA2_256)
        case .KDF384:
            self.md = MessageDigest(.SHA2_384)
        case .KDF512:
            self.md = MessageDigest(.SHA2_512)
        }
        self.suite_id = suite_id
    }
    
    func extract(_ salt: Bytes, _ ikm: Bytes) -> Bytes {
        return HMac(self.md, salt.count > 0 ? salt : Bytes(repeating: 0, count: md.digestLength)).doFinal(ikm)
    }
    
    func expand(_ prk: Bytes, _ info: Bytes, _ L: Int) -> Bytes {
        assert(0 <= L && L <= self.md.digestLength * 255)
        let hMac = HMac(self.md, prk)
        let (q, r) = L.quotientAndRemainder(dividingBy: md.digestLength)
        let n = r == 0 ? q : q + 1
        var t: Bytes = []
        var T: Bytes = []
        var x = Byte(0)
        for _ in 0 ..< n {
            x += 1
            t = hMac.doFinal(t + info + [x])
            hMac.reset()
            T += t
        }
        return Bytes(T[0 ..< L])
    }
    
    func labeledExtract(_ salt: Bytes, _ label: Bytes, _ ikm: Bytes) -> Bytes {
        let labeled_ikm: Bytes = "HPKE-v1".utf8 + self.suite_id + label + ikm
        return extract(salt, labeled_ikm)
    }

    func labeledExpand(_ prk: Bytes, _ label: Bytes, _ info: Bytes, _ L: Int) -> Bytes {
        let labeled_info: Bytes = [Byte((L >> 8) & 0xff), Byte(L & 0xff)] + "HPKE-v1".utf8 + self.suite_id + label + info
        return expand(prk, labeled_info, L)
    }

 }
