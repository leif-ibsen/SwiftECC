//
//  Base64Test.swift
//  AECTests
//
//  Created by Leif Ibsen on 06/01/2020.
//

import XCTest

class Base64Test: XCTestCase {

    func doTest(_ s1: String, _ s2: String) throws {
        let s = Base64.encode(Array(s1.utf8))
        XCTAssertEqual(s2, s)
        let x = try Base64.decode(s)
        XCTAssertEqual(s1, String(bytes: x, encoding: .utf8))
    }

    func test1() throws {
        try doTest("", "")
        try doTest("f", "Zg==")
        try doTest("fo", "Zm8=")
        try doTest("foo", "Zm9v")
        try doTest("foob", "Zm9vYg==")
        try doTest("fooba", "Zm9vYmE=")
        try doTest("foobar", "Zm9vYmFy")
    }

}



