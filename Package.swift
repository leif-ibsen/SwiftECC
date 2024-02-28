// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftECC",
    platforms: [.macOS(.v10_15), .iOS(.v13), .watchOS(.v8)], // Due to the use of the CryptoKit framework
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftECC",
            targets: ["SwiftECC"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.5.0"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.16.0"),
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.4.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftECC",
            dependencies: ["BigInt", "ASN1", "Digest"]),
        .testTarget(
            name: "SwiftECCTests",
            dependencies: ["SwiftECC"]),
    ]
)
