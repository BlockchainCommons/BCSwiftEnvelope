// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Envelope",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
        .macCatalyst(.v15)
    ],
    products: [
        .library(
            name: "Envelope",
            targets: ["Envelope"]),
    ],
    dependencies: [
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents.git", from: "9.0.0"),
        .package(url: "https://github.com/BlockchainCommons/BCSwiftKnownValues.git", from: "0.2.4"),
        .package(url: "https://github.com/WolfMcNally/WolfBase.git", from: "7.0.0"),
        .package(url: "https://github.com/WolfMcNally/Graph.git", from: "2.0.0"),
        .package(url: "https://github.com/WolfMcNally/GraphMermaid.git", from: "2.0.0"),
        .package(url: "https://github.com/WolfMcNally/GraphDot.git", from: "2.0.0"),
        .package(url: "https://github.com/WolfMcNally/WolfLorem.git", from: "4.0.0"),
        .package(url: "https://github.com/WolfMcNally/TreeDistance.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "Envelope",
            dependencies: [
                "Graph",
                "GraphMermaid",
                "GraphDot",
                "TreeDistance",
                .product(name: "KnownValues", package: "BCSwiftKnownValues"),
                .product(name: "SecureComponents", package: "BCSwiftSecureComponents"),
            ]),
        .testTarget(
            name: "EnvelopeTests",
            dependencies: [
                "Envelope",
                "WolfBase",
                "WolfLorem",
                .product(name: "SecureComponents", package: "BCSwiftSecureComponents"),
            ]),
    ]
)
