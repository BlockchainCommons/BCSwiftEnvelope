// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "Envelope",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "Envelope",
            targets: ["Envelope"]),
    ],
    dependencies: [
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents.git", from: "1.0.0"),
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "5.0.0"),
        .package(url: "https://github.com/WolfMcNally/Graph.git", from: "0.1.0"),
        .package(url: "https://github.com/WolfMcNally/GraphMermaid.git", from: "0.1.0"),
        .package(url: "https://github.com/WolfMcNally/GraphDot.git", from: "0.1.0"),
        .package(url: "https://github.com/WolfMcNally/WolfLorem.git", from: "2.0.0"),
        .package(url: "https://github.com/WolfMcNally/TreeDistance.git", from: "0.1.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "Envelope",
            dependencies: [
                "Graph",
                "GraphMermaid",
                "GraphDot",
                "TreeDistance",
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
