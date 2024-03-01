// swift-tools-version: 5.9

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
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents.git", from: "8.0.0"),
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "6.0.0"),
        .package(url: "https://github.com/WolfMcNally/Graph.git", from: "1.0.0"),
        .package(url: "https://github.com/WolfMcNally/GraphMermaid.git", from: "1.0.0"),
        .package(url: "https://github.com/WolfMcNally/GraphDot.git", from: "1.0.0"),
        .package(url: "https://github.com/WolfMcNally/WolfLorem.git", from: "3.0.0"),
        .package(url: "https://github.com/WolfMcNally/TreeDistance.git", from: "1.0.0"),
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
