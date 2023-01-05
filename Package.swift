// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "Envelope",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "Envelope",
            targets: ["Envelope"]),
    ],
    dependencies: [
        .package(url: "https://github.com/BlockchainCommons/BCSwiftSecureComponents.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "4.0.0"),
        .package(url: "https://github.com/WolfMcNally/Graph.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/GraphMermaid.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/GraphDot.git", branch: "master"),
        .package(url: "https://github.com/WolfMcNally/WolfLorem.git", from: "2.0.0"),
        .package(url: "https://github.com/WolfMcNally/TreeDistance.git", branch: "master"),
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
