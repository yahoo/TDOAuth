// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "TDOAuth",
    platforms: [
        .iOS(.v9),
        .tvOS(.v11),
        .watchOS(.v3),
        .macOS(.v10_10)
    ],
    products: [
        .library(
            name: "TDOAuth",
            targets: ["TDOAuth"]),
        .library(
            name: "TDOAuthSwift",
            targets: ["TDOAuthSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/mxcl/OMGHTTPURLRQ.git", .upToNextMajor(from: "3.3.0"))
    ],
    targets: [
        .target(
            name: "TDOAuth",
            dependencies: [
                "TDOAuthCompat"
            ],
            path: "Source/compat",
            exclude: [
                "Compat.swift"
            ],
            publicHeadersPath: "."),
        .target(
            name: "TDOAuthCompat",
            dependencies: [
                "TDOAuthSwift"
            ],
            path: "Source/compat",
            exclude: [
                "TDOAuth.h",
                "TDOAuth.m"
            ]),
        .target(
            name: "TDOAuthSwift",
            dependencies: [
                "OMGHTTPURLRQ"
            ],
            path: "Source",
            exclude: [
                "compat/TDOAuth.h",
                "compat/TDOAuth.m",
                "compat/Compat.swift"
            ]),
    ]
)
