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
    ],
    dependencies: [
        .package(url: "https://github.com/mxcl/OMGHTTPURLRQ.git", .upToNextMajor(from: "3.3.0"))
    ],
    targets: [
        .target(
            name: "TDOAuth",
            dependencies: [
                .product(name: "OMGHTTPURLRQUserAgent", package: "OMGHTTPURLRQ")
            ],
            path: "Source"),
    ]
)
