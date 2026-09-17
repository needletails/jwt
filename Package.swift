// swift-tools-version:6.4
import PackageDescription

let package = Package(
    name: "jwt",
    platforms: [
        .macOS("26.2"),
        .iOS("26.2"),
        .tvOS("26.2"),
        .watchOS("26.2"),
    ],
    products: [
        .library(name: "JWT", targets: ["JWT"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.1.0"),
        .package(url: "https://github.com/vapor/vapor.git", exact: "5.0.0-beta.2"),
    ],
    targets: [
        .target(
            name: "JWT",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Vapor", package: "vapor"),
            ]
        ),
        .testTarget(
            name: "JWTTests",
            dependencies: [
                .target(name: "JWT"),
                .product(name: "VaporTesting", package: "vapor"),
            ]
        ),
    ]
)
