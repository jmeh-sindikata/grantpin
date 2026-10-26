// swift-tools-version:5.9
import PackageDescription

// GrantpinKit holds everything of the menu-bar app that is not UI: the daemon
// socket client, the wire models and the socket-path resolver. It has no UI
// imports, so `swift test` runs it with no signing identity and no Xcode GUI
// (make ci-app). See docs/UI-SPEC.md section 5.1.
let package = Package(
    name: "GrantpinKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GrantpinKit", targets: ["GrantpinKit"]),
    ],
    targets: [
        .target(name: "GrantpinKit"),
        .testTarget(name: "GrantpinKitTests", dependencies: ["GrantpinKit"]),
    ]
)
