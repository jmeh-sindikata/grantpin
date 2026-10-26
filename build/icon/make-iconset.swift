// Renders build/icon/grantpin-app-icon.png onto Apple's macOS icon grid (artwork
// scaled to 824/1024 and centred on a transparent canvas) and writes the ten
// AppIcon.appiconset PNGs. Usage: swift make-iconset.swift <src.png> <appiconset dir>
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let args = CommandLine.arguments
guard args.count == 3,
      let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: args[1]) as CFURL, nil),
      let art = CGImageSourceCreateImageAtIndex(src, 0, nil) else {
    FileHandle.standardError.write(Data("usage: make-iconset.swift <src.png> <appiconset dir>\n".utf8)); exit(2)
}
let outDir = URL(fileURLWithPath: args[2])

func render(_ px: Int) -> CGImage {
    let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.interpolationQuality = .high
    let side = CGFloat(px) * 824 / 1024
    let off = (CGFloat(px) - side) / 2
    ctx.draw(art, in: CGRect(x: off, y: off, width: side, height: side))
    return ctx.makeImage()!
}

var images: [String] = []
for pt in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = "icon_\(pt)x\(pt)\(scale == 2 ? "@2x" : "").png"
        let img = render(pt * scale)
        let dest = CGImageDestinationCreateWithURL(outDir.appendingPathComponent(name) as CFURL, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, img, nil)
        guard CGImageDestinationFinalize(dest) else { print("failed \(name)"); exit(1) }
        images.append("    {\"filename\":\"\(name)\",\"idiom\":\"mac\",\"scale\":\"\(scale)x\",\"size\":\"\(pt)x\(pt)\"}")
    }
}
let json = "{\n  \"images\":[\n" + images.joined(separator: ",\n") + "\n  ],\n  \"info\":{\"author\":\"xcode\",\"version\":1}\n}\n"
try json.write(to: outDir.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)
