import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 3 else {
    FileHandle.standardError.write(Data("用法：make-app-icon 原图.png 输出.iconset\n".utf8))
    exit(64)
}

let sourceURL = URL(fileURLWithPath: CommandLine.arguments[1])
let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
guard let source = CGImageSourceCreateWithURL(sourceURL as CFURL, nil),
      let master = CGImageSourceCreateImageAtIndex(source, 0, nil),
      master.width == master.height, master.width >= 1024 else {
    FileHandle.standardError.write(Data("原图必须是边长至少 1024 像素的方形图片。\n".utf8))
    exit(65)
}

try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!

for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = points * scale
        let suffix = scale == 1 ? "" : "@2x"
        let file = directory.appendingPathComponent("icon_\(points)x\(points)\(suffix).png")
        guard let canvas = CGContext(data: nil, width: pixels, height: pixels,
                                     bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace,
                                     bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
              let target = CGImageDestinationCreateWithURL(file as CFURL, UTType.png.identifier as CFString, 1, nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        canvas.interpolationQuality = .high
        canvas.draw(master, in: CGRect(x: 0, y: 0, width: pixels, height: pixels))
        guard let icon = canvas.makeImage() else { throw CocoaError(.fileWriteUnknown) }
        CGImageDestinationAddImage(target, icon, nil)
        guard CGImageDestinationFinalize(target) else { throw CocoaError(.fileWriteUnknown) }
    }
}
