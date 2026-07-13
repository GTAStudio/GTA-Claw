import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else {
    fputs("usage: render.swift OUTPUT.png\n", stderr)
    exit(64)
}

let size = 1024
guard let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: size,
    pixelsHigh: size,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: size * 4,
    bitsPerPixel: 32
) else {
    fputs("failed to allocate icon bitmap\n", stderr)
    exit(1)
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)

let canvas = NSRect(x: 0, y: 0, width: size, height: size)
NSColor(calibratedRed: 0.055, green: 0.090, blue: 0.160, alpha: 1).setFill()
NSBezierPath(roundedRect: canvas.insetBy(dx: 44, dy: 44), xRadius: 210, yRadius: 210).fill()

let ringRect = canvas.insetBy(dx: 205, dy: 205)
let ring = NSBezierPath(ovalIn: ringRect)
ring.lineWidth = 66
NSColor(calibratedRed: 0.145, green: 0.710, blue: 0.790, alpha: 1).setStroke()
ring.stroke()

let mark = NSBezierPath()
mark.move(to: NSPoint(x: 330, y: 665))
mark.line(to: NSPoint(x: 512, y: 360))
mark.line(to: NSPoint(x: 694, y: 665))
mark.move(to: NSPoint(x: 410, y: 535))
mark.line(to: NSPoint(x: 614, y: 535))
mark.lineCapStyle = .round
mark.lineJoinStyle = .round
mark.lineWidth = 72
NSColor.white.setStroke()
mark.stroke()

NSGraphicsContext.restoreGraphicsState()

guard let png = bitmap.representation(using: .png, properties: [:]) else {
    fputs("failed to encode icon PNG\n", stderr)
    exit(1)
}

do {
    try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]), options: .atomic)
} catch {
    fputs("failed to write icon: \(error)\n", stderr)
    exit(1)
}
