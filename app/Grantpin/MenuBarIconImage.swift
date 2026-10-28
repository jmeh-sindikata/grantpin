import AppKit
import SwiftUI
import GrantpinKit

/// Draws the menu bar icon for a `MenuBarIcon` (docs/UI-SPEC.md 3.1).
///
/// States without a badge are the template asset `MenuBarIcon`, which the menu
/// bar tints for light, dark and a wallpaper-tinted bar. A badge needs colour,
/// and a template image has none, so those states are one non-template image
/// drawn by a handler: the glyph in the label colour of the appearance it is
/// drawn with (AppKit runs the handler again when the appearance changes), a
/// transparent ring cut around the dot so it reads on any bar, and the dot in
/// the system red or orange.
@MainActor
enum MenuBarIconImage {
    static let size = NSSize(width: 18, height: 18)

    /// One image per badged state, made once: the label's body must hand the
    /// status item the same image for the same state, not a new one on every
    /// evaluation. The drawing handler still runs per appearance.
    private static var cache = [MenuBarIcon: NSImage]()

    /// The badge image; nil for a state that stays a template.
    static func badged(_ icon: MenuBarIcon) -> NSImage? {
        guard !icon.usesTemplateImage else { return nil }
        if let cached = cache[icon] { return cached }
        guard let glyph = NSImage(named: "MenuBarIcon") else { return nil }
        let image = NSImage(size: size, flipped: false) { rect in
            glyph.draw(in: rect)
            NSColor.labelColor.withAlphaComponent(icon.subdued ? 0.55 : 1).set()
            rect.fill(using: .sourceIn)

            let center = NSPoint(x: rect.maxX - 4, y: rect.maxY - 4)
            func disc(_ radius: CGFloat) -> NSBezierPath {
                NSBezierPath(ovalIn: NSRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2))
            }
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current?.compositingOperation = .destinationOut
            NSColor.black.setFill()
            disc(4.75).fill()
            NSGraphicsContext.restoreGraphicsState()
            (icon.badge == .error ? NSColor.systemRed : NSColor.systemOrange).setFill()
            disc(3.5).fill()
            return true
        }
        image.isTemplate = false
        image.accessibilityDescription = icon.label
        cache[icon] = image
        return image
    }
}

/// The label of the `MenuBarExtra`. Equatable, so an evaluation of the label
/// for the same state does not rebuild it.
struct MenuBarIconView: View, Equatable {
    let icon: MenuBarIcon

    var body: some View {
        if let image = MenuBarIconImage.badged(icon) {
            Image(nsImage: image)
        } else {
            Image("MenuBarIcon")
                .opacity(icon.subdued ? 0.6 : 1)
        }
    }
}
