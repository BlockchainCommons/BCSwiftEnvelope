import Foundation

let packageRootPath = URL(fileURLWithPath: String(URL(fileURLWithPath: #filePath).pathComponents
    .prefix(while: { $0 != "Tests" }).joined(separator: "/").dropFirst()))
let docsPath = packageRootPath.appendingPathComponent("Sources/Envelope/Envelope.docc")

func writeDocFile(_ filename: String, _ result: String) throws {
    #if os(macOS)
    let filePath = docsPath.appendingPathComponent(filename + ".md")
    try result.write(to: filePath, atomically: true, encoding: .utf8)
    #endif
}
