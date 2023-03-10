import Foundation
import XCTest

//final class TableOfContents: XCTestCase {
//    func testGenerateTableOfContents() {
//        (0..<tocItems.count).forEach {
//            print(formatTableOfContents(itemIndex: $0))
//        }
//    }
//}
//
//let tocItems: [(title: String, filename: String)] = [
//    ("Envelope Introduction", "INTRODUCTION.md"),
//    ("Envelope Overview", "OVERVIEW.md"),
//    ("Envelope Notation", "ENVELOPE-NOTATION.md"),
//    ("Output Formats", "OUTPUT-FORMATS.md"),
//    ("Envelope Expressions", "ENVELOPE-EXPRESSIONS.md"),
//    ("Definitions", "DEFINITIONS.md"),
//    ("Examples", "EXAMPLES.md"),
//    ("Noncorrelation", "NONCORRELATION.md"),
//    ("Elision and Redaction", "ELISION-REDACTION.md"),
//    ("Existence Proofs", "EXISTENCE-PROOFS.md"),
//    ("Diffing Envelopes", "DIFFING.md"),
//    ("Appendix A: Envelope Test Vectors", "A-ENVELOPE-TEST-VECTORS.md"),
//    ("Appendix B: Envelope SSKR Test Vectors", "B-ENVELOPE-SSKR-TEST-VECTORS.md"),
//]
//
//func tocFilename(at index: Int) -> String {
//    "\(pad: index, toWidth: 2)-\(tocItems[index].filename)"
//}

//fileprivate func item(itemIndex: Int, index: Int) -> String {
//    let title = tocItems[index].title
//    let target = tocFilename(at: index)
//    if index == itemIndex {
//        return "\(title): This document"
//    } else {
//        return link(title, target)
//    }
//}

@StringBuilder
func documentHeader(_ name: String) -> String {
    header1(name)
}

fileprivate extension String.StringInterpolation {
    mutating func appendInterpolation(_ value: Date) {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium

        let dateString = formatter.string(from: value)
        appendLiteral(dateString)
    }
}
