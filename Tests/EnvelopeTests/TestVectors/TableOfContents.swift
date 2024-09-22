import Foundation

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
