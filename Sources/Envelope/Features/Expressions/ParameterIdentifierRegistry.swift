import Foundation

public extension ParameterIdentifier {
    static let blank = Self.known(1)
    static let lhs = Self.known(2)
    static let rhs = Self.known(3)
    
    static var knownParameters: [UInt64: String] = [
        1: "_",
        2: "lhs",
        3: "rhs",
    ]
}
