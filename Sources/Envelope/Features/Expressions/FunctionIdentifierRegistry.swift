import Foundation

public extension FunctionIdentifier {
    static let add = Self.known(1)
    static let sub = Self.known(2)
    static let mul = Self.known(3)
    static let div = Self.known(4)
    
    static var knownFunctions: [UInt64: String] = [
        1: "add",
        2: "sub",
        3: "mul",
        4: "div",
    ]
}
