import Foundation

public extension Function {
    static let add = Function(1, "add")
    static let sub = Function(2, "sub")
    static let mul = Function(3, "mul")
    static let div = Function(4, "div")
}

public var knownFunctions: KnownFunctions = [
    .add,
    .sub,
    .mul,
    .div,
]
