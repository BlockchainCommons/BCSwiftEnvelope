import Foundation
import SecureComponents

public extension Envelope.FunctionIdentifier {
    static let add = Envelope.FunctionIdentifier(1, "add")
    static let sub = Envelope.FunctionIdentifier(2, "sub")
    static let mul = Envelope.FunctionIdentifier(3, "mul")
    static let div = Envelope.FunctionIdentifier(4, "div")
}

var knownFunctionIdentifiers: [Envelope.FunctionIdentifier] = [
    .add,
    .sub,
    .mul,
    .div
]
