import Foundation

extension Envelope.ParameterIdentifier {
    public static let blank = Envelope.ParameterIdentifier(1, "_")
    public static let lhs = Envelope.ParameterIdentifier(2, "lhs")
    public static let rhs = Envelope.ParameterIdentifier(3, "rhs")
}

var knownFunctionParameters: [Envelope.ParameterIdentifier] = [
    .blank,
    .lhs,
    .rhs
]
