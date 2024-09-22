import Foundation

public extension Parameter {
    static let blank = Parameter(1, "_")
    static let lhs = Parameter(2, "lhs")
    static let rhs = Parameter(3, "rhs")
}

nonisolated(unsafe) public var globalParameters: ParametersStore = [
    .blank,
    .lhs,
    .rhs,
]
