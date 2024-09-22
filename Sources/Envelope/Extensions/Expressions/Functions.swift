import Foundation

public extension Function {
    static let add = Function(1, "add") // addition
    static let sub = Function(2, "sub") // subtraction
    static let mul = Function(3, "mul") // multiplication
    static let div = Function(4, "div") // division
    static let neg = Function(5, "neg") // unary negation
    static let lt = Function(6, "lt") // less than
    static let le = Function(7, "le") // less than or equal to
    static let gt = Function(8, "gt") // greater than
    static let ge = Function(9, "ge") // greater than or equal to
    static let eq = Function(10, "eq") // equal to
    static let ne = Function(11, "ne") // not equal to
    static let and = Function(12, "and") // logical and
    static let or = Function(13, "or") // logical or
    static let xor = Function(14, "xor") // logical exclusive or
    static let not = Function(15, "not") // logical not
}

nonisolated(unsafe) public var globalFunctions: FunctionsStore = [
    .add,
    .sub,
    .mul,
    .div,
    .neg,
    .lt,
    .le,
    .gt,
    .ge,
    .eq,
    .ne,
    .and,
    .or,
    .xor,
    .not
]
