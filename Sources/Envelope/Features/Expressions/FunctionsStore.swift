import Foundation

public struct FunctionsStore {
    var dict: [Function: String]
    
    public init<T>(_ functions: T) where T: Sequence, T.Element == Function {
        dict = [:]
        for function in functions {
            Self._insert(function, dict: &dict)
        }
    }
    
    public mutating func insert(_ function: Function) {
        Self._insert(function, dict: &dict)
    }
    
    public func assignedName(for function: Function) -> String? {
        dict[function]
    }
    
    public func name(for function: Function) -> String {
        assignedName(for: function) ?? function.name
    }
    
    public static func name(for function: Function, knownFunctions: FunctionsStore? = nil) -> String {
        knownFunctions?.name(for: function) ?? function.name
    }

    static func _insert(_ function: Function, dict: inout [Function: String]) {
        guard case .known(_, let name) = function else {
            preconditionFailure()
        }
        dict[function] = name
    }
}

extension FunctionsStore: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: Function...) {
        self.init(elements)
    }
}
