import Foundation

public struct ParametersStore {
    var dict: [Parameter: String]
    
    public init<T>(_ parameters: T) where T: Sequence, T.Element == Parameter {
        dict = [:]
        for parameter in parameters {
            Self._insert(parameter, dict: &dict)
        }
    }
    
    public mutating func insert(_ parameter: Parameter) {
        Self._insert(parameter, dict: &dict)
    }
    
    public func assignedName(for parameter: Parameter) -> String? {
        dict[parameter]
    }
    
    public func name(for parameter: Parameter) -> String {
        assignedName(for: parameter) ?? parameter.name
    }
    
    public static func name(for parameter: Parameter, knownParameters: ParametersStore? = nil) -> String {
        knownParameters?.name(for: parameter) ?? parameter.name
    }

    static func _insert(_ parameter: Parameter, dict: inout [Parameter: String]) {
        guard case .known(_, let name) = parameter else {
            preconditionFailure()
        }
        dict[parameter] = name
    }
}

extension ParametersStore: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: Parameter...) {
        self.init(elements)
    }
}
