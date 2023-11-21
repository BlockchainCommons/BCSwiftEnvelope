import Foundation
import SecureComponents

/// A type used to identify parameters in envelope expressions.
///
/// Used as a predicate. In an assertion, the object is the argument.
public enum Parameter {
    case known(value: UInt64, name: String?)
    case named(String)
}

extension Parameter: Hashable {
    public static func ==(lhs: Parameter, rhs: Parameter) -> Bool {
        switch (lhs, rhs) {
        case (.known(let l, _), .known(let r, _)):
            return l == r
        case (.named(let l), .named(let r)):
            return l == r
        default:
            return false
        }
    }
    
    public func hash(into hasher: inout Hasher) {
        switch self {
        case .known(let value, _):
            hasher.combine(value)
        case .named(let name):
            hasher.combine(name)
        }
    }
}

public extension Parameter {
    init(_ value: UInt64, _ name: String? = nil) {
        self = .known(value: value, name: name)
    }
    
    init(_ name: String) {
        self = .named(name)
    }
    
    var name: String {
        switch self {
        case .known(let value, let name):
            return name ?? String(value)
        case .named(let name):
            return String(name).flanked("\"")
        }
    }
}

extension Parameter: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(UInt64(value))
    }
}

extension Parameter: ExpressibleByStringLiteral {
    public init(stringLiteral name: StringLiteralType) {
        self.init(name)
    }
}

extension Parameter: CBORTaggedCodable {
    public static var cborTags = [Tag.parameter]
    
    public var untaggedCBOR: CBOR {
        switch self {
        case .known(let value, _):
            return value.cbor
        case .named(let name):
            return name.cbor
        }
    }
    
    public init(untaggedCBOR: CBOR) throws {
        switch untaggedCBOR {
        case CBOR.unsigned(let value):
            self = Self(value)
        case CBOR.text(let name):
            self = Self(name)
        default:
            throw CBORError.invalidFormat
        }
    }
}

extension Parameter: CustomStringConvertible {
    public func description(knownParameters: ParametersStore? = nil) -> String {
        switch self {
        case .known(_, _):
            return ParametersStore.name(for: self, knownParameters: knownParameters)
        case .named(let name):
            return name.flanked("\"")
        }
    }

    public var description: String {
        return description(knownParameters: nil)
    }
}
