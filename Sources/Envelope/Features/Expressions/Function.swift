import Foundation
import SecureComponents

/// A type used to identify functions in envelope expressions.
public enum Function {
    case known(value: UInt64, name: String?)
    case named(String)
}

extension Function: Hashable {
    public static func ==(lhs: Function, rhs: Function) -> Bool {
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

public extension Function {
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

extension Function: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(UInt64(value))
    }
}

extension Function: ExpressibleByStringLiteral {
    public init(stringLiteral name: StringLiteralType) {
        self.init(name)
    }
}

extension Function: CBORTaggedCodable {
    public static var cborTag = Tag.function
    
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

extension Function: CustomStringConvertible {
    public func description(knownFunctions: KnownFunctions? = nil) -> String {
        switch self {
        case .known(_, _):
            return KnownFunctions.name(for: self, knownFunctions: knownFunctions)
        case .named(let name):
            return name.flanked("\"")
        }
    }

    public var description: String {
        return description(knownFunctions: nil)
    }
}
