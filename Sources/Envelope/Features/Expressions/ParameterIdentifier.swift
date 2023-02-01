import Foundation
import SecureComponents

/// A type used to identify parameters in envelope expressions.
///
/// Used as a predicate. In an assertion, the object is the argument.
public enum ParameterIdentifier: Hashable {
    case known(UInt64)
    case named(String)
}

public extension ParameterIdentifier {
    init(_ value: UInt64) {
        self = .known(value)
    }
    
    init(_ name: String) {
        self = .named(name)
    }
}

extension ParameterIdentifier: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(UInt64(value))
    }
}

extension ParameterIdentifier: ExpressibleByStringLiteral {
    public init(stringLiteral name: StringLiteralType) {
        self.init(name)
    }
}

public extension ParameterIdentifier {
    static func ==(lhs: ParameterIdentifier, rhs: ParameterIdentifier) -> Bool {
        switch (lhs, rhs) {
        case (.known(let l), .known(let r)):
            return l == r
        case (.named(let l), .named(let r)):
            return l == r
        default:
            return false
        }
    }
}

extension ParameterIdentifier: CBORTaggedCodable {
    public static var cborTag = Tag.parameter
    
    public var untaggedCBOR: CBOR {
        switch self {
        case .known(value: let value):
            return value.cbor
        case .named(name: let name):
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
            throw CBORDecodingError.invalidFormat
        }
    }
}

extension ParameterIdentifier: CustomStringConvertible {
    public func description(knownIdentifiers: [Int: String]? = nil) -> String {
        switch self {
        case .known(value: let value):
            return knownIdentifiers?[Int(value)] ?? String(value)
        case .named(name: let name):
            return name.flanked("\"")
        }
    }

    public var description: String {
        return description(knownIdentifiers: nil)
    }
}
