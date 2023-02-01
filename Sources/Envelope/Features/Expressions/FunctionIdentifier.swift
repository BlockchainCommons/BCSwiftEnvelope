import Foundation
import SecureComponents

/// A type used to identify functions in envelope expressions.
public enum FunctionIdentifier: Hashable {
    case known(UInt64)
    case named(String)
}

public extension FunctionIdentifier {
    init(_ value: UInt64) {
        self = .known(value)
    }
    
    init(_ name: String) {
        self = .named(name)
    }
}

extension FunctionIdentifier: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(UInt64(value))
    }
}

extension FunctionIdentifier: ExpressibleByStringLiteral {
    public init(stringLiteral name: StringLiteralType) {
        self.init(name)
    }
}

public extension FunctionIdentifier {
    static func ==(lhs: FunctionIdentifier, rhs: FunctionIdentifier) -> Bool {
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

extension FunctionIdentifier: CBORTaggedCodable {
    public static var cborTag = Tag.function
    
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

extension FunctionIdentifier: CustomStringConvertible {
    public func description(knownIdentifiers: [Int: String]? = nil) -> String {
        switch self {
        case .known(let value):
            return knownIdentifiers?[Int(value)] ?? String(value)
        case .named(let name):
            return name.flanked("\"")
        }
    }

    public var description: String {
        return description(knownIdentifiers: nil)
    }
}
