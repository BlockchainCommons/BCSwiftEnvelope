import Foundation
import SecureComponents

public extension Envelope {
    /// A type used to identify functions in envelope expressions.
    enum FunctionIdentifier: Hashable {
        case known(value: Int, name: String?)
        case named(name: String)
    }
}

public extension Envelope.FunctionIdentifier {
    init(_ value: Int, _ name: String? = nil) {
        self = .known(value: value, name: name)
    }
    
    init(_ name: String) {
        self = .named(name: name)
    }
}

extension Envelope.FunctionIdentifier: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }
}

public extension Envelope.FunctionIdentifier {
    static func ==(lhs: Envelope.FunctionIdentifier, rhs: Envelope.FunctionIdentifier) -> Bool {
        if
            case .known(let lValue, _) = lhs,
            case .known(let rValue, _) = rhs
        {
            return lValue == rValue
        } else if
            case .named(let lName) = lhs,
            case .named(let rName) = rhs
        {
            return lName == rName
        } else {
            return false
        }
    }
}

public extension Envelope.FunctionIdentifier {
    var isKnown: Bool {
        guard case .known = self else {
            return false
        }
        return true
    }
    
    var isNamed: Bool {
        guard case .named = self else {
            return false
        }
        return true
    }
    
    var name: String? {
        switch self {
        case .known(value: _, name: let name):
            return name
        case .named(name: let name):
            return name
        }
    }
    
    var value: Int? {
        switch self {
        case .known(value: let value, name: _):
            return value
        case .named(name: _):
            return nil
        }
    }
}

public extension Envelope.FunctionIdentifier {
    static func knownIdentifier(for value: Int) -> Envelope.FunctionIdentifier {
        knownFunctionIdentifiersByValue[value] ?? Envelope.FunctionIdentifier(value)
    }

    static func setKnownIdentifier(_ identifier: Envelope.FunctionIdentifier) {
        guard case .known(value: let value, name: _) = identifier else {
            preconditionFailure()
        }
        knownFunctionIdentifiersByValue[value] = identifier
    }
}

extension Envelope.FunctionIdentifier: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Envelope.FunctionIdentifier {
        try Envelope.FunctionIdentifier(taggedCBOR: cbor)
    }

    public var cbor: CBOR {
        switch self {
        case .known(value: let value, name: _):
            return CBOR.tagged(.function, CBOR.unsignedInt(UInt64(value)))
        case .named(name: let name):
            return CBOR.tagged(.function, CBOR.utf8String(name))
        }
    }
}

public extension Envelope.FunctionIdentifier {
    init(taggedCBOR cbor: CBOR) throws {
        guard case CBOR.tagged(.function, let item) = cbor else {
            throw CBORError.invalidTag
        }
        switch item {
        case CBOR.unsignedInt(let value):
            if let knownIdentifier = knownFunctionIdentifiersByValue[Int(value)] {
                self = knownIdentifier
            } else {
                self.init(Int(value))
            }
        case CBOR.utf8String(let name):
            self.init(name)
        default:
            throw CBORError.invalidFormat
        }
    }
}

extension Envelope.FunctionIdentifier: CustomStringConvertible {
    public var description: String {
        switch self {
        case .known(value: let value, name: let name):
            return name ?? String(value)
        case .named(name: let name):
            return name.flanked("\"")
        }
    }
}

fileprivate var knownFunctionIdentifiersByValue: [Int: Envelope.FunctionIdentifier] = {
    knownFunctionIdentifiers.reduce(into: [Int: Envelope.FunctionIdentifier]()) {
        guard case .known(value: let value, name: _) = $1 else {
            preconditionFailure()
        }
        $0[value] = $1
    }
}()
