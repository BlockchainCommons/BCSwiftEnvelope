import Foundation
import SecureComponents

/// A value in a namespace of unsigned integers, frequently used as predicates.
///
/// Known values are a specific case of envelope that defines a namespace consisting
/// of single unsigned integers. The expectation is that the most common and widely
/// useful predicates will be assigned in this namespace, but known values may be
/// used in any position in an envelope.
public struct KnownValue {
    /// The known value as coded into CBOR.
    public let value: UInt64
    /// A name assigned to the known value used for debugging and formatted output.
    public let assignedName: String?
    
    /// Create a known value with the given unsigned integer value and name.
    public init(_ rawValue: UInt64, _ name: String? = nil) {
        self.value = rawValue
        self.assignedName = name
    }
    
    /// The human readable name.
    ///
    /// Defaults to the numerical value if no name has been assigned.
    public var name: String {
        return assignedName ?? String(value)
    }
}

extension KnownValue: Equatable {
    public static func ==(lhs: KnownValue, rhs: KnownValue) -> Bool {
        lhs.value == rhs.value
    }
}

extension KnownValue: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(value)
    }
}

extension KnownValue: CustomStringConvertible {
    public var description: String {
        assignedName ?? String(value)
    }
}

extension KnownValue: DigestProvider {
    public var digest: Digest {
        Digest(taggedCBOR.cborData)
    }
}

extension KnownValue: CBORTaggedCodable {
    public static let cborTags = [Tag.knownValue]
    
    public var untaggedCBOR: CBOR {
        .unsigned(value)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard
            case CBOR.unsigned(let rawValue) = untaggedCBOR
        else {
            throw EnvelopeError.invalidFormat
        }
        self = KnownValue(rawValue)
    }
}

extension KnownValue: EnvelopeEncodable {
    public var envelope: Envelope {
        Envelope(self)
    }
}
