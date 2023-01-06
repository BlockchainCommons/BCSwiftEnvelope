import Foundation
import SecureComponents

public extension Envelope {
    /// A value in a namespace of unsigned integers, frequently used as predicates.
    ///
    /// Known values are a specific case of envelope that defines a namespace consisting
    /// of single unsigned integers. The expectation is that the most common and widely
    /// useful predicates will be assigned in this namespace, but known values may be
    /// used in any position in an envelope.
    struct KnownValue {
        /// The known value as coded into CBOR.
        public let rawValue: UInt64
        /// A name assigned to the known value used for debugging and formatted output.
        public let assignedName: String?
        
        /// Create a known value with the given unsigned integer value and name.
        public init(_ rawValue: UInt64, _ name: String?) {
            self.rawValue = rawValue
            self.assignedName = name
        }
        
        /// Create a known value with the given unsigned integer value.
        public init(rawValue: UInt64) {
            guard let p = knownValuesByRawValue[rawValue] else {
                self = KnownValue(rawValue, nil)
                return
            }
            self = p
        }
        
        /// Create a known value with the given name.
        ///
        /// The constructor fails if the registry contains no such named known value.
        public init?(name: String) {
            guard let p = knownValuesByName[name] else {
                return nil
            }
            self = p
        }
        
        /// The human readable name.
        ///
        /// Defaults to the numerical value if no name has been assigned.
        public var name: String {
            return assignedName ?? String(rawValue)
        }
    }
}

extension Envelope.KnownValue: Equatable {
    public static func ==(lhs: Envelope.KnownValue, rhs: Envelope.KnownValue) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
}

extension Envelope.KnownValue: CustomStringConvertible {
    public var description: String {
        assignedName ?? String(rawValue)
    }
}

public extension Envelope.KnownValue {
    /// The known value, encoded as untagged CBOR.
    var untaggedCBOR: CBOR {
        CBOR.unsignedInt(rawValue)
    }
    
    /// The known value, encoded as tagged CBOR.
    var taggedCBOR: CBOR {
        CBOR.tagged(.knownValue, untaggedCBOR)
    }

    /// Creates a known value by decoding the given CBOR.
    ///
    /// Throws if the CBOR is not an unsigned integer.
    init(untaggedCBOR: CBOR) throws {
        guard
            case CBOR.unsignedInt(let rawValue) = untaggedCBOR
        else {
            throw Envelope.EnvelopeError.invalidFormat
        }
        self = Envelope.KnownValue(rawValue: rawValue)
    }
    
    /// Creates a known value by decoding the given tagged CBOR.
    ///
    /// Throws if not tagged as a known value.
    /// Throws if the tagged CBOR is not an unsigned integer.
    init(taggedCBOR: CBOR) throws {
        guard
            case CBOR.tagged(.knownValue, let untaggedCBOR) = taggedCBOR
        else {
            throw Envelope.EnvelopeError.invalidFormat
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Envelope.KnownValue: DigestProvider {
    public var digest: Digest {
        Digest(taggedCBOR)
    }
}

extension Envelope.KnownValue: CBORCodable {
    public var cbor: CBOR {
        taggedCBOR
    }
    
    public static func cborDecode(_ cbor: CBOR) throws -> Envelope.KnownValue {
        return try Envelope.KnownValue(taggedCBOR: cbor)
    }
}

fileprivate var knownValuesByRawValue: [UInt64: Envelope.KnownValue] = {
    var result: [UInt64: Envelope.KnownValue] = [:]
    knownValueRegistry.forEach {
        result[$0.rawValue] = $0
    }
    return result
}()

fileprivate var knownValuesByName: [String: Envelope.KnownValue] = {
    var result: [String: Envelope.KnownValue] = [:]
    knownValueRegistry.forEach {
        if let name = $0.assignedName {
            result[name] = $0
        }
    }
    return result
}()
