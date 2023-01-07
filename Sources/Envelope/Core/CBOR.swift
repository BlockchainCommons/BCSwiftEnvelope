import Foundation
import SecureComponents

/// Support for CBOR encoding and decoding of ``Envelope``.

public extension Envelope {
    /// Returns the envelope encoded as tagged CBOR.
    var taggedCBOR: CBOR {
        CBOR.tagged(.envelope, untaggedCBOR)
    }

    /// Creates an envelope by decoding the provided tagged CBOR.
    ///
    /// Throws if the provided CBOR is not tagged as an envelope.
    /// Throws if the tagged CBOR is not a well-formed envelope.
    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.envelope, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Envelope: CBORCodable {
    public var cbor: CBOR {
        taggedCBOR
    }

    public static func cborDecode(_ cbor: CBOR) throws -> Envelope {
        try Envelope(taggedCBOR: cbor)
    }
}

public extension Envelope {
    /// Used by test suite to check round-trip encoding of ``Envelope``.
    ///
    /// Not needed in production code.
    @discardableResult
    func checkEncoding() throws -> Envelope {
        do {
            let cbor = taggedCBOR
            let restored = try Envelope(taggedCBOR: cbor)
            guard self.digest == restored.digest else {
                print("=== EXPECTED")
                print(self.format)
                print("=== GOT")
                print(restored.format)
                print("===")
                throw Error.invalidFormat
            }
            return self
        } catch {
            print("===")
            print(format)
            print("===")
            print(cbor.diagAnnotated)
            print("===")
            throw error
        }
    }
}

// MARK: - Internal

extension Envelope {
    /// Returns the envelope encoded as CBOR.
    var untaggedCBOR: CBOR {
        switch self {
        case .node(let subject, let assertions, _):
            precondition(!assertions.isEmpty)
            var result = [subject.taggedCBOR]
            for assertion in assertions {
                result.append(assertion.taggedCBOR)
            }
            return CBOR.array(result)
        case .leaf(let cbor, _):
            return CBOR.tagged(.leaf, cbor)
        case .wrapped(let envelope, _):
            return CBOR.tagged(.wrappedEnvelope, envelope.untaggedCBOR)
        case .knownValue(let knownValue, _):
            return knownValue.taggedCBOR
        case .assertion(let assertion):
            return assertion.taggedCBOR
        case .encrypted(let encryptedMessage):
            return encryptedMessage.taggedCBOR
        case .elided(let digest):
            return digest.taggedCBOR
        }
    }
    
    /// Creates an envelope by decoding the provided untagged CBOR.
    ///
    /// Throws if the provided CBOR is not a well-formed envelope.
    init(untaggedCBOR cbor: CBOR) throws {
        switch cbor {
        case CBOR.tagged(.leaf, let item):
            self.init(cbor: item)
        case CBOR.tagged(.knownValue, let item):
            self.init(knownValue: try KnownValue(untaggedCBOR: item))
        case CBOR.tagged(.wrappedEnvelope, let item):
            self.init(wrapped: try Envelope(untaggedCBOR: item))
        case CBOR.tagged(.assertion, let item):
            self.init(assertion: try Assertion(untaggedCBOR: item))
        case CBOR.tagged(.envelope, let item):
            self = try Envelope(untaggedCBOR: item)
        case CBOR.tagged(.message, let item):
            let message = try EncryptedMessage(untaggedCBOR: item)
            try self.init(encryptedMessage: message)
        case CBOR.tagged(.digest, let item):
            let digest = try Digest(untaggedCBOR: item)
            self.init(elided: digest)
        case CBOR.array(let elements):
            guard elements.count >= 2 else {
                throw CBORError.invalidFormat
            }
            let subject = try Envelope(taggedCBOR: elements[0])
            let assertions = try elements.dropFirst().map { try Envelope(taggedCBOR: $0 ) }
            try self.init(subject: subject, assertions: assertions)
        default:
            throw Error.invalidFormat
        }
    }
}
