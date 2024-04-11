import Foundation
import SecureComponents

/// Support for CBOR encoding and decoding of ``Envelope``.

/// All envelopes are tagged with the `envelope` tag. Within that tag, each of
/// the seven cases has a unique CBOR signature:
///
/// * `.node` contains a CBOR array, the first element of which is the subject,
/// followed by one or more assertions.
/// * `.leaf` is tagged #6.24, which is the IANA tag for embedded CBOR.
/// * `.wrapped` is tagged with the `envelope` tag.
/// * `.assertion` is a single-element map `{predicate: object}`.
/// * `.knownValue` is an unsigned 64-bit integer.
/// * `.encrypted` is tagged with the `crypto-msg` tag.
/// * `.elided` is a byte string of length 32.

extension Envelope: CBORCodable {
    public var untaggedCBOR: CBOR {
        switch self {
        case .node(let subject, let assertions, _):
            precondition(!assertions.isEmpty)
            var result = [subject.untaggedCBOR]
            for assertion in assertions {
                result.append(assertion.untaggedCBOR)
            }
            return CBOR.array(result)
        case .leaf(let cbor, _):
            return CBOR.tagged(.leaf, cbor)
        case .wrapped(let envelope, _):
            return envelope.taggedCBOR
        case .knownValue(let knownValue, _):
            return knownValue.untaggedCBOR
        case .assertion(let assertion):
            return assertion.cbor
        case .encrypted(let encryptedMessage):
            return encryptedMessage.taggedCBOR
        case .compressed(let compressed):
            return compressed.taggedCBOR
        case .elided(let digest):
            return digest.untaggedCBOR
        }
    }
    
    public init(untaggedCBOR: CBOR) throws {
        let result: Envelope
        switch untaggedCBOR {
        case CBOR.tagged(let tag, let item):
            switch tag {
            // See testReadLegacyLeaf
            case .leaf, .encodedCBOR:
                result = Envelope(leaf: item)
            case .envelope:
                result = Envelope(wrapped: try Self(taggedCBOR: untaggedCBOR))
            case .encrypted:
                let message = try EncryptedMessage(untaggedCBOR: item)
                result = try Envelope(encryptedMessage: message)
            case .compressed:
                let compressed = try Compressed(untaggedCBOR: item)
                result = try Envelope(compressed: compressed)
            default:
                throw EnvelopeError.invalidFormat
            }
        case CBOR.bytes(let bytes):
            guard let digest = Digest(rawValue: bytes) else {
                throw EnvelopeError.invalidFormat
            }
            result = Envelope(elided: digest)
        case CBOR.array(let elements):
            guard elements.count >= 2 else {
                throw CBORError.invalidFormat
            }
            let subject = try Envelope(untaggedCBOR: elements[0])
            let assertions = try elements.dropFirst().map { try Envelope(untaggedCBOR: $0) }
            result = try Envelope(subject: subject, assertions: assertions)
        case CBOR.map(_):
            let assertion = try Assertion(cbor: untaggedCBOR)
            result = Envelope(assertion: assertion)
        case CBOR.unsigned(let value):
            result = Envelope(knownValue: KnownValue(value))
        default:
            throw EnvelopeError.invalidFormat
        }
        self = result
    }
}

public extension Envelope {
    /// Used by test suite to check round-trip encoding of ``Envelope``.
    ///
    /// Not needed in production code.
    @discardableResult
    func checkEncoding(tags: TagsStoreProtocol? = nil) throws -> Envelope {
        do {
            let cbor = taggedCBOR
            let restored = try Envelope(taggedCBOR: cbor)
            guard self.digest == restored.digest else {
                print("=== EXPECTED")
                print(self.format)
                print("=== GOT")
                print(restored.format)
                print("===")
                throw EnvelopeError.invalidFormat
            }
            return self
        } catch {
            print("===")
            print(format())
            print("===")
            print(cbor.diagnostic(annotate: true, tags: tags))
            print("===")
            throw error
        }
    }
}

extension Envelope: CBORTaggedCodable {
    public static var cborTags = [Tag.envelope]
    
    public var cbor: CBOR {
        untaggedCBOR
    }
    
    public var cborData: Data {
        untaggedCBOR.cborData
    }

    public init(cbor: CBOR) throws {
        self = try Self(untaggedCBOR: cbor)
    }
}
