import Foundation
import SecureComponents

/// Support for CBOR encoding and decoding of ``Envelope``.

/// All envelopes are tagged with the `envelope` tag. Within that tag, each of
/// the seven cases has a unique CBOR signature:
///
/// * `.node` contains a CBOR array, the first element of which is the subject,
/// followed by one or more assertions.
/// * `.leaf` is tagged #6.24, which is the IANA tag for embedded CBOR.
/// * `.wrapped` is tagged with the `wrapped-envelope` tag.
/// * `.knownValue` is tagged with the `known-value` tag.
/// * `.assertion` is tagged with the `assertion` tag.
/// * `.encrypted` is tagged with the `crypto-msg` tag.
/// * `.elided` is tagged with the `crypto-digest` tag.

extension Envelope: CBORCodable {
    public var untaggedCBOR: CBOR {
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
        case .compressed(let compressed):
            return compressed.taggedCBOR
        case .elided(let digest):
            return digest.taggedCBOR
        }
    }
    
    public init(untaggedCBOR: CBOR) throws {
        let result: Envelope
        switch untaggedCBOR {
        case CBOR.tagged(let tag, let item):
            switch tag {
            case .leaf:
                result = Envelope(leaf: item)
            case .knownValue:
                result = Envelope(knownValue: try KnownValue(untaggedCBOR: item))
            case .wrappedEnvelope:
                result = Envelope(wrapped: try Self(untaggedCBOR: item))
            case .assertion:
                result = Envelope(assertion: try Assertion(untaggedCBOR: item))
            case .envelope:
                result = try Envelope(untaggedCBOR: item)
            case .encrypted:
                let message = try EncryptedMessage(untaggedCBOR: item)
                result = try Envelope(encryptedMessage: message)
            case .compressed:
                let compressed = try Compressed(untaggedCBOR: item)
                result = try Envelope(compressed: compressed)
            case .digest:
                let digest = try Digest(untaggedCBOR: item)
                result = Envelope(elided: digest)
            default:
                throw EnvelopeError.invalidFormat
            }
        case CBOR.array(let elements):
            guard elements.count >= 2 else {
                throw CBORError.invalidFormat
            }
            let subject = try Envelope(taggedCBOR: elements[0])
            let assertions = try elements.dropFirst().map { try Envelope(taggedCBOR: $0) }
            result = try Envelope(subject: subject, assertions: assertions)
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
    public static var cborTag = Tag.envelope
}
