import Foundation
import SecureComponents

/// Support for CBOR encoding and decoding of ``Envelope``.

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
        case .elided(let digest):
            return digest.taggedCBOR
        }
    }
    
    public static func decodeUntaggedCBOR(_ cbor: CBOR) throws -> Envelope {
        let result: Envelope
        switch cbor {
        case CBOR.tagged(let tag, let item):
            switch tag {
            case .leaf:
                result = Envelope(cbor: item)
            case KnownValue.cborTag:
                result = Envelope(knownValue: try KnownValue.decodeUntaggedCBOR(item))
            case .wrappedEnvelope:
                result = Envelope(wrapped: try decodeUntaggedCBOR(item))
            case .assertion:
                result = Envelope(assertion: try Assertion.decodeUntaggedCBOR(item))
            case .envelope:
                result = try Envelope.decodeUntaggedCBOR(item)
            case EncryptedMessage.cborTag:
                let message = try EncryptedMessage.decodeUntaggedCBOR(item)
                result = try Envelope(encryptedMessage: message)
            case Digest.cborTag:
                let digest = try Digest.decodeUntaggedCBOR(item)
                result = Envelope(elided: digest)
            default:
                throw EnvelopeError.invalidFormat
            }
        case CBOR.array(let elements):
            guard elements.count >= 2 else {
                throw CBORDecodingError.invalidFormat
            }
            let subject = try Envelope.decodeTaggedCBOR(elements[0])
            let assertions = try elements.dropFirst().map { try Envelope.decodeTaggedCBOR($0) }
            result = try Envelope(subject: subject, assertions: assertions)
        default:
            throw EnvelopeError.invalidFormat
        }
        return result
    }
}

public extension Envelope {
    /// Used by test suite to check round-trip encoding of ``Envelope``.
    ///
    /// Not needed in production code.
    @discardableResult
    func checkEncoding(knownTags: KnownTags? = nil) throws -> Envelope {
        do {
            let cbor = taggedCBOR
            let restored = try Envelope.decodeTaggedCBOR(cbor)
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
            print(format)
            print("===")
            print(cbor.diagnostic(annotate: true, knownTags: knownTags))
            print("===")
            throw error
        }
    }
}
