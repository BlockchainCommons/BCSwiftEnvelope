import Foundation
import SecureComponents

extension EnvelopeError {
    static let invalidKey = EnvelopeError("invalidKey")
    static let alreadyEncrypted = EnvelopeError("alreadyEncrypted")
    static let notEncrypted = EnvelopeError("notEncrypted")
    static let alreadyCompressed = EnvelopeError("alreadyCompressed")
    static let notCompressed = EnvelopeError("notCompressed")
    static let alreadyElided = EnvelopeError("alreadyElided")
}

public extension Envelope {
    /// Returns a new envelope with its subject encrypted.
    ///
    /// Assertions are not encrypted. To encrypt an entire envelope including its
    /// assertions it must first be wrapped using the ``wrap()`` method.
    ///
    /// - Parameters:
    ///   - key: The `SymmetricKey` to be used to encrypt the subject.
    ///   - testNonce: Not used in production code.
    ///
    /// - Returns: The encrypted envelope.
    ///
    /// - Throws: If the envelope is already encrypted.
    func encryptSubject(with key: SymmetricKey, testNonce: Nonce? = nil) throws -> Envelope {
        let result: Envelope
        let originalDigest: Digest

        switch self {
        case .node(let subject, let assertions, let envelopeDigest):
            guard !subject.isEncrypted else {
                throw EnvelopeError.alreadyEncrypted
            }
            let encodedCBOR = subject.taggedCBOR.cborData
            let subjectDigest = subject.digest
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: subjectDigest, nonce: testNonce)
            let encryptedSubject = try Envelope(encryptedMessage: encryptedMessage)
            result = Envelope(subject: encryptedSubject, uncheckedAssertions: assertions)
            originalDigest = envelopeDigest
        case .leaf(let cbor, let envelopeDigest):
            let encodedCBOR = CBOR.tagged(.envelope, CBOR.tagged(.leaf, cbor)).cborData
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: envelopeDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = envelopeDigest
        case .wrapped(_, let wrappedDigest):
            let encodedCBOR = self.taggedCBOR.cborData
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: wrappedDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = wrappedDigest
        case .knownValue(let knownValue, let envelopeDigest):
            let encodedCBOR = CBOR.tagged(.envelope, knownValue.untaggedCBOR).cborData
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: envelopeDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = envelopeDigest
        case .assertion(let assertion):
            let assertionDigest = assertion.digest
            let encodedCBOR = CBOR.tagged(.envelope, assertion.cbor).cborData
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: assertionDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = assertionDigest
        case .encrypted:
            throw EnvelopeError.alreadyEncrypted
        case .compressed(let compressed):
            let compressedDigest = compressed.digest!
            let encodedCBOR = CBOR.tagged(.envelope, compressed.taggedCBOR).cborData
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: compressedDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = compressedDigest
        case .elided:
            throw EnvelopeError.alreadyElided
        }

        assert(result.digest == originalDigest)
        return result
    }
    
    /// Returns a new envelope with its subject decrypted.
    ///
    /// - Parameter key: The `SymmetricKey` to use to decrypt the subject.
    ///
    /// - Returns: The decrypted envelope.
    ///
    /// - Throws: If the envelope is not encrypted or if the `SymmetricKey` is not correct.
    func decryptSubject(with key: SymmetricKey) throws -> Envelope {
        guard case .encrypted(let message) = subject else {
            throw EnvelopeError.notEncrypted
        }

        let encodedCBOR = try key.decrypt(message: message)

        guard let subjectDigest = message.digest else {
            throw EnvelopeError.missingDigest
        }

        let cbor = try CBOR(encodedCBOR)
        let resultSubject = try Envelope(taggedCBOR: cbor)

        guard resultSubject.digest == subjectDigest else {
            throw EnvelopeError.invalidDigest
        }

        switch self {
        case .node(subject: _, assertions: let assertions, digest: let originalDigest):
            let result = Envelope(subject: resultSubject, uncheckedAssertions: assertions)
            guard result.digest == originalDigest else {
                throw EnvelopeError.invalidDigest
            }
            return result
        default:
            return resultSubject
        }
    }
}
