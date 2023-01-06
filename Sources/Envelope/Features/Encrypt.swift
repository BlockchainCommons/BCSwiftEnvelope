import Foundation
import SecureComponents

extension Envelope.Error {
    static let invalidKey = Envelope.Error("invalidKey")
    static let missingDigest = Envelope.Error("missingDigest")
    static let alreadyEncrypted = Envelope.Error("alreadyEncrypted")
    static let notEncrypted = Envelope.Error("notEncrypted")
    static let alreadyElided = Envelope.Error("alreadyElided")
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
                throw Error.alreadyEncrypted
            }
            let encodedCBOR = subject.cborEncode
            let subjectDigest = subject.digest
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: subjectDigest, nonce: testNonce)
            let encryptedSubject = try Envelope(encryptedMessage: encryptedMessage)
            result = Envelope(subject: encryptedSubject, uncheckedAssertions: assertions)
            originalDigest = envelopeDigest
        case .leaf(let cbor, let envelopeDigest):
            let encodedCBOR = CBOR.tagged(.leaf, cbor).cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: envelopeDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = envelopeDigest
        case .wrapped(_, let wrappedDigest):
            let encodedCBOR = self.untaggedCBOR.cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: wrappedDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = wrappedDigest
        case .knownValue(let knownValue, let envelopeDigest):
            let encodedCBOR = knownValue.taggedCBOR.cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: envelopeDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = envelopeDigest
        case .assertion(let assertion):
            let assertionDigest = assertion.digest
            let encodedCBOR = assertion.taggedCBOR.cborEncode
            let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: assertionDigest, nonce: testNonce)
            result = try Envelope(encryptedMessage: encryptedMessage)
            originalDigest = assertionDigest
        case .encrypted(_):
            throw Error.alreadyEncrypted
        case .elided(_):
            throw Error.alreadyElided
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
            throw Error.notEncrypted
        }

        guard
            let encodedCBOR = key.decrypt(message: message)
        else {
            throw Error.invalidKey
        }

        guard let subjectDigest = message.digest else {
            throw Error.missingDigest
        }

        let cbor = try CBOR(encodedCBOR)
        let resultSubject = try Envelope(untaggedCBOR: cbor).subject

        guard resultSubject.digest == subjectDigest else {
            throw Error.invalidDigest
        }

        switch self {
        case .node(subject: _, assertions: let assertions, digest: let originalDigest):
            let result = Envelope(subject: resultSubject, uncheckedAssertions: assertions)
            guard result.digest == originalDigest else {
                throw Error.invalidDigest
            }
            return result
        default:
            return resultSubject
        }
    }
}
