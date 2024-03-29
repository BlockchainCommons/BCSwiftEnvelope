import Foundation
import WolfBase
import SecureComponents

extension EnvelopeError {
    static let invalidRecipient = EnvelopeError("invalidRecipient")
}

public extension Envelope {
    /// Returns a new envelope with an added `hasRecipient: SealedMessage` assertion.
    ///
    /// The `SealedMessage` contains the `contentKey` encrypted to the recipient's `PublicKeyBase`.
    ///
    /// - Parameters:
    ///   - recipient: The `PublicKeyBase` of the recipient.
    ///   - contentKey: The `SymmetricKey` that was used to encrypt the subject.
    ///
    /// - Returns: The new envelope.
    func addRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        try! addAssertion(Self.hasRecipient(recipient, contentKey: contentKey, testKeyMaterial: testKeyMaterial, testNonce: testNonce))
    }
}

public extension Envelope {
    /// Convenience constructor for a `hasRecipient: SealedMessage` assertion.
    ///
    /// The `SealedMessage` contains the `contentKey` encrypted to the recipient's `PublicKeyBase`.
    ///
    /// - Parameters:
    ///   - recipient: The `PublicKeyBase` of the recipient.
    ///   - contentKey: The `SymmetricKey` that was used to encrypt the subject.
    ///
    /// - Returns: The assertion envelope.
    static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey, testKeyMaterial: DataProvider? = nil, testNonce: Nonce? = nil) -> Envelope {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR.cborData, recipient: recipient, testKeyMaterial: testKeyMaterial, testNonce: testNonce)
        return Envelope(.hasRecipient, sealedMessage)
    }
}

public extension Envelope {
    /// Returns an array of `SealedMessage`s from all of the envelope's `hasRecipient` assertions.
    ///
    /// - Throws: Throws an exception if any `hasRecipient` assertions do not have a `SealedMessage` as their object.
    var recipients: [SealedMessage] {
        get throws {
            try assertions(withPredicate: .hasRecipient)
                .filter { !$0.object.isObscured }
                .map { try $0.object!.extractSubject(SealedMessage.self) }
        }
    }
    
    /// Returns an new envelope with its subject encrypted and a `hasReceipient`
    /// assertion added for each of the `recipients`.
    ///
    /// Generates an ephemeral symmetric key which is used to encrypt the subject and
    /// which is then encrypted to each recipient's public key.
    ///
    /// - Parameter recipients: An array of `PublicKeyBase`, one for each potential
    /// recipient.
    ///
    /// - Returns: The encrypted envelope.
    ///
    /// - Throws: If the envelope is already encrypted.
    func encryptSubject(to recipients: [PublicKeyBase]) throws -> Envelope {
        let contentKey = SymmetricKey()
        var e = try encryptSubject(with: contentKey)
        for recipient in recipients {
            e = e.addRecipient(recipient, contentKey: contentKey)
        }
        return e
    }
    
    /// Returns an new envelope with its subject encrypted and a `hasReceipient`
    /// assertion added for the `recipient`.
    ///
    /// Generates an ephemeral symmetric key which is used to encrypt the subject and
    /// which is then encrypted to each recipient's public key.
    ///
    /// - Parameter recipients: A `PublicKeyBase`, for the intended recipient.
    ///
    /// - Returns: The encrypted envelope.
    ///
    /// - Throws: If the envelope is already encrypted.
    func encryptSubject(to recipient: PublicKeyBase) throws -> Envelope {
        try encryptSubject(to: [recipient])
    }
    
    static func firstPlaintext(in sealedMessages: [SealedMessage], for privateKeys: PrivateKeyBase) throws -> Data {
        for sealedMessage in sealedMessages {
            if let plaintext = try? sealedMessage.decrypt(with: privateKeys) {
                return plaintext
            }
        }
        throw EnvelopeError.invalidRecipient
    }

    /// Returns a new envelope with its subject decrypted using the recipient's
    /// `PrivateKeyBase`.
    ///
    /// - Parameter recipient: The recipient's `PrivateKeyBase`
    ///
    /// - Returns: The decryptedEnvelope.
    ///
    /// - Throws: If a `SealedMessage` for `recipient` is not found among the
    /// `hasRecipient` assertions on the envelope.
    func decrypt(to recipient: PrivateKeyBase) throws -> Envelope {
        let sealedMessage = try self.recipients
        let contentKeyData = try Self.firstPlaintext(in: sealedMessage, for: recipient)
        let contentKey = try SymmetricKey(taggedCBORData: contentKeyData)
        return try decryptSubject(with: contentKey).subject
    }
}
