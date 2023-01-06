import Foundation
import SecureComponents

extension Envelope.EnvelopeError {
    static let unverifiedSignature = Envelope.EnvelopeError("unverifiedSignature")
}

public extension Envelope {
    /// Creates a signature for the envelope's subject and returns a new envelope with a `verifiedBy: Signature` assertion.
    ///
    /// - Parameters:
    ///   - privateKeys: The signer's `PrivateKeyBase`
    ///   - note: Optional text note to add to the `Signature`
    ///
    /// - Returns: The signed envelope.
    func sign(with privateKeys: PrivateKeyBase, note: String? = nil, tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        var assertions: [Envelope] = []
        if let note {
            assertions.append(Envelope(.note, note))
        }
        return try! sign(with: privateKeys, uncoveredAssertions: assertions, tag: tag, randomGenerator: randomGenerator)
    }
    
    /// Creates several signatures for the envelope's subject and returns a new envelope with additional `verifiedBy: Signature` assertions.
    ///
    /// - Parameters:
    ///   - privateKeys: An array of signers' `PrivateKeyBase`s.
    ///
    /// - Returns: The signed envelope.
    func sign(with privateKeys: [PrivateKeyBase], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) -> Envelope {
        privateKeys.reduce(into: self) {
            $0 = $0.sign(with: $1, tag: tag, randomGenerator: randomGenerator)
        }
    }

    /// Creates a signature for the envelope's subject and returns a new envelope with a `verifiedBy: Signature` assertion.
    ///
    /// - Parameters:
    ///   - privateKeys: The signer's `PrivateKeyBase`
    ///   - uncoveredAssertions: Assertions to add to the `Signature`.
    ///
    /// - Returns: The signed envelope.
    func sign(with privateKeys: PrivateKeyBase, uncoveredAssertions: [Envelope], tag: Data? = nil, randomGenerator: ((Int) -> Data)? = nil) throws -> Envelope {
        let signature = try Envelope(privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag, randomGenerator: randomGenerator))
            .addAssertions(uncoveredAssertions)
        return try addAssertion(Envelope(.verifiedBy, signature))
    }
}

public extension Envelope {
    /// Convenience constructor for a `verifiedBy: Signature` assertion envelope.
    ///
    /// - Parameters:
    ///   - signature: The `Signature` for the object.
    ///   - note: An optional note to be added to the `Signature`.
    ///
    /// - Returns: The new assertion envelope.
    static func verifiedBy(signature: Signature, note: String? = nil) -> Envelope {
        Envelope(
            .verifiedBy,
            Envelope(signature)
                .addAssertion(if: note != nil, .note, note!)
        )
    }
}

public extension Envelope {
    /// An array of signatures from all of the envelope's `verifiedBy` predicates.
    ///
    /// - Throws: Throws an exception if any `verifiedBy` assertion doesn't contain a
    /// valid `Signature` as its object.
    var signatures: [Signature] {
        get throws {
            try assertions(withPredicate: .verifiedBy)
                .map { try $0.object!.extractSubject(Signature.self) }
        }
    }

    /// Checks whether the given signature is valid.
    ///
    /// - Parameters:
    ///   - signature: The `Signature` to be checked.
    ///   - publicKeys: The potential signer's `PublicKeyBase`.
    ///
    /// - Returns: `true` if the signature is valid for this envelope's subject, `false` otherwise.
    func isVerifiedSignature(_ signature: Signature, publicKeys: PublicKeyBase) -> Bool {
        isVerifiedSignature(signature, key: publicKeys.signingPublicKey)
    }

    /// Checks whether the given signature is valid.
    ///
    /// Used for chaining a series of operations that include validating signatures.
    ///
    /// - Parameters:
    ///   - signature: The `Signature` to be checked.
    ///   - publicKeys: The potential signer's `PublicKeyBase`.
    ///
    /// - Returns: This envelope.
    ///
    /// - Throws: Throws `EnvelopeError.unverifiedSignature` if the signature is not valid.
    /// valid.
    @discardableResult
    func verifySignature(_ signature: Signature, publicKeys: PublicKeyBase) throws -> Envelope {
        try verifySignature(signature, key: publicKeys.signingPublicKey)
    }
    
    /// Checks whether the envelope's subject has a valid signature.
    ///
    /// - Parameters:
    ///   - publicKeys: The potential signer's `PublicKeyBase`.
    ///
    /// - Returns: `true` if the signature is valid for this envelope's subject, `false` otherwise.
    ///
    /// - Throws: Throws an exception if any `verifiedBy` assertion doesn't contain a
    /// valid `Signature` as its object.
    func hasVerifiedSignature(from publicKeys: PublicKeyBase) throws -> Bool {
        try hasVerifiedSignature(key: publicKeys.signingPublicKey)
    }

    /// Checks whether the envelope's subject has a valid signature.
    ///
    /// Used for chaining a series of operations that include validating signatures.
    ///
    /// - Parameters:
    ///   - publicKeys: The potential signer's `PublicKeyBase`.
    ///
    /// - Returns: This envelope.
    ///
    /// - Throws: Throws `EnvelopeError.unverifiedSignature` if the signature is not valid.
    /// valid.
    @discardableResult
    func verifySignature(from publicKeys: PublicKeyBase) throws -> Envelope {
        try verifySignature(key: publicKeys.signingPublicKey)
    }

    /// Checks whether the envelope's subject has some threshold of signatures.
    ///
    /// If `threshold` is `nil`, then *all* signers in `publicKeysArray` must have
    /// signed. If `threshold` is `1`, then at least one signer must have signed.
    ///
    /// - Parameters:
    ///   - publicKeysArray: An array of potential signers' `PublicKeyBase`s.
    ///
    /// - Returns: `true` if the threshold of valid signatures is met, `false` otherwise.
    ///
    /// - Throws: Throws an exception if any `verifiedBy` assertion doesn't contain a
    /// valid `Signature` as its object.
    func hasVerifiedSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Bool {
        try hasVerifiedSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }

    /// Checks whether the envelope's subject has some threshold of signatures.
    ///
    /// If `threshold` is `nil`, then *all* signers in `publicKeysArray` must have
    /// signed. If `threshold` is `1`, then at least one signer must have signed.
    ///
    /// Used for chaining a series of operations that include validating signatures.
    ///
    /// - Parameters:
    ///   - publicKeysArray: An array of potential signers' `PublicKeyBase`s.
    ///
    /// - Returns: This envelope.
    ///
    /// - Throws: Throws an exception if the threshold of valid signatures is not met.
    @discardableResult
    func verifySignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Envelope {
        try verifySignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }
}

extension Envelope {
    func isVerifiedSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        return key.isValidSignature(signature, for: subject.digest)
    }
    
    @discardableResult
    func verifySignature(_ signature: Signature, key: SigningPublicKey) throws -> Envelope {
        guard isVerifiedSignature(signature, key: key) else {
            throw EnvelopeError.unverifiedSignature
        }
        return self
    }

    func hasVerifiedSignature(key: SigningPublicKey) throws -> Bool {
        try signatures.contains { isVerifiedSignature($0, key: key) }
    }

    @discardableResult
    func verifySignature(key: SigningPublicKey) throws -> Envelope {
        guard try hasVerifiedSignature(key: key) else {
            throw EnvelopeError.unverifiedSignature
        }
        return self
    }

    func hasVerifiedSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Bool {
        let threshold = threshold ?? keys.count
        var count = 0
        for key in keys {
            if try hasVerifiedSignature(key: key) {
                count += 1
                if count >= threshold {
                    return true
                }
            }
        }
        return false
    }

    @discardableResult
    func verifySignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Envelope {
        guard try hasVerifiedSignatures(with: keys, threshold: threshold) else {
            throw EnvelopeError.unverifiedSignature
        }
        return self
    }
}
