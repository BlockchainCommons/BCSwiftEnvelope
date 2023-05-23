import Foundation
import SecureComponents

// MARK: - High-Level Elision Functions

// An action which obscures (elides, encrypts, or compresses) an envelope.
public enum ObscureAction {
    case elide
    case encrypt(SymmetricKey)
    case compress
}

public extension Envelope {
    /// Returns the elided variant of this envelope.
    ///
    /// Returns the same envelope if it is already elided.
    func elide() -> Envelope {
        switch self {
        case .elided:
            return self
        default:
            return Envelope(elided: self.digest)
        }
    }
}

public extension Envelope {
    /// Returns a version of this envelope with elements in the `target` set elided.
    ///
    /// - Parameters:
    ///   - target: The target set of digests.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elideRemoving(_ target: Set<Digest>, action: ObscureAction = .elide) -> Envelope {
        elide(target, isRevealing: false, action: action)
    }
    
    /// Returns a version of this envelope with elements in the `target` set elided.
    ///
    /// - Parameters:
    ///   - target: An array of `DigestProvider`s.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elideRemoving(_ target: [DigestProvider], action: ObscureAction = .elide) -> Envelope {
        elide(target, isRevealing: false, action: action)
    }
    
    /// Returns a version of this envelope with the target element elided.
    ///
    /// - Parameters:
    ///   - target: A `DigestProvider`.
    ///   - key: If provided, encrypt the targeted element using the `SymmetricKey` instead of eliding it.
    ///
    /// - Returns: The elided envelope.
    func elideRemoving(_ target: DigestProvider, action: ObscureAction = .elide) -> Envelope {
        elide(target, isRevealing: false, action: action)
    }
    
    /// Returns a version of this envelope with elements *not* in the `target` set elided.
    ///
    /// - Parameters:
    ///   - target: The target set of digests.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elideRevealing(_ target: Set<Digest>, action: ObscureAction = .elide) -> Envelope {
        elide(target, isRevealing: true, action: action)
    }
    
    /// Returns a version of this envelope with elements *not* in the `target` set elided.
    ///
    /// - Parameters:
    ///   - target: An array of `DigestProvider`s.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elideRevealing(_ target: [DigestProvider], action: ObscureAction = .elide) -> Envelope {
        elide(target, isRevealing: true, action: action)
    }
    
    /// Returns a version of this envelope with all elements *except* the target element elided.
    ///
    /// - Parameters:
    ///   - target: A `DigestProvider`.
    ///   - key: If provided, encrypt the targeted element using the `SymmetricKey` instead of eliding it.
    ///
    /// - Returns: The elided envelope.
    func elideRevealing(_ target: DigestProvider, action: ObscureAction = .elide) -> Envelope {
        elide(target, isRevealing: true, action: action)
    }
}

// MARK: - Utility Elision Functions

public extension Envelope {
    // Target Matches   isRevealing     elide
    // ----------------------------------------
    //     false           false        false
    //     false           true         true
    //     true            false        true
    //     true            true         false

    /// Returns an elided version of this envelope.
    ///
    /// - Parameters:
    ///   - target: The target set of digests.
    ///   - isRevealing: If `true`, the target set contains the digests of the elements to
    ///   leave revealed. If it is `false`, the target set contains the digests of the
    ///   elements to elide.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elide(_ target: Set<Digest>, isRevealing: Bool, action: ObscureAction = .elide) -> Envelope {
        let result: Envelope
        if target.contains(digest) != isRevealing {
            switch action {
            case .elide:
                result = elide()
            case .encrypt(let key):
                let message = key.encrypt(plaintext: self.taggedCBOR.cborData, digest: self.digest)
                result = try! Envelope(encryptedMessage: message)
            case .compress:
                result = try! compress()
            }
        } else if case .assertion(let assertion) = self {
            let predicate = assertion.predicate.elide(target, isRevealing: isRevealing, action: action)
            let object = assertion.object.elide(target, isRevealing: isRevealing, action: action)
            let elidedAssertion = Assertion(predicate: predicate, object: object)
            assert(elidedAssertion == assertion)
            result = Envelope(assertion: elidedAssertion)
        } else if case .node(let subject, let assertions, _) = self {
            let elidedSubject = subject.elide(target, isRevealing: isRevealing, action: action)
            assert(elidedSubject.digest == subject.digest)
            let elidedAssertions = assertions.map { assertion in
                let elidedAssertion = assertion.elide(target, isRevealing: isRevealing, action: action)
                assert(elidedAssertion.digest == assertion.digest)
                return elidedAssertion
            }
            result = Envelope(subject: elidedSubject, uncheckedAssertions: elidedAssertions)
        } else if case .wrapped(let envelope, _) = self {
            let elidedEnvelope = envelope.elide(target, isRevealing: isRevealing, action: action)
            assert(elidedEnvelope.digest == envelope.digest)
            result = Envelope(wrapped: elidedEnvelope)
        } else {
            result = self
        }
        assert(result.digest == digest)
        return result
    }
    
    /// Returns an elided version of this envelope.
    ///
    /// - Parameters:
    ///   - target: An array of `DigestProvider`s.
    ///   - isRevealing: If `true`, the target set contains the digests of the elements to
    ///   leave revealed. If it is `false`, the target set contains the digests of the
    ///   elements to elide.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elide(_ target: [DigestProvider], isRevealing: Bool, action: ObscureAction = .elide) -> Envelope {
        elide(Set(target.map { $0.digest }), isRevealing: isRevealing, action: action)
    }
    
    /// Returns an elided version of this envelope.
    ///
    /// - Parameters:
    ///   - target: A `DigestProvider`.
    ///   - isRevealing: If `true`, the target is the element to leave revealed, eliding
    ///   all others. If it is `false`, the target is the element to elide, leaving all
    ///   others revealed.
    ///   - action: If provided, perform the specified action (encryption or compression) instead of elision.
    ///
    /// - Returns: The elided envelope.
    func elide(_ target: DigestProvider, isRevealing: Bool, action: ObscureAction = .elide) -> Envelope {
        elide([target], isRevealing: isRevealing, action: action)
    }
}

// MARK: - Uneliding an Envelope

public extension Envelope {
    /// Returns the unelided variant of this envelope.
    ///
    /// Throws an exception if the digest of the unelided version does not match.
    func unelide(_ envelope: Envelope) throws -> Envelope {
        guard digest == envelope.digest else {
            throw EnvelopeError.invalidDigest
        }
        return envelope
    }
}
