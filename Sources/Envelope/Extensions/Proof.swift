import Foundation
import SecureComponents

public extension Envelope {
    /// Returns a proof that this envelope includes every element in the target set.
    ///
    /// - Parameter target: The elements if this envelope that the proof must include.
    /// - Returns: The proof, of `nil` if it cannot be proven that the envelope contains every element in the target set.
    func proof(contains target: Set<Digest>) -> Envelope? {
        let revealSet = revealSet(of: target)
        guard target.isSubset(of: revealSet) else { return nil }
        return elideRevealing(revealSet).elideRemoving(target)
    }

    /// Returns a proof that this envelope includes the target element.
    ///
    /// - Parameter target: The elements if this envelope that the proof must include.
    /// - Returns: The proof, of `nil` if it cannot be proven that the envelope contains the targeted element.
    func proof(contains target: DigestProvider) -> Envelope? {
        proof(contains: [target.digest])
    }

    /// Confirms whether or not this envelope contains the target set using the given inclusion proof.
    ///
    /// - Parameters:
    ///   - target: The target elements that need to be proven exist somewhere in this envelope, even if they were elided or encrypted.
    ///   - proof: The inclusion proof to use.
    ///
    /// - Returns: `true` if every element of `target` is in this envelope as shown by `proof`, `false` otherwise.
    func confirm(contains target: Set<Digest>, using proof: Envelope) -> Bool {
        self.digest == proof.digest && proof.containsAll(in: target)
    }

    /// Confirms whether or not this envelope contains the target element using the given inclusion proof.
    ///
    /// - Parameters:
    ///   - target: The target element that needs to be proven to exist somewhere in this envelope, even if it was elided or encrypted.
    ///   - proof: The inclusion proof to use.
    ///
    /// - Returns: `true` if `target` is in this envelope as shown by `proof`, `false` otherwise.
    func confirm(contains target: DigestProvider, using proof: Envelope) -> Bool {
        confirm(contains: [target.digest], using: proof)
    }
}

extension Envelope {
    func revealSet(of target: Set<Digest>) -> Set<Digest> {
        var result: Set<Digest> = []
        revealSets(of: target, current: [], result: &result)
        return result
    }

    func revealSet(of target: DigestProvider) -> Set<Digest> {
        revealSet(of: [target.digest])
    }

    func containsAll(in target: Set<Digest>) -> Bool {
        var target = target
        removeAllFound(in: &target)
        return target.isEmpty
    }

    func contains(_ target: DigestProvider) -> Bool {
        containsAll(in: [target.digest])
    }
}

extension Envelope {
    func revealSets(of target: Set<Digest>, current: Set<Digest>, result: inout Set<Digest>) {
        var current = current
        current.insert(digest)

        if target.contains(digest) {
            result.formUnion(current)
        }

        switch self {
        case .node(let subject, let assertions, _):
            subject.revealSets(of: target, current: current, result: &result)
            for assertion in assertions {
                assertion.revealSets(of: target, current: current, result: &result)
            }
        case .wrapped(let envelope, _):
            envelope.revealSets(of: target, current: current, result: &result)
        case .assertion(let assertion):
            assertion.predicate.revealSets(of: target, current: current, result: &result)
            assertion.object.revealSets(of: target, current: current, result: &result)
        default:
            break
        }
    }
    
    func removeAllFound(in target: inout Set<Digest>) {
        if target.contains(digest) {
            target.remove(digest)
        }
        guard !target.isEmpty else { return }

        switch self {
        case .node(let subject, let assertions, _):
            subject.removeAllFound(in: &target)
            for assertion in assertions {
                assertion.removeAllFound(in: &target)
            }
        case .wrapped(let envelope, _):
            envelope.removeAllFound(in: &target)
        case .assertion(let assertion):
            assertion.predicate.removeAllFound(in: &target)
            assertion.object.removeAllFound(in: &target)
        default:
            break
        }
    }
}
