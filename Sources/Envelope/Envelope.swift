import Foundation
import SecureComponents
import WolfBase

/// A flexible container for structured data.
///
/// Envelopes are immutable. You create "mutations" by creating new envelopes from old envelopes.
public indirect enum Envelope: DigestProvider {
    /// Represents an envelope with one or more assertions.
    case node(subject: Envelope, assertions: [Envelope], digest: Digest)
    
    /// Represents an envelope with encoded CBOR data.
    case leaf(CBOR, Digest)
    
    /// Represents an envelope that wraps another envelope.
    case wrapped(Envelope, Digest)
    
    /// Represents a value from a namespace of unsigned integers.
    case knownValue(KnownValue, Digest)
    
    /// Represents an assertion.
    ///
    /// An assertion is a predicate-object pair, each of which is itself an ``Envelope``.
    case assertion(Assertion)
    
    /// Represents an encrypted envelope.
    case encrypted(EncryptedMessage)
    
    /// Represents an elided envelope.
    case elided(Digest)
}

extension Envelope: CustomStringConvertible {
    public var description: String {
        switch self {
        case .node(subject: let subject, assertions: let assertions, digest: _):
            return ".node(\(subject), \(assertions))"
        case .leaf(let cbor, _):
            return ".cbor(\(cbor.formatItem.description))"
        case .wrapped(let envelope, _):
            return ".wrapped(\(envelope))"
        case .knownValue(let knownValue, _):
            return ".knownValue(\(knownValue))"
        case .assertion(let assertion):
            return ".assertion(\(assertion.predicate), \(assertion.object))"
        case .encrypted(_):
            return ".encrypted"
        case .elided(_):
            return ".elided"
        }
    }
}
