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
    
    /// Represents a compressed envelope.
    case compressed(Compressed, Digest)
    
    /// Represents an elided envelope.
    case elided(Digest)
}

public extension Envelope {
    func description(context: FormatContext?) -> String {
        switch self {
        case .node(subject: let subject, assertions: let assertions, digest: _):
            return ".node(\(subject), \(assertions))"
        case .leaf(let cbor, _):
            return ".cbor(\(cbor.formatItem(context: context).description))"
        case .wrapped(let envelope, _):
            return ".wrapped(\(envelope))"
        case .knownValue(let knownValue, _):
            return ".knownValue(\(knownValue))"
        case .assertion(let assertion):
            return ".assertion(\(assertion.predicate), \(assertion.object))"
        case .encrypted:
            return ".encrypted"
        case .compressed:
            return ".compressed"
        case .elided:
            return ".elided"
        }
    }
}

extension Envelope: CustomStringConvertible {
    public var description: String {
        description(context: nil)
    }
}

// MARK: - Constructing Envelopes

public extension Envelope {
    /// Create an envelope with the given subject.
    ///
    /// If the subject is another ``Envelope``, a wrapped envelope is created.
    /// If the subject is a ``KnownValue``, a known value envelope is created.
    /// If the subject is an ``Assertion``, an assertion envelope is created.
    /// If the subject is an `EncryptedMessage`, with a properly declared `Digest`, then an encrypted Envelope is created.
    /// If the subject is any type conforming to `CBOREncodable`, then a leaf envelope is created.
    /// Any other type passed as `subject` is a programmer error and results in a trap.
    ///
    /// ```swift
    /// let e = Envelope("Hello")
    /// print(e.format)
    /// ```
    ///
    /// ```
    /// "Hello"
    /// ```
    /// - Parameter subject: The envelope's subject.
    init(_ subject: Any) {
        if let envelope = subject as? Envelope {
            self.init(wrapped: envelope)
        } else if let knownValue = subject as? KnownValue {
            self.init(knownValue: knownValue)
        } else if let assertion = subject as? Assertion {
            self.init(assertion: assertion)
        } else if
            let encryptedMessage = subject as? EncryptedMessage,
            encryptedMessage.digest != nil
        {
            try! self.init(encryptedMessage: encryptedMessage)
        } else if let cborItem = subject as? CBOREncodable {
            self.init(leaf: cborItem.cbor)
        } else {
            preconditionFailure()
        }
    }
    
    /// Create an envelope with the given subject.
    ///
    /// This is a convenience constructor for ``KnownValue`` subjects.
    ///
    /// ```swift
    /// let e = Envelope(.verifiedBy)
    /// print(e.format)
    /// ```
    ///
    /// ```
    /// verifiedBy
    /// ```
    /// - Parameter knownValue: The envelope's subject, a ``KnownValue``.
    init(_ knownValue: KnownValue) {
        self.init(knownValue: knownValue)
    }

    /// Create an assertion envelope with the given predicate and object.
    init(_ predicate: Any, _ object: Any) {
        self.init(assertion: Assertion(predicate: predicate, object: object))
    }

    /// Create an assertion envelope with the given `KnownValue` predicate and object.
    init(_ predicate: KnownValue, _ object: Any) {
        self.init(assertion: Assertion(predicate: predicate, object: object))
    }
}

extension Envelope: ExpressibleByIntegerLiteral {
    /// Creates an ``Envelope`` from an integer literal.
    public init(integerLiteral value: Int) {
        self.init(value)
    }
}

extension Envelope: ExpressibleByStringLiteral {
    /// Creates an ``Envelope`` from a `String` literal.
    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }
}

public extension Envelope {
    /// Convenience constructor to create an assertion ``Envelope`` with the `isA` predicate and the provided object.
    static func isA(_ object: Envelope) -> Envelope {
        Envelope(.isA, object)
    }

    /// Convenience constructor to create an assertion ``Envelope`` with the `id` predicate and the provided `CID` as its object.
    static func id(_ id: CID) -> Envelope {
        Envelope(.id, id)
    }
}

// MARK: - Internal constructors

extension Envelope {
    init(subject: Envelope, uncheckedAssertions: [Envelope]) {
        assert(!uncheckedAssertions.isEmpty)
        let sortedAssertions = uncheckedAssertions.sorted() { $0.digest < $1.digest }
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        let digest = Digest(Data(digests.map { $0.data }.joined()))

        self = .node(subject: subject, assertions: sortedAssertions, digest: digest)
    }

    init(subject: Envelope, assertions: [Envelope]) throws {
        guard assertions.allSatisfy({ $0.isSubjectAssertion || $0.isSubjectObscured }) else {
            throw EnvelopeError.invalidFormat
        }
        self.init(subject: subject, uncheckedAssertions: assertions)
    }

    init(knownValue: KnownValue) {
        self = .knownValue(knownValue, knownValue.digest)
    }

    init(assertion: Assertion) {
        self = .assertion(assertion)
    }

    init(encryptedMessage: EncryptedMessage) throws {
        guard encryptedMessage.digest != nil else {
            throw EnvelopeError.missingDigest
        }
        self = .encrypted(encryptedMessage)
    }
    
    init(compressed: Compressed, digest: Digest) {
        self = .compressed(compressed, digest)
    }

    init(elided digest: Digest) {
        self = .elided(digest)
    }

    init(leaf: CBOR) {
        let digest = Digest(leaf.cborData)
        self = .leaf(leaf, digest)
    }

    init(wrapped envelope: Envelope) {
        let digest = Digest(envelope.digest)
        self = .wrapped(envelope, digest)
    }
}
