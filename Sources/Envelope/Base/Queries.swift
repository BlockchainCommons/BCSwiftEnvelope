import Foundation
import SecureComponents

extension EnvelopeError {
    static let nonexistentAssertion = EnvelopeError("nonexistentAssertion")
    static let ambiguousPredicate = EnvelopeError("ambiguousPredicate")
}

public extension Envelope {
    /// The envelope's subject.
    ///
    /// For an envelope with no assertions, `subject` will return the same envelope.
    var subject: Envelope {
        if case .node(let subject, _, _) = self {
            return subject
        }
        return self
    }

    /// The envelope's assertions.
    var assertions: [Envelope] {
        guard case .node(_, let assertions, _) = self else {
            return []
        }
        return assertions
    }

    /// `true` if the envelope has at least one assertion, `false` otherwise.
    var hasAssertions: Bool {
        !assertions.isEmpty
    }

    /// If the envelope's subject is an assertion return it, else return `nil`.
    var assertion: Envelope? {
        guard isSubjectAssertion else {
            return nil
        }
        return subject
    }

    /// The envelope's predicate, or `nil` if the envelope is not an assertion.
    var predicate: Envelope! {
        guard case .assertion(let assertion) = self else {
            return nil
        }
        return assertion.predicate
    }

    /// The envelope's object, or `nil` if the envelope is not an assertion.
    var object: Envelope! {
        guard case .assertion(let assertion) = self else {
            return nil
        }
        return assertion.object
    }

    /// The envelope's leaf CBOR object, or `nil` if the envelope is not a leaf.
    var leaf: CBOR? {
        guard case .leaf(let cbor, _) = subject else {
            return nil
        }
        return cbor
    }

    /// The envelope's `KnownValue`, or `nil` if the envelope is not case `.knownValue`.
    var knownValue: KnownValue? {
        guard case .knownValue(let knownValue, _) = self else {
            return nil
        }
        return knownValue
    }
}

public extension Envelope {
    /// `true` if the envelope is case `.leaf`, `false` otherwise.
    var isLeaf: Bool {
        guard case .leaf = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.node`, `false` otherwise.
    var isNode: Bool {
        guard case .node = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.encrypted`, `false` otherwise.
    var isEncrypted: Bool {
        guard case .encrypted = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.compressed`, `false` otherwise.
    var isCompressed: Bool {
        guard case .compressed = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.elided`, `false` otherwise.
    var isElided: Bool {
        guard case .elided = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.wrapped`, `false` otherwise.
    var isWrapped: Bool {
        guard case .wrapped = self else {
            return false
        }
        return true
    }
    
    /// `true` if the envelope is case `.knownValue`, `false` otherwise.
    var isKnownValue: Bool {
        guard case .knownValue = self else {
            return false
        }
        return true
    }
}

public extension Envelope {
    /// `true` if the subject of the envelope is an assertion, `false` otherwise.
    var isSubjectAssertion: Bool {
        switch self {
        case .assertion:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .assertion = subject {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// `true` if the subject of the envelope has been encrypted, `false` otherwise.
    var isSubjectEncrypted: Bool {
        switch self {
        case .encrypted:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .encrypted = subject {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// `true` if the subject of the envelope has been compressed, `false` otherwise.
    var isSubjectCompressed: Bool {
        switch self {
        case .compressed:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .compressed = subject {
                return true
            }
            return false
        default:
            return false
        }
    }

    /// `true` if the subject of the envelope has been elided, `false` otherwise.
    var isSubjectElided: Bool {
        switch self {
        case .elided:
            return true
        case .node(subject: let subject, assertions: _, digest: _):
            if case .elided = subject {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// `true` if the subject of the envelope has been encrypted, elided, or compressed, `false` otherwise.
    ///
    /// Obscured assertion envelopes may exist in the list of an envelope's assertions.
    var isSubjectObscured: Bool {
        isSubjectEncrypted || isSubjectElided || isSubjectCompressed
    }
}

public extension Envelope {
    /// `true` if the envelope is *internal*, that is, it has child elements, or `false` if it is a leaf node.
    ///
    /// Internal elements include `.node`, `.wrapped`, and `.assertion`.
    var isInternal: Bool {
        isNode || isWrapped || isSubjectAssertion
    }
    
    /// `true` if the envelope is encrypted, elided, or compressed; `false` otherwise.
    var isObscured: Bool {
        isEncrypted || isElided || isCompressed
    }
}

public extension Envelope {
    /// Returns the envelope's subject, decoded as the given type.
    ///
    /// - Throws: Throws `EnvelopeError.invalidFormat` if the encoded type doesn't match the given type.
    func extractSubject<T>(_ type: T.Type) throws -> T {
        switch self {
        case .wrapped(let envelope, _):
            guard let result = envelope as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .node(let subject, _, _):
            return try subject.extractSubject(type)
        case .leaf(let cbor, _):
            let t = (type.self as! CBORDecodable.Type)
            return try t.init(cbor: cbor) as! T
        case .knownValue(let knownValue, _):
            guard let result = knownValue as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .assertion(let assertion):
            guard let result = assertion as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .encrypted(let encryptedMessage):
            guard let result = encryptedMessage as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .compressed(let compressed):
            guard let result = compressed as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        case .elided(let digest):
            guard let result = digest as? T else {
                throw EnvelopeError.invalidFormat
            }
            return result
        }
    }
}

public extension Envelope {
    /// Returns all assertions with the given predicate.
    func assertions(withPredicate predicate: Envelope) -> [Envelope] {
        return assertions.filter { $0.subject.predicate.digest == predicate.digest }
    }
    
    /// Returns all assertions with the given predicate.
    func assertions(withPredicate predicate: CBOREncodable) -> [Envelope] {
        assertions(withPredicate: Envelope(predicate))
    }
    
    /// Returns all assertions with the given predicate.
    func assertions(withPredicate predicate: KnownValue) -> [Envelope] {
        assertions(withPredicate: Envelope(knownValue: predicate))
    }
}

public extension Envelope {
    /// Returns the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    func optionalAssertion(withPredicate predicate: Envelope) throws -> Envelope? {
        let a = assertions(withPredicate: predicate)
        guard !a.isEmpty else {
            return nil
        }
        guard
            a.count == 1,
            let result = a.first
        else {
            throw EnvelopeError.ambiguousPredicate
        }
        return result
    }
    
    /// Returns the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    func assertion(withPredicate predicate: Envelope) throws -> Envelope {
        guard let a = try optionalAssertion(withPredicate: predicate) else {
            throw EnvelopeError.invalidFormat
        }
        return a
    }
    
    /// Returns the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    func optionalAssertion(withPredicate predicate: CBOREncodable) throws -> Envelope? {
        try optionalAssertion(withPredicate: Envelope(predicate))
    }
    
    /// Returns the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    func assertion(withPredicate predicate: CBOREncodable) throws -> Envelope {
        try assertion(withPredicate: Envelope(predicate))
    }
    
    /// Returns the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    func optionalAssertion(withPredicate predicate: KnownValue) throws -> Envelope? {
        try optionalAssertion(withPredicate: Envelope(knownValue: predicate))
    }
    
    /// Returns the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    func assertion(withPredicate predicate: KnownValue) throws -> Envelope {
        try assertion(withPredicate: Envelope(knownValue: predicate))
    }
}

public extension Envelope {
    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    func optionalObject(forPredicate predicate: Envelope) throws -> Envelope? {
        try optionalAssertion(withPredicate: predicate)?.subject.object
    }

    /// Returns the object of the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    func object(forPredicate predicate: Envelope) throws -> Envelope {
        try assertion(withPredicate: predicate).object
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    func optionalObject(forPredicate predicate: CBOREncodable) throws -> Envelope? {
        try optionalObject(forPredicate: Envelope(predicate))
    }

    /// Returns the object of the assertion with the given predicate
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    func object(forPredicate predicate: CBOREncodable) throws -> Envelope {
        try object(forPredicate: Envelope(predicate))
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    func optionalObject(forPredicate predicate: KnownValue) throws -> Envelope? {
        try optionalObject(forPredicate: Envelope(knownValue: predicate))
    }

    /// Returns the object of the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    func object(forPredicate predicate: KnownValue) throws -> Envelope {
        try object(forPredicate: Envelope(knownValue: predicate))
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractOptionalObject<T>(_ type: T.Type, forPredicate predicate: Envelope) throws -> T? where T: CBORDecodable {
        try optionalObject(forPredicate: predicate)?.extractSubject(type)
    }
    
    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func optionalObject<T>(_ type: T.Type, forPredicate predicate: Envelope) throws -> T? where T: EnvelopeDecodable {
        try type.self.init(envelope: optionalObject(forPredicate: predicate))
    }

    /// Returns the object of the assertion with the given predicate
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractObject<T>(_ type: T.Type, forPredicate predicate: Envelope) throws -> T where T: CBORDecodable {
        try object(forPredicate: predicate).extractSubject(type)
    }

    /// Returns the object of the assertion with the given predicate
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func object<T>(_ type: T.Type, forPredicate predicate: Envelope) throws -> T where T: EnvelopeDecodable {
        try type.self.init(envelope: object(forPredicate: predicate))
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractOptionalObject<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> T? where T: CBORDecodable {
        try extractOptionalObject(type, forPredicate: Envelope(predicate))
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func optionalObject<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> T? where T: EnvelopeDecodable {
        try optionalObject(type, forPredicate: Envelope(predicate))
    }

    /// Returns the object of the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractObject<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: Envelope(predicate))
    }

    /// Returns the object of the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func object<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> T where T: EnvelopeDecodable {
        try object(type, forPredicate: Envelope(predicate))
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractOptionalObject<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> T? where T: CBORDecodable {
        try extractOptionalObject(type, forPredicate: Envelope(knownValue: predicate))
    }

    /// Returns the object of the assertion with the given predicate, or `nil` if none exists.
    ///
    /// Throws an exception if there are multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func optionalObject<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> T? where T: EnvelopeDecodable {
        try optionalObject(type, forPredicate: Envelope(knownValue: predicate))
    }

    /// Returns the object of the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractObject<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: Envelope(knownValue: predicate))
    }

    /// Returns the object of the assertion with the given predicate.
    ///
    /// Throws an exception if there is no matching or multiple matching predicates.
    /// Throws an exception if the encoded type doesn't match the given type.
    func object<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> T where T: EnvelopeDecodable {
        try object(type, forPredicate: Envelope(knownValue: predicate))
    }
}

public extension Envelope {
    /// Returns the objects of all assertions with the matching predicate.
    func objects(forPredicate predicate: Envelope) -> [Envelope] {
        assertions(withPredicate: predicate).map { $0.object! }
    }
    
    /// Returns the objects of all assertions with the matching predicate.
    func objects(forPredicate predicate: KnownValue) -> [Envelope] {
        objects(forPredicate: Envelope(predicate))
    }
    
    /// Returns the objects of all assertions with the matching predicate.
    ///
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractObjects<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> [T] where T: CBORDecodable {
        let predicate = Envelope(predicate)
        return try objects(forPredicate: predicate).map { try $0.extractSubject(type) }
    }
    
    /// Returns the objects of all assertions with the matching predicate.
    ///
    /// Throws an exception if the encoded type doesn't match the given type.
    func objects<T>(_ type: T.Type, forPredicate predicate: CBOREncodable) throws -> [T] where T: EnvelopeDecodable {
        let predicate = Envelope(predicate)
        return try objects(forPredicate: predicate).map { try type.self.init(envelope: $0) }
    }

    /// Returns the objects of all assertions with the matching predicate.
    ///
    /// Throws an exception if the encoded type doesn't match the given type.
    func extractObjects<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> [T] where T: CBORDecodable {
        let predicate = Envelope(predicate)
        return try objects(forPredicate: predicate).map { try $0.extractSubject(type) }
    }

    /// Returns the objects of all assertions with the matching predicate.
    ///
    /// Throws an exception if the encoded type doesn't match the given type.
    func objects<T>(_ type: T.Type, forPredicate predicate: KnownValue) throws -> [T] where T: EnvelopeDecodable {
        let predicate = Envelope(predicate)
        return try objects(forPredicate: predicate).map { try type.self.init(envelope: $0) }
    }
}

public extension Envelope {
    private func validateNonemptyString(_ s: String?) throws -> String? {
        guard let s else {
            return nil
        }
        guard !s.isEmpty else {
            throw EnvelopeError.invalidFormat
        }
        return s
    }
    
    
    func extractString(forPredicte predicate: Envelope) throws -> String {
        try extractObject(String.self, forPredicate: predicate)
    }
    
    func extractString(forPredicte predicate: CBOREncodable) throws -> String {
        try extractObject(String.self, forPredicate: predicate)
    }
    
    func extractString(forPredicte predicate: KnownValue) throws -> String {
        try extractObject(String.self, forPredicate: predicate)
    }
    
    
    func extractNonemptyString(forPredicate predicate: Envelope) throws -> String {
        try validateNonemptyString(extractString(forPredicte: predicate))!
    }
    
    func extractNonemptyString(forPredicate predicate: CBOREncodable) throws -> String {
        try validateNonemptyString(extractString(forPredicte: predicate))!
    }
    
    func extractNonemptyString(forPredicate predicate: KnownValue) throws -> String {
        try validateNonemptyString(extractString(forPredicte: predicate))!
    }
    
    
    func extractOptionalString(forPredicate predicate: Envelope) throws -> String? {
        try extractOptionalObject(String.self, forPredicate: predicate)
    }
    
    func extractOptionalString(forPredicate predicate: CBOREncodable) throws -> String? {
        try extractOptionalObject(String.self, forPredicate: predicate)
    }
    
    func extractOptionalString(forPredicate predicate: KnownValue) throws -> String? {
        try extractOptionalObject(String.self, forPredicate: predicate)
    }
    
    
    func extractOptionalNonemptyString(forPredicate predicate: Envelope) throws -> String? {
        try validateNonemptyString(extractOptionalString(forPredicate: predicate))
    }
    
    func extractOptionalNonemptyString(forPredicate predicate: CBOREncodable) throws -> String? {
        try validateNonemptyString(extractOptionalString(forPredicate: predicate))
    }
    
    func extractOptionalNonemptyString(forPredicate predicate: KnownValue) throws -> String? {
        try validateNonemptyString(extractOptionalString(forPredicate: predicate))
    }
}

public extension Envelope {
    /// Returns the number of structural elements in the envelope, including itself.
    var elementsCount: Int {
        var result = 0
        
        func _count(_ envelope: Envelope) {
            result += 1
            switch envelope {
            case .node(let subject, let assertions, _):
                result += subject.elementsCount
                for assertion in assertions {
                    result += assertion.elementsCount
                }
            case .assertion(let assertion):
                result += assertion.predicate.elementsCount
                result += assertion.object.elementsCount
            case .wrapped(let envelope, _):
                result += envelope.elementsCount
            default:
                break
            }
        }
        
        _count(self)
        
        return result
    }
}
