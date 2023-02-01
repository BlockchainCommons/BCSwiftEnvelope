import Foundation
import SecureComponents

/// Represents an assertion in an envelope.
///
/// This structure is public but opaque, and the APIs on ``Envelope`` itself should be used to manipulate it.
public struct Assertion {
    let predicate: Envelope
    let object: Envelope
    let digest: Digest
    
    /// Creates an ``Assertion`` and calculates its digest.
    init(predicate: Any, object: Any) {
        let p: Envelope
        if let predicate = predicate as? Envelope {
            p = predicate
        } else {
            p = Envelope(predicate)
        }
        let o: Envelope
        if let object = object as? Envelope {
            o = object
        } else {
            o = Envelope(object)
        }
        self.predicate = p
        self.object = o
        self.digest = Digest(p.digest + o.digest)
    }
}

extension Assertion: CBORTaggedCodable {
    public static var cborTag = Tag.assertion
    
    public var untaggedCBOR: CBOR {
        [predicate.cbor, object.cbor]
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case CBOR.array(let array) = untaggedCBOR,
            array.count == 2
        else {
            throw CBORDecodingError.invalidFormat
        }
        let predicate = try Envelope(cbor: array[0])
        let object = try Envelope(cbor: array[1])
        self = Self(predicate: predicate, object: object)
    }
}

extension Assertion: Equatable {
    public static func ==(lhs: Assertion, rhs: Assertion) -> Bool {
        lhs.digest == rhs.digest
    }
}

/// Support for manipulating assertions.

public extension Envelope {
    /// Returns a new ``Envelope`` with the given assertion added.
    ///
    /// ```swift
    /// let assertion = Envelope("knows", "Bob")
    /// let e = Envelope("Alice")
    ///     .addAssertion(assertion)
    /// print(e.format)
    /// ```
    ///
    /// ```
    /// "Alice" [
    ///     "knows": "Bob"
    /// ]
    /// ```
    ///
    /// - Parameters:
    ///   - assertion: The assertion envelope to be added. May be encrypted or elided, but it adding an encrypted or elided envelope that is not an assertion results in undefined behavior. If `assertion` is `nil`, no assertion is addded.
    ///   - salted: If `true`, add a `salt: Salt` assertion. See ``Envelope/Envelope/addSalt()``.
    ///
    /// - Returns: The envelope with the assertion added. If `assertion` is nil, returns the unmodifed envelope.
    ///
    /// - Throws: Throws an exception if `assertion` is not an assertion envelope.
    func addAssertion(_ assertion: Envelope?, salted: Bool = false) throws -> Envelope {
        guard let assertion else {
            return self
        }
        guard assertion.isSubjectAssertion || assertion.isSubjectObscured else {
            throw EnvelopeError.invalidFormat
        }
        let envelope2 = salted ? assertion.addSalt() : assertion
        switch self {
        case .node(subject: let subject, assertions: let assertions, digest: _):
            if !assertions.contains(where: { $0.digest == envelope2.digest}) {
                return Envelope(subject: subject, uncheckedAssertions: assertions.appending(envelope2))
            } else {
                return self
            }
        default:
            return Envelope(subject: subject, uncheckedAssertions: [envelope2])
        }
    }
    
    /// Returns a new ``Envelope`` with the given array of assertions added.
    ///
    /// - Parameters:
    ///   - envelopes: An array of assertion envelopes to be added.
    ///   - salted: If `true`, add a `salt: Salt` assertion. See ``Envelope/Envelope/addSalt()``.
    ///
    /// - Returns: The envelope with the assertions added.
    ///
    /// - Throws: Throws an exception if any of `envelopes` is not an assertion envelope.
    func addAssertions(_ envelopes: [Envelope], salted: Bool = false) throws -> Envelope {
        try envelopes.reduce(into: self) {
            $0 = try $0.addAssertion($1, salted: salted)
        }
    }

    /// Returns a new ``Envelope`` with the given assertion added.
    ///
    /// The values passed for `predicate` and `object` may be any of the same values that can be passed to ``Envelope/Envelope/init(_:)-2fdao``.
    ///
    /// ```swift
    /// let e = Envelope("Alice")
    ///     .addAssertion("knows", "Bob")
    /// print(e.format)
    /// ```
    ///
    /// ```
    /// "Alice" [
    ///     "knows": "Bob"
    /// ]
    /// ```
    ///
    /// - Parameters:
    ///   - predicate: The assertion's predicate.
    ///   - object: The assertion's object. If `nil`, no assertion is added.
    ///   - salted: If `true`, add a `salt: Salt` assertion. See ``Envelope/Envelope/addSalt()``.
    ///
    /// - Returns: The envelope with the assertion added. If `object` is nil, returns the unmodifed envelope.
    func addAssertion(_ predicate: Any, _ object: Any?, salted: Bool = false) -> Envelope {
        guard let object else {
            return self
        }
        return addAssertion(Assertion(predicate: predicate, object: object), salted: salted)
    }

    /// Returns a new ``Envelope`` with the given assertion added.
    ///
    /// The value passed for `predicate` is a ``KnownValue-swift.struct`` and the value passed for `object` may be any of the same values that can be passed to ``Envelope/Envelope/init(_:)-2fdao``.
    ///
    /// ```swift
    /// let e = Envelope("Alice")
    ///     .addAssertion(.isA, "person")
    /// print(e.format)
    /// ```
    ///
    /// ```
    /// "Alice" [
    ///     isA: "person"
    /// ]
    /// ```
    ///
    /// - Parameters:
    ///   - predicate: The assertion's predicate, a ``KnownValue-swift.struct``.
    ///   - object: The assertion's object. If `nil`, no assertion is added.
    ///   - salted: If `true`, add a `salt: Salt` assertion. See ``Envelope/Envelope/addSalt()``.
    ///
    /// - Returns: The envelope with the assertion added. If `object` is nil, returns the unmodifed envelope.
    func addAssertion(_ predicate: KnownValue, _ object: Any?, salted: Bool = false) -> Envelope {
        guard let object else {
            return self
        }
        return addAssertion(Assertion(predicate: predicate, object: object), salted: salted)
    }
}

public extension Envelope {
    /// If the condition is met, returns a new ``Envelope`` with the given assertion
    /// added, otherwise returns the same envelope.
    ///
    /// The expression passed for `assertino` is lazily evaluated only if `condition` is `true`.
    ///
    /// See ``addAssertion(_:salted:)`` for more information.
    func addAssertion(if condition: Bool, _ assertion: @autoclosure () -> Envelope?, salted: Bool = false) throws -> Envelope {
        guard condition else {
            return self
        }
        return try addAssertion(assertion(), salted: salted)
    }

    /// If the condition is met, returns a new ``Envelope`` with the given assertion
    /// added, otherwise returns the same envelope.
    ///
    /// The expressions passed for `predicate` and `object` are lazily evaluated only if `condition` is `true`.
    ///
    /// See ``addAssertion(_:_:salted:)-277sn`` for more information.
    func addAssertion(if condition: Bool, _ predicate: @autoclosure () -> Any, _ object: @autoclosure () -> Any?, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(predicate(), object(), salted: salted)
    }

    /// If the condition is met, returns a new ``Envelope`` with the given assertion
    /// added, otherwise returns the same envelope.
    ///
    /// The expressions passed for `predicate` and `object` are lazily evaluated only if `condition` is `true`.
    ///
    /// See ``addAssertion(_:_:salted:)-9sf9h`` for more information.
    func addAssertion(if condition: Bool, _ predicate: @autoclosure () -> KnownValue, _ object: @autoclosure () -> Any?, salted: Bool = false) -> Envelope {
        guard condition else {
            return self
        }
        return addAssertion(predicate(), object(), salted: salted)
    }
}

public extension Envelope {
    /// Returns a new envelope with the given assertion removed. If the assertion does
    /// not exist, returns the same envelope.
    func removeAssertion(_ target: DigestProvider) -> Envelope {
        var assertions = self.assertions
        let target = target.digest
        if let index = assertions.firstIndex(where: { $0.digest == target }) {
            assertions.remove(at: index)
        }
        if assertions.isEmpty {
            return subject
        } else {
            return Envelope(subject: subject, uncheckedAssertions: assertions)
        }
    }
    
    /// Returns a new envelope with the given assertion replaced by the provided one. If
    /// the targeted assertion does not exist, returns the same envelope.
    func replaceAssertion(_ assertion: DigestProvider, with newAssertion: Envelope) throws -> Envelope {
        var e = self
        e = e.removeAssertion(assertion)
        e = try e.addAssertion(newAssertion)
        return e
    }
}

public extension Envelope {
    /// Returns a new envelope with its subject replaced by the provided one.
    func replaceSubject(with subject: Envelope) -> Envelope {
        assertions.reduce(into: subject) {
            try! $0 = $0.addAssertion($1)
        }
    }
}

// MARK: - Internal

extension Envelope {
    /// Returns a new ``Envelope`` with the given assertion added.
    func addAssertion(_ assertion: Assertion?, salted: Bool = false) -> Envelope {
        guard let assertion else {
            return self
        }
        return try! addAssertion(Envelope(assertion: assertion), salted: salted)
    }
}
