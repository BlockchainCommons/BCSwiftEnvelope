import Foundation
import SecureComponents

// MARK: - Function Construction

public extension Envelope {
    /// Creates an envelope with a `«function»` subject.
    init(function identifier: FunctionIdentifier) {
        self.init(identifier)
    }
    
    /// Creates an envelope with a `«function»` subject.
    init(function name: String) {
        self.init(function: FunctionIdentifier(name))
    }
    
    /// Creates an envelope with a `«function»` subject.
    init(function value: Int, name: String? = nil) {
        self.init(function: FunctionIdentifier(value, name))
    }
}

// MARK: - Parameter Construction.

public extension Envelope {
    /// Creates a new envelope by adding a `❰parameter❱: value` assertion.
    ///
    /// - Parameters:
    ///   - param: A ``ParameterIdentifier``. This will be encoded as either an unsigned integer or a string.
    ///   - value: The argument value.
    ///
    /// - Returns: The new envelope. If `value` is `nil`, returns the original envelope.
    func addParameter(_ param: ParameterIdentifier, value: CBOREncodable?) -> Envelope {
        try! addAssertion(.parameter(param, value: value))
    }
    
    /// Creates a new envelope by adding a `❰parameter❱: value` assertion.
    ///
    /// - Parameters:
    ///   - param: A parameter name. This will be encoded as a string.
    ///   - value: The argument value.
    ///
    /// - Returns: The new envelope. If `value` is `nil`, returns the original envelope.
    func addParameter(_ name: String, value: CBOREncodable?) -> Envelope {
        try! addAssertion(.parameter(name, value: value))
    }
}

// MARK: - Request Construction

public extension Envelope {
    /// Creates an envelope with a `CID` subject and a `body: «function»` assertion.
    init(request id: CID, body: CBOREncodable) {
        self = Envelope(CBOR.tagged(.request, id.taggedCBOR))
            .addAssertion(.body, body)
    }
}

// MARK: - Response Construction

public extension Envelope {
    /// Creates an envelope with a `CID` subject and a `result: value` assertion.
    init(response id: CID, result: CBOREncodable? = KnownValue.ok) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.result, result)
    }
    
    /// Creates an envelope with a `CID` subject and a `result: value` assertion for each provided result.
    init(response id: CID, results: [CBOREncodable]) {
        var e = Envelope(CBOR.tagged(.response, id.taggedCBOR))
        for result in results {
            e = e.addAssertion(.result, result)
        }
        self = e
    }
    
    /// Creates an envelope with a `CID` subject and a `error: value` assertion.
    init(response id: CID, error: CBOREncodable) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.error, error)
    }
    
    /// Creates an envelope with an `unknown` subject and a `error: value` assertion.
    ///
    /// If `error` is nil, no assertion will be added.
    ///
    /// Used for an immediate response to a request without a proper ID.
    init(error: CBOREncodable?) {
        self = Envelope(CBOR.tagged(.response, "unknown"))
            .addAssertion(.error, error)
    }
}

// MARK: - Parameter decoding

public extension Envelope {
    /// Returns the argument for the given parameter.
    ///
    /// - Throws: Throws an exception if there is not exactly one matching `parameter`,
    /// or if the parameter value is not the correct type.
    func extractObject<T>(_ type: T.Type, forParameter parameter: ParameterIdentifier) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: parameter)
    }
    
    /// Returns an array of arguments for the given parameter.
    ///
    /// - Throws: Throws an exception if any of the parameter values are not the correct type.
    func extractObjects<T>(_ type: T.Type, forParameter parameter: ParameterIdentifier) throws -> [T] where T: CBORDecodable {
        try extractObjects(type, forPredicate: parameter)
    }
}

// MARK: - Result Decoding

public extension Envelope {
    /// Returns the object of the `result` predicate.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate.
    func result() throws -> Envelope {
        try extractObject(forPredicate: .result)
    }
    
    /// Returns the objects of every `result` predicate.
    func results() -> [Envelope] {
        extractObjects(forPredicate: .result)
    }
    
    /// Returns the object of the `result` predicate.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate, or if its
    /// object cannot be decoded to the specified `type`.
    func result<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .result)
    }
    
    /// Returns the objects of every `result` predicate.
    ///
    /// - Throws: Throws an if not all object cannot be decoded to the specified `type`.
    func results<T: CBORDecodable>(_ type: T.Type) throws -> [T] {
        try extractObjects(T.self, forPredicate: .result)
    }
    
    /// Checks whether the `result` predicate has the `KnownValue` `.ok`.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate.
    func isResultOK() throws -> Bool {
        try result(KnownValue.self) == .ok
    }
    
    /// Returns the error value.
    ///
    /// - Throws: Throws an exception if there is no `error` predicate.
    func error<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .error)
    }
}

// MARK: - Internal

extension Envelope {
    static func parameter(_ param: ParameterIdentifier, value: CBOREncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return Envelope(param.cbor, Envelope(value))
    }
    
    static func parameter(_ name: String, value: CBOREncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return parameter(ParameterIdentifier(name), value: value)
    }
}

