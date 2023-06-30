import Foundation
import SecureComponents

// MARK: - Function Construction

public extension Envelope {
    /// Creates an envelope with a `«function»` subject.
    init(function identifier: Function) {
        self.init(identifier)
    }
    
    /// Creates an envelope with a `«function»` subject.
    init(function name: String) {
        self.init(function: Function(name))
    }
    
    /// Creates an envelope with a `«function»` subject.
    init(function value: UInt64) {
        self.init(function: Function(value))
    }
}

// MARK: - Parameter Construction.

public extension Envelope {
    /// Adds a `❰parameter❱: value` assertion to the envelope.
    ///
    /// - Parameters:
    ///   - param: A ``Parameter``. This will be encoded as either an unsigned integer or a string.
    ///   - value: The argument value.
    ///
    /// - Returns: The new envelope. If `value` is `nil`, returns the original envelope.
    func addParameter(_ param: Parameter, value: EnvelopeEncodable?) -> Envelope {
        try! addAssertion(.parameter(param, value: value))
    }
    
    /// Adds a `❰parameter❱: value` assertion to the envelope.
    ///
    /// - Parameters:
    ///   - param: A parameter name. This will be encoded as a string.
    ///   - value: The argument value.
    ///
    /// - Returns: The new envelope. If `value` is `nil`, returns the original envelope.
    func addParameter(_ name: String, value: EnvelopeEncodable?) -> Envelope {
        try! addAssertion(.parameter(name, value: value))
    }
    
    /// Creates a new envelope containing a `❰parameter❱: value` assertion.
    ///
    /// - Parameters:
    ///   - param: A ``Parameter``. This will be encoded as either an unsigned integer or a string.
    ///   - value: The argument value.
    ///
    /// - Returns: The new assertion envelope. If `value` is `nil`, returns `nil`.
    static func parameter(_ param: Parameter, value: EnvelopeEncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return Envelope(param.cbor, Envelope(value))
    }
    
    /// Creates a new envelope containing a `❰parameter❱: value` assertion.
    ///
    /// - Parameters:
    ///   - param: A parameter name. This will be encoded as a string.
    ///   - value: The argument value.
    ///
    /// - Returns: The new envelope. If `value` is `nil`, returns the original envelope.
    static func parameter(_ name: String, value: EnvelopeEncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return parameter(Parameter(name), value: value)
    }
}

// MARK: - Request Construction

public extension Envelope {
    /// Creates an envelope with a `request(CID)` subject and a `body: «function»` assertion.
    init(request id: CID, body: Envelope) {
        precondition((try? body.extractSubject(Function.self)) != nil)
        self = Envelope(CBOR.tagged(.request, id.cbor))
            .addAssertion(.body, body)
    }
}

// MARK: - Request Decoding

public extension EnvelopeError {
    static let unknownFunction = EnvelopeError("unknownFunction")
}

public extension Envelope {
    var requestID: CID {
        get throws {
            guard
                let leaf = self.subject.leaf,
                case CBOR.tagged(.request, let cbor) = leaf
            else {
                throw EnvelopeError.invalidFormat
            }
            
            return try CID(cbor: cbor)
        }
    }
    
    var requestBody: Envelope {
        get throws {
            try object(forPredicate: .body)
        }
    }
    
    var function: Function {
        get throws {
            try extractSubject(Function.self)
        }
    }
    
    func checkFunction(_ function: Function) throws {
        guard try self.function == function else {
            throw EnvelopeError.unknownFunction
        }
    }
}

// MARK: - Response Construction

public extension Envelope {
    /// Creates an envelope with a `response(CID)` subject and a `result: value` assertion.
    init(response id: CID, result: EnvelopeEncodable? = KnownValue.ok) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.result, result)
    }
    
    /// Creates an envelope with a `CID` subject and a `result: value` assertion for each provided result.
    init(response id: CID, results: [EnvelopeEncodable]) {
        var e = Envelope(CBOR.tagged(.response, id.taggedCBOR))
        for result in results {
            e = e.addAssertion(.result, result)
        }
        self = e
    }
    
    /// Creates an envelope with a `CID` subject and a `error: value` assertion.
    init(response id: CID, error: EnvelopeEncodable) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.error, error)
    }
    
    /// Creates an envelope with an `unknown` subject and a `error: value` assertion.
    ///
    /// If `error` is nil, no assertion will be added.
    ///
    /// Used for an immediate response to a request without a proper ID, for example
    /// when a encrypted request envelope is received and the decryption fails, making
    /// it impossible to extract the request ID.
    init(error: EnvelopeEncodable?) {
        self = Envelope(CBOR.tagged(.response, KnownValue.unknown.cbor))
            .addAssertion(.error, error)
    }
}

// MARK: - Response Decoding

public extension Envelope {
    var responseID: CID {
        get throws {
            guard
                let leaf = self.subject.leaf,
                case CBOR.tagged(.response, let cbor) = leaf
            else {
                throw EnvelopeError.invalidFormat
            }
            
            return try CID(cbor: cbor)
        }
    }
    
    var isResponseIDUnknown: Bool {
        get throws {
            guard
                let leaf = self.subject.leaf,
                case CBOR.tagged(.response, let cbor) = leaf
            else {
                throw EnvelopeError.invalidFormat
            }
            
            guard
                let knownValue = try? KnownValue(cbor: cbor),
                knownValue == .unknown
            else {
                return false
            }
            
            return true
        }
    }
}

// MARK: - Parameter decoding

public extension Envelope {
    /// Returns the argument for the given parameter, or `nil` if none.
    ///
    /// - Throws: Throws an exception if there is not exactly zero or one matching `parameter`s,
    /// or if the parameter value is not the correct type.
    func extractOptionalObject<T>(_ type: T.Type, forParameter parameter: Parameter) throws -> T? where T: CBORDecodable {
        try extractOptionalObject(type, forPredicate: parameter)
    }

    /// Returns the argument for the given parameter, or `nil` if none.
    ///
    /// - Throws: Throws an exception if there is not exactly zero or one matching `parameter`s,
    /// or if the parameter value is not the correct type.
    func optionalObject<T>(_ type: T.Type, forParameter parameter: Parameter) throws -> T? where T: EnvelopeDecodable {
        try optionalObject(type, forPredicate: parameter)
    }

    /// Returns the argument for the given parameter.
    ///
    /// - Throws: Throws an exception if there is not exactly one matching `parameter`,
    /// or if the parameter value is not the correct type.
    func extractObject<T>(_ type: T.Type, forParameter parameter: Parameter) throws -> T where T: CBORDecodable {
        try extractObject(type, forPredicate: parameter)
    }

    /// Returns the argument for the given parameter.
    ///
    /// - Throws: Throws an exception if there is not exactly one matching `parameter`,
    /// or if the parameter value is not the correct type.
    func object<T>(_ type: T.Type, forParameter parameter: Parameter) throws -> T where T: EnvelopeDecodable {
        try object(type, forPredicate: parameter)
    }

    /// Returns an array of arguments for the given parameter.
    ///
    /// - Throws: Throws an exception if any of the parameter values are not the correct type.
    func extractObjects<T>(_ type: T.Type, forParameter parameter: Parameter) throws -> [T] where T: CBORDecodable {
        try extractObjects(type, forPredicate: parameter)
    }

    /// Returns an array of arguments for the given parameter.
    ///
    /// - Throws: Throws an exception if any of the parameter values are not the correct type.
    func objects<T>(_ type: T.Type, forParameter parameter: Parameter) throws -> [T] where T: EnvelopeDecodable {
        try objects(type, forPredicate: parameter)
    }
}

// MARK: - Result Decoding

public extension Envelope {
    /// Returns the object of the `result` predicate.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate.
    func result() throws -> Envelope {
        try object(forPredicate: .result)
    }
    
    /// Returns the objects of every `result` predicate.
    func results() -> [Envelope] {
        objects(forPredicate: .result)
    }
    
    /// Returns the object of the `result` predicate.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate, or if its
    /// object cannot be decoded to the specified `type`.
    func extractResult<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .result)
    }
    
    /// Returns the object of the `result` predicate.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate, or if its
    /// object cannot be decoded to the specified `type`.
    func result<T: EnvelopeDecodable>(_ type: T.Type) throws -> T {
        try object(T.self, forPredicate: .result)
    }

    /// Returns the objects of every `result` predicate.
    ///
    /// - Throws: Throws an if not all object cannot be decoded to the specified `type`.
    func extractResults<T: CBORDecodable>(_ type: T.Type) throws -> [T] {
        try extractObjects(T.self, forPredicate: .result)
    }

    /// Returns the objects of every `result` predicate.
    ///
    /// - Throws: Throws an if not all object cannot be decoded to the specified `type`.
    func results<T: EnvelopeDecodable>(_ type: T.Type) throws -> [T] {
        try objects(T.self, forPredicate: .result)
    }

    /// Checks whether the `result` predicate has the `KnownValue` `.ok`.
    ///
    /// - Throws: Throws an exception if there is no `result` predicate.
    var isResultOK: Bool {
        get throws {
            try extractResult(KnownValue.self) == .ok
        }
    }
    
    /// Returns `true` if this response contains an error, false otherwise.
    var isError: Bool {
        !objects(forPredicate: .error).isEmpty
    }
    
    /// Returns the error value.
    ///
    /// - Throws: Throws an exception if there is no `error` predicate.
    func extractError<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .error)
    }
    
    /// Returns the error value.
    ///
    /// - Throws: Throws an exception if there is no `error` predicate.
    func rrror<T: EnvelopeDecodable>(_ type: T.Type) throws -> T {
        try object(T.self, forPredicate: .error)
    }
}
