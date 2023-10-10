import Foundation

extension EnvelopeError {
    static let nonexistentAttachment = EnvelopeError("nonexistentAttachment")
    static let ambiguousAttachment = EnvelopeError("ambiguousAttachment")
    static let invalidAttachment = EnvelopeError("invalidAttachment")
}

public extension Assertion {
    /// Creates an attachment assertion. See: [BCR-2023-006](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2023-006-envelope-attachment.md)
    init(payload: Envelope, vendor: String, conformsTo: String? = nil) {
        self.init(
            predicate: KnownValue.attachment,
            object: payload
                .wrap()
                .addAssertion(.vendor, vendor)
                .addAssertion(.conformsTo, conformsTo)
        )
    }
    
    var attachmentPayload: Envelope {
        get throws {
            try object.unwrap()
        }
    }
    
    var attachmentVendor: String {
        get throws {
            try object.extractObject(String.self, forPredicate: .vendor)
        }
    }
    
    var attachmentConformsTo: String? {
        get throws {
            try object.extractOptionalObject(String.self, forPredicate: .conformsTo)
        }
    }
    
    @discardableResult
    func validateAttachment() throws -> Self {
        let payload = try attachmentPayload
        let vendor = try attachmentVendor
        let conformsTo = try attachmentConformsTo
        let assertion = Assertion(payload: payload, vendor: vendor, conformsTo: conformsTo)
        let e = Envelope(assertion)
        guard e.isEquivalent(to: self.envelope) else {
            throw EnvelopeError.invalidAttachment
        }
        return self
    }
}

public extension Envelope {
    init(payload: Envelope, vendor: String, conformsTo: String? = nil) {
        self.init(Assertion(payload: payload, vendor: vendor, conformsTo: conformsTo))
    }
    
    func addAttachment(_ payload: Envelope, vendor: String, conformsTo: String? = nil, salted: Bool = false) -> Envelope {
        addAssertion(
            Assertion(payload: payload, vendor: vendor, conformsTo: conformsTo)
        )
    }
}

public extension Envelope {
    var attachmentPayload: Envelope {
        get throws {
            guard case .assertion(let assertion) = self else {
                throw EnvelopeError.invalidAttachment
            }
            return try assertion.attachmentPayload
        }
    }
    
    var attachmentVendor: String {
        get throws {
            guard case .assertion(let assertion) = self else {
                throw EnvelopeError.invalidAttachment
            }
            return try assertion.attachmentVendor
        }
    }
    
    var attachmentConformsTo: String? {
        get throws {
            guard case .assertion(let assertion) = self else {
                throw EnvelopeError.invalidAttachment
            }
            return try assertion.attachmentConformsTo
        }
    }
    
    func attachments(withVendor vendor: String? = nil, conformingTo conformsTo: String? = nil) throws -> [Envelope] {
        try assertions(withPredicate: .attachment).filter { envelope in
            try envelope.validateAttachment()
            if let vendor {
                guard try envelope.attachmentVendor == vendor else {
                    return false
                }
            }
            if let conformsTo {
                guard try envelope.attachmentConformsTo == conformsTo else {
                    return false
                }
            }
            return true
        }
    }
    
    @discardableResult
    func validateAttachment() throws -> Self {
        guard case .assertion(let assertion) = self else {
            throw EnvelopeError.invalidAttachment
        }
        try assertion.validateAttachment()
        return self
    }
    
    func attachment(withVendor vendor: String? = nil, conformingTo conformsTo: String? = nil) throws -> Envelope {
        let attachments = try attachments(withVendor: vendor, conformingTo: conformsTo)
        guard !attachments.isEmpty else {
            throw EnvelopeError.nonexistentAttachment
        }
        guard attachments.count == 1 else {
            throw EnvelopeError.ambiguousAttachment
        }
        return attachments.first!
    }
}
