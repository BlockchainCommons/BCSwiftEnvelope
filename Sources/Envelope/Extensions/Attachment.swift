import Foundation

extension EnvelopeError {
    static let nonexistentAttachment = EnvelopeError("nonexistentAttachment")
    static let ambiguousAttachment = EnvelopeError("ambiguousAttachment")
    static let invalidAttachment = EnvelopeError("invalidAttachment")
}

public extension Assertion {
    /// Creates an attachment assertion. See: [BCR-2023-006](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2023-006-envelope-attachment.md)
    init(attachment: Envelope, vendor: String, conformsTo: String? = nil) {
        self.init(
            predicate: KnownValue.attachment,
            object: attachment
                .wrap()
                .addAssertion(.vendor, vendor)
                .addAssertion(.conformsTo, conformsTo)
        )
    }
}

public extension Envelope {
    func addAttachment(_ attachment: Envelope, vendor: String, conformsTo: String? = nil, salted: Bool = false) -> Envelope {
        addAssertion(
            Assertion(attachment: attachment, vendor: vendor, conformsTo: conformsTo)
        )
    }
}

public extension Envelope {
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
    
    func attachments(withVendor vendor: String? = nil, conformingTo conformsTo: String? = nil) throws -> [Envelope] {
        try assertions(withPredicate: .attachment).filter { envelope in
            try validateAttachment(envelope)
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
    
    func validateAttachment(_ envelope: Envelope) throws {
        let payload = try envelope.attachmentPayload
        let vendor = try envelope.attachmentVendor
        let conformsTo = try envelope.attachmentConformsTo
        let assertion = Assertion(attachment: payload, vendor: vendor, conformsTo: conformsTo)
        let e = Envelope(assertion)
        guard e.isEquivalent(to: envelope) else {
            throw EnvelopeError.invalidAttachment
        }
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
