import Foundation

public extension Envelope.KnownValue {
    /// Predicate declaring the subject is known by the identifier object.
    static let id = Envelope.KnownValue(1, "id")
    
    /// Predicate declaring the subject is of a type identified by the object.
    static let isA = Envelope.KnownValue(2, "isA")
    
    /// Predicate declaring the subject is signed by the `Signature` object.
    static let verifiedBy = Envelope.KnownValue(3, "verifiedBy")
    
    /// Predicate declaring the subject is accompanied by a human-readable note object.
    static let note = Envelope.KnownValue(4, "note")
    
    /// Predicate declaring the subject can be decrypted by the ephemeral key contained
    /// in the `SealedMessage` object.
    static let hasRecipient = Envelope.KnownValue(5, "hasRecipient")
    
    /// Predicate declaring the subject can be decryped by a quorum of `SSKRShare`s
    /// including the one in the object.
    static let sskrShare = Envelope.KnownValue(6, "sskrShare")
    
    /// Predicate declaring that the document is controlled by the party identified by
    /// the object.
    static let controller = Envelope.KnownValue(7, "controller")
    
    /// Predicate declaring that the party identified by the subject holds the private keys
    /// to the `PublicKeyBase` object.
    static let publicKeys = Envelope.KnownValue(8, "publicKeys")
    
    /// Predicate declaring that the content referenced by the subject can be
    /// dereferenced using the information in the object.
    static let dereferenceVia = Envelope.KnownValue(9, "dereferenceVia")
    
    /// Predicate declaring that the entity referenced by the subject is specified in
    /// the object.
    static let entity = Envelope.KnownValue(10, "entity")
    
    /// Predicate declaring that the entity referenced by the subject is known by the
    /// name in the object.
    static let hasName = Envelope.KnownValue(11, "hasName")
    
    /// Predicate declaring the the subject `String` is written in the language of the
    /// ISO language code object.
    static let language = Envelope.KnownValue(12, "language")
    
    /// Predicate declaring that the issuer of the object referenced in the subject is
    /// the entity referenced in the object.
    static let issuer = Envelope.KnownValue(13, "issuer")
    
    /// Predicate declaring that the holder of the credential or certificate referenced
    /// in the subject is the entity referenced in the object.
    static let holder = Envelope.KnownValue(14, "holder")
    
    /// Predicate declaring that the object is random salt used to decorrelate the
    /// digest of the subject.
    static let salt = Envelope.KnownValue(15, "salt")
    
    /// Predicate declaring a primary datestamp on the envelope.
    static let date = Envelope.KnownValue(16, "date")
    
    
    /// Predicate declaring that the object is a set of edits using by the
    /// `Envelope.transform(edits:)` method to transform a `source` envelope into a `target`
    /// envelope.
    static let diffEdits = Envelope.KnownValue(20, "edits")

    
    /// Predicate declaring that the object is the body (parameters of) a distributed
    /// request identified by the subject.
    static let body = Envelope.KnownValue(100, "body")
    
    /// Predicate declaring that the object is the success result of the request
    /// identified by the subject.
    static let result = Envelope.KnownValue(101, "result")
    
    /// Predicate declaring that the object is the failure result of the request
    /// identified by the subject.
    static let error = Envelope.KnownValue(102, "error")
    
    /// Object providing the success result of a request that has no other return value.
    static let ok = Envelope.KnownValue(103, "ok")
    
    /// Object providing the "in processing" result of a request.
    static let processing = Envelope.KnownValue(104, "processing")
}

var knownValueRegistry: [Envelope.KnownValue] = [
    // General-purpose
    .id,
    .isA,
    .verifiedBy,
    .note,
    .hasRecipient,
    .sskrShare,
    .controller,
    .publicKeys,
    .dereferenceVia,
    .entity,
    .hasName,
    .language,
    .issuer,
    .holder,
    .salt,
    .date,

    // Used by diffing
    .diffEdits,

    // Used by expressions/distributed calls
    .body,
    .result,
    .error,
    .ok,
    .processing,
]
