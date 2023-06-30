import Foundation

public extension KnownValue {
    /// GENERAL
    
    /// Predicate declaring the subject is of a type identified by the object.
    static let isA = KnownValue(1, "isA")

    /// Predicate declaring the subject is known by the identifier object.
    static let id = KnownValue(2, "id")
    
    /// Predicate declaring the subject is signed by the `Signature` object.
    static let verifiedBy = KnownValue(3, "verifiedBy")
    
    /// Predicate declaring the subject is accompanied by a human-readable note object.
    static let note = KnownValue(4, "note")
    
    /// Predicate declaring the subject can be decrypted by the ephemeral key contained
    /// in the `SealedMessage` object.
    static let hasRecipient = KnownValue(5, "hasRecipient")
    
    /// Predicate declaring the subject can be decryped by a quorum of `SSKRShare`s
    /// including the one in the object.
    static let sskrShare = KnownValue(6, "sskrShare")
    
    /// Predicate declaring that the document is controlled by the party identified by
    /// the object.
    static let controller = KnownValue(7, "controller")
    
    /// Predicate declaring that the party identified by the subject holds the private keys
    /// to the `PublicKeyBase` object.
    static let publicKeys = KnownValue(8, "publicKeys")
    
    /// Predicate declaring that the content referenced by the subject can be
    /// dereferenced using the information in the object.
    static let dereferenceVia = KnownValue(9, "dereferenceVia")
    
    /// Predicate declaring that the entity referenced by the subject is specified in
    /// the object.
    static let entity = KnownValue(10, "entity")
    
    /// Predicate declaring that the entity referenced by the subject is known by the
    /// name in the object.
    static let hasName = KnownValue(11, "hasName")
    
    /// Predicate declaring the the subject `String` is written in the language of the
    /// ISO language code object.
    static let language = KnownValue(12, "language")
    
    /// Predicate declaring that the issuer of the object referenced in the subject is
    /// the entity referenced in the object.
    static let issuer = KnownValue(13, "issuer")
    
    /// Predicate declaring that the holder of the credential or certificate referenced
    /// in the subject is the entity referenced in the object.
    static let holder = KnownValue(14, "holder")
    
    /// Predicate declaring that the object is random salt used to decorrelate the
    /// digest of the subject.
    static let salt = KnownValue(15, "salt")
    
    /// Predicate declaring a primary datestamp on the envelope.
    static let date = KnownValue(16, "date")
    
    /// An unknown value
    static let unknown = KnownValue(17, "unknown")
    
    /// Predicate declaring that the object is a set of edits using by the
    /// `Envelope.transform(edits:)` method to transform a `source` envelope into a `target`
    /// envelope.
    static let diffEdits = KnownValue(20, "edits")

    
    /// EXPRESSIONS AND FUNCTION CALLING

    /// Predicate declaring that the object is the body (parameters of) a distributed
    /// request identified by the subject.
    static let body = KnownValue(100, "body")
    
    /// Predicate declaring that the object is the success result of the request
    /// identified by the subject.
    static let result = KnownValue(101, "result")
    
    /// Predicate declaring that the object is the failure result of the request
    /// identified by the subject.
    static let error = KnownValue(102, "error")
    
    /// Object providing the success result of a request that has no other return value.
    static let ok = KnownValue(103, "ok")
    
    /// Object providing the "in processing" result of a request.
    static let processing = KnownValue(104, "processing")
    
    
    /// CRYPTOGRAPHY

    /// A cryptographic seed
    static let seed = KnownValue(200, "seed")
    
    /// A private key
    static let privateKey = KnownValue(201, "privateKey")
    
    /// A public key
    static let publicKey = KnownValue(202, "publicKey")
    
    /// A master key
    static let masterKey = KnownValue(203, "masterKey")

    
    /// CRYPTOCURRENCY ASSETS

    /// A cryptocurrency asset specifier, e.g. "btc", "eth"
    static let asset = KnownValue(300, "asset")
    
    /// The Bitcoin cryptocurrency ("btc")
    static let bitcoin = KnownValue(301, "btc")
    
    /// The Ethereum cryptocurrency ("eth")
    static let ethereum = KnownValue(302, "eth")
    

    /// ONLINE NETWORKS
    
    /// A network, e.g. "main", "test"
    static let network = KnownValue(400, "network")
    
    /// A main network
    static let mainNet = KnownValue(401, "mainNet")
    
    /// A test network
    static let testNet = KnownValue(402, "testNet")
    
    
    /// BITCOIN

    /// A BIP-32 HD key
    static let bip32key = KnownValue(500, "bip32key")
    
    /// Chain code for a BIP-32 key
    static let chainCode = KnownValue(501, "chainCode")
    
    /// Derivation path for a BIP-32 key
    static let derivationPath = KnownValue(502, "derivationPath")
    
    /// Derivation path for this key
    static let parentPath = KnownValue(503, "parent")
    
    /// Allowable derivation paths from this key
    static let childrenPath = KnownValue(504, "children")
    
    /// Parent fingerprint for a BIP-32 key
    static let parentFingerprint = KnownValue(505, "parentFingerprint")

    /// A Partially-Signed Bitcoin Transaction (PSBT)
    static let psbt = KnownValue(506, "psbt")

    /// An Output Descriptor
    static let outputDescriptor = KnownValue(507, "outputDescriptor")
}

public var globalKnownValues: KnownValuesStore = [
    /// GENERAL

    .isA,
    .id,
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
    .unknown,
    .diffEdits,

    /// EXPRESSIONS AND FUNCTION CALLING
    .body,
    .result,
    .error,
    .ok,
    .processing,

    /// CRYPTOGRAPHY
    .seed,
    .privateKey,
    .publicKey,
    .masterKey,

    /// CRYPTOCURRENCY ASSETS
    .asset,
    .bitcoin,
    .ethereum,

    /// ONLINE NETWORKS
    .network,
    .mainNet,
    .testNet,
    
    /// BITCOIN
    .bip32key,
    .chainCode,
    .derivationPath,
    .parentPath,
    .childrenPath,
    .parentFingerprint,
    .psbt,
    .outputDescriptor,
]
