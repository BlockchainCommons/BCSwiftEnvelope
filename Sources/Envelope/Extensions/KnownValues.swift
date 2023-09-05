import Foundation

// For definitions see: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2023-002-known-value.md#appendix-a-registry
public extension KnownValue {
    static let isA = KnownValue(1, "isA")
    static let id = KnownValue(2, "id")
    static let verifiedBy = KnownValue(3, "verifiedBy")
    static let note = KnownValue(4, "note")
    static let hasRecipient = KnownValue(5, "hasRecipient")
    static let sskrShare = KnownValue(6, "sskrShare")
    static let controller = KnownValue(7, "controller")
    static let publicKeys = KnownValue(8, "publicKeys")
    static let dereferenceVia = KnownValue(9, "dereferenceVia")
    static let entity = KnownValue(10, "entity")
    static let hasName = KnownValue(11, "hasName")
    static let language = KnownValue(12, "language")
    static let issuer = KnownValue(13, "issuer")
    static let holder = KnownValue(14, "holder")
    static let salt = KnownValue(15, "salt")
    static let date = KnownValue(16, "date")
    static let unknown = KnownValue(17, "Unknown")
    static let diffEdits = KnownValue(20, "edits")
    static let attachment = KnownValue(50, "attachment")
    static let vendor = KnownValue(51, "vendor")
    static let conformsTo = KnownValue(52, "conformsTo")
    static let body = KnownValue(100, "body")
    static let result = KnownValue(101, "result")
    static let error = KnownValue(102, "error")
    static let OK = KnownValue(103, "OK")
    static let Processing = KnownValue(104, "Processing")
    static let Seed = KnownValue(200, "Seed")
    static let PrivateKey = KnownValue(201, "PrivateKey")
    static let PublicKey = KnownValue(202, "PublicKey")
    static let MasterKey = KnownValue(203, "MasterKey")
    static let asset = KnownValue(300, "asset")
    static let Bitcoin = KnownValue(301, "BTC")
    static let Ethereum = KnownValue(302, "ETH")
    static let network = KnownValue(400, "network")
    static let MainNet = KnownValue(401, "MainNet")
    static let TestNet = KnownValue(402, "TestNet")
    static let BIP32Key = KnownValue(500, "BIP32Key")
    static let chainCode = KnownValue(501, "chainCode")
    static let DerivationPath = KnownValue(502, "DerivationPath")
    static let parentPath = KnownValue(503, "parent")
    static let childrenPath = KnownValue(504, "children")
    static let parentFingerprint = KnownValue(505, "parentFingerprint")
    static let PSBT = KnownValue(506, "PSBT")
    static let OutputDescriptor = KnownValue(507, "OutputDescriptor")
    static let outputDescriptor = KnownValue(508, "outputDescriptor")
}

public var globalKnownValues: KnownValuesStore = [
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
    .attachment,
    .vendor,
    .conformsTo,
    .body,
    .result,
    .error,
    .OK,
    .Processing,
    .Seed,
    .PrivateKey,
    .PublicKey,
    .MasterKey,
    .asset,
    .Bitcoin,
    .Ethereum,
    .network,
    .MainNet,
    .TestNet,
    .BIP32Key,
    .chainCode,
    .DerivationPath,
    .parentPath,
    .childrenPath,
    .parentFingerprint,
    .PSBT,
    .OutputDescriptor,
    .outputDescriptor,
]
