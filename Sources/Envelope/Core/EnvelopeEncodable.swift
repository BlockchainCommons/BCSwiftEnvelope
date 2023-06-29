import Foundation

public protocol EnvelopeEncodable {
    var envelope: Envelope { get }
}

public protocol EnvelopeDecodable {
    init(_ envelope: Envelope) throws
    init?(_ envelope: Envelope?) throws
}

extension EnvelopeDecodable {
    init?(_ envelope: Envelope?) throws {
        guard let envelope else {
            return nil
        }
        try self.init(envelope)
    }
}

public protocol EnvelopeCodable: EnvelopeEncodable, EnvelopeDecodable {
}

extension Envelope: EnvelopeEncodable {
    public var envelope: Envelope { self }
}
