import Foundation

public protocol EnvelopeEncodable {
    var envelope: Envelope { get }
}

public protocol EnvelopeDecodable {
    init(_ envelope: Envelope) throws
    init?(_ envelope: Envelope?) throws
}

public extension EnvelopeDecodable {
    init?(_ envelope: Envelope?) throws {
        guard let envelope else {
            return nil
        }
        try self.init(envelope)
    }
}

public protocol EnvelopeCodable: EnvelopeEncodable & EnvelopeDecodable {
}

extension Envelope: EnvelopeEncodable {
    public var envelope: Envelope { self }
}

extension Bool: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Data: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Date: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Int: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Int8: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Int16: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Int32: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension Int64: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension String: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension UInt: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension UInt8: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension UInt16: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension UInt32: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

extension UInt64: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(_ envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}
