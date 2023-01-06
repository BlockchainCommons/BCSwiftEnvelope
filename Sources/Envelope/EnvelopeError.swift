import Foundation

public extension Envelope {
    /// The type of error thrown by the Envelope package.
    ///
    /// This is an extensible enumerated type. Parts of the Envelope package that throw
    /// their own specific errors define them close to where they are thrown.
    struct EnvelopeError: LocalizedError {
        public let type: String
        
        init(_ type: String) {
            self.type = type
        }
        
        var localizedString: String {
            type
        }
    }
}

/// Common errors thrown many places in the package.

extension Envelope.EnvelopeError {
    static let invalidDigest = Envelope.EnvelopeError("invalidDigest")
    static let invalidFormat = Envelope.EnvelopeError("invalidFormat")
}
