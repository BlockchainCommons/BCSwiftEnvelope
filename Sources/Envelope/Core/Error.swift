import Foundation

public extension Envelope {
    /// The type of error thrown by the Envelope package.
    ///
    /// This is an extensible enumerated type. Parts of the Envelope package that throw
    /// their own specific errors define them close to where they are thrown.
    struct Error: LocalizedError {
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

extension Envelope.Error {
    static let invalidDigest = Envelope.Error("invalidDigest")
    static let invalidFormat = Envelope.Error("invalidFormat")
    static let missingDigest = Envelope.Error("missingDigest")
}
