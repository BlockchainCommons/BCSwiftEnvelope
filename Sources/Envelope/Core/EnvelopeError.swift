import Foundation

/// The type of error thrown by the Envelope package.
///
/// This is an extensible enumerated type. Parts of the Envelope package that throw
/// their own specific errors define them close to where they are thrown.
public struct EnvelopeError: Error {
    public let type: String
    
    init(_ type: String) {
        self.type = type
    }
}

extension EnvelopeError: CustomStringConvertible {
    public var description: String {
        type
    }
}

/// Common errors thrown many places in the package.

extension EnvelopeError {
    static let invalidDigest = EnvelopeError("invalidDigest")
    static let invalidFormat = EnvelopeError("invalidFormat")
    static let missingDigest = EnvelopeError("missingDigest")
}
