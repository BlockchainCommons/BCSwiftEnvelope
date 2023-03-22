import Foundation
import SecureComponents

public extension Envelope {
    /// Returns the compressed variant of this envelope.
    ///
    /// Returns the same envelope if it is already compressed.
    func compress() throws -> Envelope {
        switch self {
        case .compressed:
            return self
        case .encrypted:
            throw EnvelopeError.alreadyEncrypted
        case .elided:
            throw EnvelopeError.alreadyElided
        default:
            return Envelope(compressed: Compressed(uncompressedData: cborData), digest: digest)
        }
    }
    
    /// Returns the uncompressed variant of this envelope.
    ///
    /// Returns the same envelope if it is already uncompressed.
    func uncompress() throws -> Envelope {
        switch self {
        case .compressed(let compressed, let digest):
            let envelope = try Envelope(cborData: compressed.uncompress())
            guard envelope.digest == digest else {
                throw EnvelopeError.invalidDigest
            }
            return envelope
        default:
            return self
        }
    }
}

public extension Envelope {
    /// Returns this envelope with its subject compressed.
    ///
    /// Returns the same envelope if its subject is already compressed.
    func compressSubject() throws -> Envelope {
        guard !subject.isCompressed else {
            return self
        }
        return replaceSubject(with: try subject.compress())
    }
    
    /// Returs this envelope with its subject uncompressed.
    ///
    /// Returns the same envelope if its subject is already uncompressed.
    func uncompressSubject() throws -> Envelope {
        guard subject.isCompressed else {
            return self
        }
        return try replaceSubject(with: subject.uncompress())
    }
}
