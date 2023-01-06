import Foundation

extension Envelope.Error {
    static let notWrapped = Envelope.Error("notWrapped")
}

public extension Envelope {
    /// Return a new envelope which wraps the current envelope.
    func wrap() -> Envelope {
        Envelope(self)
    }

    /// Unwraps and returns the inner envelope.
    ///
    /// Throws an exception if this is not a wrapped envelope.
    func unwrap() throws -> Envelope {
        guard case .wrapped(let envelope, _) = subject else {
            throw Error.notWrapped
        }
        return envelope
    }
}
