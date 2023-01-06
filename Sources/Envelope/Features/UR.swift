import Foundation
import SecureComponents

public extension Envelope {
    /// Returns the encoding of the envelope as a `UR`.
    var ur: UR {
        return try! UR(type: .envelope, cbor: untaggedCBOR)
    }
    
    /// Returns the encoding of the envelope as a `String`-encoded `UR`.
    ///
    /// The `UR` will have the schema `ur:envelope`.
    var urString: String {
        ur.string
    }

    /// Creates a new envelope by decoding the given `UR`.
    ///
    /// - Parameter ur: The `UR` to decode.
    ///
    /// - Throws: Throws an exception if the UR type is not `envelope` or the CBOR it contains is not a well-formed `Envelope`.
    init(ur: UR) throws {
        try ur.checkType(.envelope)
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }

    /// Creates a new envelope by decoding the given `String`-encoded `UR`.
    ///
    /// The given `String` must have the schema `ur:envelope`.
    ///
    /// - Throws: Throws an exception if the UR of envelope it contains is not well-formed.
    init(urString: String) throws {
        try self.init(ur: UR(urString: urString))
    }
}
