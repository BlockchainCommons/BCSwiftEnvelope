import Foundation
import SecureComponents

extension KnownValue: DigestProvider {
    public var digest: Digest {
        Digest(taggedCBOR.cborData)
    }
}

extension KnownValue: EnvelopeEncodable {
    public var envelope: Envelope {
        Envelope(self)
    }
}
