import Testing
import SecureComponents
import Envelope
import WolfBase

struct ObscuringTests {
    /// This tests the transformation of different kinds of "obscured" envelopes into
    /// others. Some transformations are allowed, some are idempotent (return the same
    /// result), and some throw errors.
    ///
    /// | Operation > | Encrypt | Elide      | Compress   |
    /// |:------------|:--------|:-----------|:-----------|
    /// | Encrypted   | ERROR   | OK         | ERROR      |
    /// | Elided      | ERROR   | IDEMPOTENT | ERROR      |
    /// | Compressed  | OK      | OK         | IDEMPOTENT |
    ///
    @Test func testObscuring() throws {
        let key = SymmetricKey()
        
        let envelope = Envelope(plaintextHello)
        #expect(!envelope.isObscured)
        
        let encrypted = try envelope.encryptSubject(with: key)
        #expect(encrypted.isObscured)

        let elided = envelope.elide()
        #expect(elided.isObscured)

        let compressed = try envelope.compress()
        #expect(compressed.isObscured)

        
        // ENCRYPTION
        
        // Cannot encrypt an encrypted envelope.
        //
        // If allowed, would result in an envelope with the same digest but
        // double-encrypted, possibly with a different key, which is probably not what's
        // intended. If you want to double-encrypt then wrap the encrypted envelope first,
        // which will change its digest.
        #expect(throws: (any Error).self) { try encrypted.encryptSubject(with: key) }
        
        // Cannot encrypt an elided envelope.
        //
        // Elided envelopes have no data to encrypt.
        #expect(throws: (any Error).self) { try elided.encryptSubject(with: key) }
        
        // OK to encrypt a compressed envelope.
        guard case .encrypted = try compressed.encryptSubject(with: key) else {
            Issue.record()
            return
        }
        
        
        // ELISION
        
        // OK to elide an encrypted envelope.
        guard case .elided = encrypted.elide() else {
            Issue.record()
            return
        }
        
        // Eliding an elided envelope is idempotent.
        guard case .elided = elided.elide() else {
            Issue.record()
            return
        }
        
        // OK to elide a compressed envelope.
        guard case .elided = compressed.elide() else {
            Issue.record()
            return
        }
        
        
        // COMPRESSION
        
        // Cannot compress an encrypted envelope.
        //
        // Encrypted envelopes cannot become smaller because encrypted data looks random,
        // and random data is not compressible.
        #expect(throws: (any Error).self) { try encrypted.compress() }
        
        // Cannot compress an elided envelope.
        //
        // Elided envelopes have no data to compress.
        #expect(throws: (any Error).self) { try elided.compress() }
        
        // Compressing a compressed envelope is idempotent.
        guard case .compressed = try compressed.compress() else {
            Issue.record()
            return
        }
    }
}
