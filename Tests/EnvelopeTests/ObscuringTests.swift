import XCTest
import SecureComponents
import Envelope
import WolfBase

class ObscuringTests: XCTestCase {
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
    func testObscuring() throws {
        let key = SymmetricKey()
        
        let envelope = Envelope(plaintextHello)
        XCTAssertFalse(envelope.isObscured)
        
        let encrypted = try envelope.encryptSubject(with: key)
        XCTAssertTrue(encrypted.isObscured)

        let elided = envelope.elide()
        XCTAssertTrue(elided.isObscured)

        let compressed = try envelope.compress()
        XCTAssertTrue(compressed.isObscured)

        
        // ENCRYPTION
        
        // Cannot encrypt an encrypted envelope.
        //
        // If allowed, would result in an envelope with the same digest but
        // double-encrypted, possibly with a different key, which is probably not what's
        // intended. If you want to double-encrypt then wrap the encrypted envelope first,
        // which will change its digest.
        XCTAssertThrowsError(try encrypted.encryptSubject(with: key))
        
        // Cannot encrypt an elided envelope.
        //
        // Elided envelopes have no data to encrypt.
        XCTAssertThrowsError(try elided.encryptSubject(with: key))
        
        // OK to encrypt a compressed envelope.
        guard case .encrypted = try compressed.encryptSubject(with: key) else {
            XCTFail()
            return
        }
        
        
        // ELISION
        
        // OK to elide an encrypted envelope.
        guard case .elided = encrypted.elide() else {
            XCTFail()
            return
        }
        
        // Eliding an elided envelope is idempotent.
        guard case .elided = elided.elide() else {
            XCTFail()
            return
        }
        
        // OK to elide a compressed envelope.
        guard case .elided = compressed.elide() else {
            XCTFail()
            return
        }
        
        
        // COMPRESSION
        
        // Cannot compress an encrypted envelope.
        //
        // Encrypted envelopes cannot become smaller because encrypted data looks random,
        // and random data is not compressible.
        XCTAssertThrowsError(try encrypted.compress())
        
        // Cannot compress an elided envelope.
        //
        // Elided envelopes have no data to compress.
        XCTAssertThrowsError(try elided.compress())
        
        // Compressing a compressed envelope is idempotent.
        guard case .compressed = try compressed.compress() else {
            XCTFail()
            return
        }
    }
}
