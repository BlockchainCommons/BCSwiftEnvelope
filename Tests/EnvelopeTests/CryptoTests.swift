import Testing
import SecureComponents
import Envelope
import WolfBase
import Foundation

struct CryptoTests {
    @Test func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let envelope = try Envelope(plaintextHello).checkEncoding()
        let ur = envelope.ur

//        print(envelope.diagnostic())
//        print(envelope.hex())
//        print(ur)

        let expectedFormat =
        """
        "Hello."
        """
        #expect(envelope.format() == expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope and reads the message.
        let receivedPlaintext = try Envelope(ur: ur)
            .checkEncoding()
            .extractSubject(String.self)
        #expect(receivedPlaintext == plaintextHello)
    }

    @Test func testSignedPlaintext() throws {
        // Alice sends a signed plaintext message to Bob.
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .checkEncoding()
        let ur = envelope.ur

//        print(envelope.diagAnnotated)
//        print(envelope.hex())
//        print(envelope.ur)

        let expectedFormat =
        """
        "Hello." [
            'verifiedBy': Signature
        ]
        """
        #expect(envelope.format() == expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur).checkEncoding()

        // Bob receives the message, validates Alice's signature, and reads the message.
        let receivedPlaintext = try receivedEnvelope.verifySignature(from: alicePublicKeys)
            .extractSubject(String.self)
        #expect(receivedPlaintext == plaintextHello)

        // Confirm that it wasn't signed by Carol.
        #expect(throws: (any Error).self) { try receivedEnvelope.verifySignature(from: carolPublicKeys) }

        // Confirm that it was signed by Alice OR Carol.
        try receivedEnvelope.verifySignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 1)

        // Confirm that it was not signed by Alice AND Carol.
        #expect(throws: (any Error).self) { try receivedEnvelope.verifySignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 2) }
    }

    @Test func testMultisignedPlaintext() throws {
        // Alice and Carol jointly send a signed plaintext message to Bob.
        let envelope = try Envelope(plaintextHello)
            .sign(with: [alicePrivateKeys, carolPrivateKeys])
            .checkEncoding()
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        let expectedFormat =
        """
        "Hello." [
            'verifiedBy': Signature
            'verifiedBy': Signature
        ]
        """
        #expect(envelope.format() == expectedFormat)

        // Alice & Carol ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope and verifies the message was signed by both Alice and Carol.
        let receivedPlaintext = try Envelope(ur: ur)
            .checkEncoding()
            .verifySignatures(from: [alicePublicKeys, carolPublicKeys])
            .extractSubject(String.self)

        // Bob reads the message.
        #expect(receivedPlaintext == plaintextHello)
    }

    @Test func testSymmetricEncryption() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let envelope = try Envelope(plaintextHello).checkEncoding()
            .encryptSubject(with: key).checkEncoding()
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        let expectedFormat =
        """
        ENCRYPTED
        """
        #expect(envelope.format() == expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur).checkEncoding()

        // Bob decrypts and reads the message.
        let receivedPlaintext = try receivedEnvelope
            .decryptSubject(with: key)
            .extractSubject(String.self)
        #expect(receivedPlaintext == plaintextHello)

        // Can't read with no key.
        #expect(throws: (any Error).self) { try receivedEnvelope.extractSubject(String.self) }

        // Can't read with incorrect key.
        #expect(throws: (any Error).self) { try receivedEnvelope.decryptSubject(with: SymmetricKey()) }
    }
    
    func roundTripTest(_ envelope: Envelope) throws {
        let key = SymmetricKey()
        let plaintextSubject = try envelope.checkEncoding()
        let encryptedSubject = try plaintextSubject.encryptSubject(with: key).checkEncoding()
        #expect(plaintextSubject.isEquivalent(to: encryptedSubject))
        let plaintextSubject2 = try encryptedSubject.decryptSubject(with: key).checkEncoding()
        #expect(encryptedSubject.isEquivalent(to: plaintextSubject2))
        #expect(plaintextSubject.isIdentical(to: plaintextSubject2))
    }

    @Test func testEncryptDecrypt() throws {
        // leaf
        let e1 = Envelope(plaintextHello)
        try roundTripTest(e1)

        // node
        let e2 = Envelope("Alice")
            .addAssertion("knows", "Bob")
        try roundTripTest(e2)

        // wrapped
        let e3 = Envelope("Alice")
            .wrap()
        try roundTripTest(e3)

        // known value
        let e4 = Envelope(.isA)
        try roundTripTest(e4)

        // assertion
        let e5 = Envelope("knows", "Bob")
        try roundTripTest(e5)

        // compressed
        let e6 = try Envelope(plaintextHello).compress()
        try roundTripTest(e6)
    }

    @Test func testSignThenEncrypt() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice signs a plaintext message, then encrypts it.
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys).checkEncoding()
            .wrap().checkEncoding()
            .encryptSubject(with: key).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        ENCRYPTED
        """
        #expect(envelope.format() == expectedFormat)

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope, decrypts it using the shared key, and then validates Alice's signature.
        let receivedPlaintext = try Envelope(ur: ur).checkEncoding()
            .decryptSubject(with: key).checkEncoding()
            .unwrap().checkEncoding()
            .verifySignature(from: alicePublicKeys)
            .extractSubject(String.self)
        // Bob reads the message.
        #expect(receivedPlaintext == plaintextHello)
    }

    @Test func testEncryptThenSign() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice encryptes a plaintext message, then signs it.
        //
        // It doesn't actually matter whether the `encrypt` or `sign` method comes first,
        // as the `encrypt` method transforms the `subject` into its `.encrypted` form,
        // which carries a `Digest` of the plaintext `subject`, while the `sign` method
        // only adds an `Assertion` with the signature of the hash as the `object` of the
        // `Assertion`.
        //
        // Similarly, the `decrypt` method used below can come before or after the
        // `verifySignature` method, as `verifySignature` checks the signature against
        // the `subject`'s hash, which is explicitly present when the subject is in
        // `.encrypted` form and can be calculated when the subject is in `.plaintext`
        // form. The `decrypt` method transforms the subject from its `.encrypted` case to
        // its `.plaintext` case, and also checks that the decrypted plaintext has the same
        // hash as the one associated with the `.encrypted` subject.
        //
        // The end result is the same: the `subject` is encrypted and the signature can be
        // checked before or after decryption.
        //
        // The main difference between this order of operations and the sign-then-encrypt
        // order of operations is that with sign-then-encrypt, the decryption *must*
        // be performed first before the presence of signatures can be known or checked.
        // With this order of operations, the presence of signatures is known before
        // decryption, and may be checked before or after decryption.
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: key).checkEncoding()
            .sign(with: alicePrivateKeys).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        ENCRYPTED [
            'verifiedBy': Signature
        ]
        """
        #expect(envelope.format() == expectedFormat)

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the envelope, validates Alice's signature, then decrypts the message.
        let receivedPlaintext = try Envelope(ur: ur).checkEncoding()
            .verifySignature(from: alicePublicKeys)
            .decryptSubject(with: key).checkEncoding()
            .extractSubject(String.self)
        // Bob reads the message.
        #expect(receivedPlaintext == plaintextHello)
    }

    @Test func testMultiRecipient() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: contentKey).checkEncoding()
            .addRecipient(bobPublicKeys, contentKey: contentKey).checkEncoding()
            .addRecipient(carolPublicKeys, contentKey: contentKey).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        ENCRYPTED [
            'hasRecipient': SealedMessage
            'hasRecipient': SealedMessage
        ]
        """
        #expect(envelope.format() == expectedFormat)

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The envelope is received
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts and reads the message
        let bobReceivedPlaintext = try receivedEnvelope
            .decrypt(to: bobPrivateKeys).checkEncoding()
            .extractSubject(String.self)
        #expect(bobReceivedPlaintext == plaintextHello)

        // Alice decrypts and reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .decrypt(to: carolPrivateKeys).checkEncoding()
            .extractSubject(String.self)
        #expect(carolReceivedPlaintext == plaintextHello)

        // Alice didn't encrypt it to herself, so she can't read it.
        #expect(throws: (any Error).self) { try receivedEnvelope.decrypt(to: alicePrivateKeys) }
    }

    @Test func testVisibleSignatureMultiRecipient() throws {
        // Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .encryptSubject(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
        let ur = envelope.ur

        let expectedFormat =
        """
        ENCRYPTED [
            'hasRecipient': SealedMessage
            'hasRecipient': SealedMessage
            'verifiedBy': Signature
        ]
        """
        #expect(envelope.format() == expectedFormat)

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The envelope is received
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob validates Alice's signature, then decrypts and reads the message
        let bobReceivedPlaintext = try receivedEnvelope
            .verifySignature(from: alicePublicKeys)
            .decrypt(to: bobPrivateKeys)
            .extractSubject(String.self)
        #expect(bobReceivedPlaintext == plaintextHello)

        // Carol validates Alice's signature, then decrypts and reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .verifySignature(from: alicePublicKeys)
            .decrypt(to: carolPrivateKeys)
            .extractSubject(String.self)
        #expect(carolReceivedPlaintext == plaintextHello)

        // Alice didn't encrypt it to herself, so she can't read it.
        #expect(throws: (any Error).self) { try receivedEnvelope.decrypt(to: alicePrivateKeys) }
    }

    @Test func testHiddenSignatureMultiRecipient() throws {
        // Alice signs a message, and then encloses it in another envelope before
        // encrypting it so that it can only be decrypted by Bob or Carol. This hides
        // Alice's signature, and requires recipients to decrypt the subject before they
        // are able to validate the signature.
        let contentKey = SymmetricKey()
        let envelope = try Envelope(plaintextHello)
            .sign(with: alicePrivateKeys)
            .wrap()
            .encryptSubject(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey).checkEncoding()
        let ur = envelope.ur

        let expectedFormat =
        """
        ENCRYPTED [
            'hasRecipient': SealedMessage
            'hasRecipient': SealedMessage
        ]
        """
        #expect(envelope.format() == expectedFormat)

//        print(envelope.taggedCBOR.diagnostic())
//        print(envelope.taggedCBOR.hex())
//        print(envelope.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The envelope is received
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts the envelope, then extracts the inner envelope and validates
        // Alice's signature, then reads the message
        let bobReceivedPlaintext = try receivedEnvelope
            .decrypt(to: bobPrivateKeys)
            .unwrap().checkEncoding()
            .verifySignature(from: alicePublicKeys)
            .extractSubject(String.self)
        #expect(bobReceivedPlaintext == plaintextHello)

        // Carol decrypts the envelope, then extracts the inner envelope and validates
        // Alice's signature, then reads the message
        let carolReceivedPlaintext = try receivedEnvelope
            .decrypt(to: carolPrivateKeys)
            .unwrap().checkEncoding()
            .verifySignature(from: alicePublicKeys)
            .extractSubject(String.self)
        #expect(carolReceivedPlaintext == plaintextHello)

        // Alice didn't encrypt it to herself, so she can't read it.
        #expect(throws: (any Error).self) { try receivedEnvelope.decrypt(to: alicePrivateKeys) }
    }

    @Test func testSSKR() throws {
        // Dan has a cryptographic seed he wants to backup using a social recovery scheme.
        // The seed includes metadata he wants to back up also, making it too large to fit
        // into a basic SSKR share.
        var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        danSeed.name = "Dark Purple Aqua Love"
        danSeed.creationDate = try! Date(iso8601: "2021-02-24")
        danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

        // Dan encrypts the seed and then splits the content key into a single group
        // 2-of-3. This returns an array of arrays of Envelope, the outer arrays
        // representing SSKR groups and the inner array elements each holding the encrypted
        // seed and a single share.
        let contentKey = SymmetricKey()
        let seedEnvelope = danSeed.envelope
//        print(seedEnvelope.format())

        let encryptedSeedEnvelope = try seedEnvelope
            .wrap()
            .encryptSubject(with: contentKey)
        
//        print(encryptedSeedEnvelope.format())

        let envelopes = encryptedSeedEnvelope
            .split(groupThreshold: 1, groups: [(2, 3)], contentKey: contentKey)

        // Flattening the array of arrays gives just a single array of all the envelopes
        // to be distributed.
        let sentEnvelopes = envelopes.flatMap { $0 }
        let sentURs = sentEnvelopes.map { $0.ur }

        let expectedFormat =
        """
        ENCRYPTED [
            'sskrShare': SSKRShare
        ]
        """
        #expect(sentEnvelopes[0].format() == expectedFormat)

        // Dan sends one envelope to each of Alice, Bob, and Carol.

//        print(sentEnvelopes[0].format())
//        print(sentEnvelopes[0].taggedCBOR.diagnostic())
//        print(sentEnvelopes[0].taggedCBOR.hex())
//        print(sentEnvelopes[0].ur)

        // Dan ➡️ ☁️ ➡️ Alice
        // Dan ➡️ ☁️ ➡️ Bob
        // Dan ➡️ ☁️ ➡️ Carol

        // let aliceEnvelope = try Envelope(ur: sentURs[0]) // UNRECOVERED
        let bobEnvelope = try Envelope(ur: sentURs[1])
        let carolEnvelope = try Envelope(ur: sentURs[2])

        // At some future point, Dan retrieves two of the three envelopes so he can recover his seed.
        let recoveredEnvelopes = [bobEnvelope, carolEnvelope]
        let recoveredSeedEnvelope = try Envelope(shares: recoveredEnvelopes).unwrap()
//        print(recoveredSeedEnvelope.format())

        let recoveredSeed = try Seed(recoveredSeedEnvelope)

        // The recovered seed is correct.
        #expect(danSeed.data == recoveredSeed.data)
        #expect(danSeed.creationDate == recoveredSeed.creationDate)
        #expect(danSeed.name == recoveredSeed.name)
        #expect(danSeed.note == recoveredSeed.note)

        // Attempting to recover with only one of the envelopes won't work.
        #expect(throws: (any Error).self) { try Envelope(shares: [bobEnvelope]) }
    }
}
