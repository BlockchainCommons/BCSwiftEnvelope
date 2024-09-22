import Testing
import SecureComponents
import Envelope
import WolfBase

struct CoreTests {
    static let basicEnvelope = Envelope("Hello.")
    static let knownValueEnvelope = Envelope(.note)
    static let wrappedEnvelope = basicEnvelope.wrap()
    static let doubleWrappedEnvelope = wrappedEnvelope.wrap()
    static let assertionEnvelope = Envelope("knows", "Bob")

    init() async {
        await addKnownTags()
    }

    static let singleAssertionEnvelope = Envelope("Alice")
        .addAssertion("knows", "Bob")
    static let doubleAssertionEnvelope = singleAssertionEnvelope
        .addAssertion("knows", "Carol")

    // A previous version of the Envelope spec used tag #6.24 ("Encoded CBOR Item") as
    // the header for the Envelope `leaf` case. Unfortunately, this was not a correct
    // use of the tag, as the contents of #6.24 (RFC8949 §3.4.5.1) MUST always be a
    // byte string, while we were simply using it as a wrapper/header for any dCBOR
    // data item.
    //
    // https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
    //
    // This test ensures that Envelopes encoded with the old tag are still
    // correctly decoded as `leaf` cases.
    @Test func testReadLegacyLeaf() throws {
        let legacyEnvelope = try Envelope(taggedCBORData: ‡"d8c8d818182a")
        let envelope = Envelope(42)
        #expect(envelope.isEquivalent(to: legacyEnvelope))
        #expect(envelope.isIdentical(to: legacyEnvelope))
    }

    @Test func testIntSubject() throws {
        let e = try Envelope(42).checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           201(42)   / leaf /
        )
        """)
        
        #expect(e.digest† == "Digest(7f83f7bda2d63959d34767689f06d47576683d378d9eb8d09386c9a020395c53)")
        
        #expect(e.format() ==
        """
        42
        """
        )
        
        #expect(try e.extractSubject(Int.self) == 42)
    }
    
    @Test func testNegativeIntSubject() throws {
        let e = try Envelope(-42).checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           201(-42)   / leaf /
        )
        """)
        
        #expect(e.digest† == "Digest(9e0ad272780de7aa1dbdfbc99058bb81152f623d3b95b5dfb0a036badfcc9055)")
        
        #expect(e.format() ==
        """
        -42
        """
        )
        
        #expect(try e.extractSubject(Int.self) == -42)
    }
    
    @Test func testCBOREncodableSubject() throws {
        let e = try Self.basicEnvelope.checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           201("Hello.")   / leaf /
        )
        """)
        
        #expect(e.digest† == "Digest(8cc96cdb771176e835114a0f8936690b41cfed0df22d014eedd64edaea945d59)")
        
        #expect(e.format() ==
        """
        "Hello."
        """
        )
        
        #expect(try e.extractSubject(String.self) == "Hello.")
    }
    
    @Test func testKnownValueSubject() throws {
        let e = try Self.knownValueEnvelope.checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(4)   / envelope /
        """)
        
        try e.checkEncoding()
        
        #expect(e.digest† == "Digest(0fcd6a39d6ed37f2e2efa6a96214596f1b28a5cd42a5a27afc32162aaf821191)")
        
        #expect(e.format() ==
        """
        'note'
        """)
        
        #expect(try e.extractSubject(KnownValue.self) == KnownValue.note)
    }
    
    @Test func testAssertionSubject() throws {
        let e = try Self.assertionEnvelope.checkEncoding()
        
        #expect(e.predicate.digest† == "Digest(db7dd21c5169b4848d2a1bcb0a651c9617cdd90bae29156baaefbb2a8abef5ba)")
        #expect(e.object.digest† == "Digest(13b741949c37b8e09cc3daa3194c58e4fd6b2f14d4b1d0f035a46d6d5a1d3f11)")
        #expect(e.subject.digest† == "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")
        #expect(e.digest† == "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")

        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           {
              201("knows"):   / leaf /
              201("Bob")   / leaf /
           }
        )
        """)
        
        #expect(e.digest† == "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")
        
        #expect(e.format() ==
        """
        "knows": "Bob"
        """)
        
        #expect(e.subject.digest == Envelope("knows", "Bob").digest)
    }
    
    @Test func testSubjectWithAssertion() throws {
        let e = try Self.singleAssertionEnvelope.checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           [
              201("Alice"),   / leaf /
              {
                 201("knows"):   / leaf /
                 201("Bob")   / leaf /
              }
           ]
        )
        """)
        
        #expect(e.digest† == "Digest(8955db5e016affb133df56c11fe6c5c82fa3036263d651286d134c7e56c0e9f2)")
        
        #expect(e.format() ==
        """
        "Alice" [
            "knows": "Bob"
        ]
        """)
        
        #expect(try e.extractSubject(String.self) == "Alice")
    }
    
    @Test func testSubjectWithTwoAssertions() throws {
        let e = try Self.doubleAssertionEnvelope.checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           [
              201("Alice"),   / leaf /
              {
                 201("knows"):   / leaf /
                 201("Carol")   / leaf /
              },
              {
                 201("knows"):   / leaf /
                 201("Bob")   / leaf /
              }
           ]
        )
        """)
        
        #expect(e.digest† == "Digest(b8d857f6e06a836fbc68ca0ce43e55ceb98eefd949119dab344e11c4ba5a0471)")
        
        #expect(e.format() ==
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """)
        
        #expect(try e.extractSubject(String.self) == "Alice")
    }
    
    @Test func testWrapped() throws {
        #expect(Self.wrappedEnvelope.diagnostic() ==
        """
        200(   / envelope /
           200(   / envelope /
              201("Hello.")   / leaf /
           )
        )
        """
        )
        
        #expect(Self.wrappedEnvelope.digest† == "Digest(172a5e51431062e7b13525cbceb8ad8475977444cf28423e21c0d1dcbdfcaf47)")
        
        #expect(Self.wrappedEnvelope.format() ==
        """
        {
            "Hello."
        }
        """)
        
        try Self.wrappedEnvelope.checkEncoding()
    }
    
    @Test func testDoubleWrapped() throws {
        let e = try Self.doubleWrappedEnvelope.checkEncoding()
        
        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           200(   / envelope /
              200(   / envelope /
                 201("Hello.")   / leaf /
              )
           )
        )
        """
        )
        
        #expect(e.digest† == "Digest(8b14f3bcd7c05aac8f2162e7047d7ef5d5eab7d82ee3f9dc4846c70bae4d200b)")
        
        #expect(e.format() ==
        """
        {
            {
                "Hello."
            }
        }
        """)
    }
    
    @Test func testAssertionWithAssertions() throws {
        let a = try Envelope(1, 2)
            .addAssertion(Envelope(3, 4))
            .addAssertion(Envelope(5, 6))
        let e = try Envelope(7)
            .addAssertion(a)
        #expect(e.format() ==
        """
        7 [
            {
                1: 2
            } [
                3: 4
                5: 6
            ]
        ]
        """)
    }

    @Test func testDigestLeaf() throws {
        let digest = Self.basicEnvelope.digest
        let e = try Envelope(digest).checkEncoding()

        #expect(e.format() ==
        """
        Digest(8cc96cdb)
        """
        )

        #expect(e.digest† == "Digest(07b518af92a6196bc153752aabefedb34ff8e1a7d820c01ef978dfc3e7e52e05)")

        #expect(e.diagnostic() ==
        """
        200(   / envelope /
           201(   / leaf /
              40001(   / digest /
                 h'8cc96cdb771176e835114a0f8936690b41cfed0df22d014eedd64edaea945d59'
              )
           )
        )
        """
        )
    }
}
