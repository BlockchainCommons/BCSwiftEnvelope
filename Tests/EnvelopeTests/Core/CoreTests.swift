import XCTest
import SecureComponents
import Envelope
import WolfBase

let formatContext = FormatContext(
    tags: knownTags,
    functions: knownFunctions,
    parameters: knownParameters
)

class CoreTests: XCTestCase {
    static let basicEnvelope = Envelope("Hello.")
    static let knownValueEnvelope = Envelope(.note)
    static let wrappedEnvelope = Envelope(basicEnvelope)
    static let doubleWrappedEnvelope = Envelope(wrappedEnvelope)
    static let assertionEnvelope = Envelope("knows", "Bob")

    static let singleAssertionEnvelope = Envelope("Alice")
        .addAssertion("knows", "Bob")
    static let doubleAssertionEnvelope = singleAssertionEnvelope
        .addAssertion("knows", "Carol")
    
    func testIntSubject() throws {
        let e = try Envelope(42).checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           24(42)   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digestâ€ , "Digest(7f83f7bda2d63959d34767689f06d47576683d378d9eb8d09386c9a020395c53)")
        
        XCTAssertEqual(e.format(),
        """
        42
        """
        )
        
        XCTAssertEqual(try e.extractSubject(Int.self), 42)
    }
    
    func testNegativeIntSubject() throws {
        let e = try Envelope(-42).checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           24(-42)   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digestâ€ , "Digest(9e0ad272780de7aa1dbdfbc99058bb81152f623d3b95b5dfb0a036badfcc9055)")
        
        XCTAssertEqual(e.format(),
        """
        -42
        """
        )
        
        XCTAssertEqual(try e.extractSubject(Int.self), -42)
    }
    
    func testCBOREncodableSubject() throws {
        let e = try Self.basicEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           24("Hello.")   ; leaf
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(8cc96cdb771176e835114a0f8936690b41cfed0df22d014eedd64edaea945d59)")
        
        XCTAssertEqual(e.format(),
        """
        "Hello."
        """
        )
        
        XCTAssertEqual(try e.extractSubject(String.self), "Hello.")
    }
    
    func testKnownValueSubject() throws {
        let e = try Self.knownValueEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           223(4)   ; known-value
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(499c8a11a42152b721ae9f16dd412bcf5e47ecace3ef20acfd84d96409c382c6)")
        
        XCTAssertEqual(e.format(),
        """
        note
        """)
        
        XCTAssertEqual(try e.extractSubject(KnownValue.self), KnownValue.note)
    }
    
    func testAssertionSubject() throws {
        let e = try Self.assertionEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           221(   ; assertion
              [
                 200(   ; envelope
                    24("knows")   ; leaf
                 ),
                 200(   ; envelope
                    24("Bob")   ; leaf
                 )
              ]
           )
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")
        
        XCTAssertEqual(e.format(),
        """
        "knows": "Bob"
        """)
        
        XCTAssertEqual(e.subject.digest, Envelope("knows", "Bob").digest)
    }
    
    func testSubjectWithAssertion() throws {
        let e = Self.singleAssertionEnvelope
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           [
              200(   ; envelope
                 24("Alice")   ; leaf
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          24("knows")   ; leaf
                       ),
                       200(   ; envelope
                          24("Bob")   ; leaf
                       )
                    ]
                 )
              )
           ]
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(8955db5e016affb133df56c11fe6c5c82fa3036263d651286d134c7e56c0e9f2)")
        
        XCTAssertEqual(e.format(),
        """
        "Alice" [
            "knows": "Bob"
        ]
        """)
        
        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }
    
    func testSubjectWithTwoAssertions() throws {
        let e = Self.doubleAssertionEnvelope
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           [
              200(   ; envelope
                 24("Alice")   ; leaf
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          24("knows")   ; leaf
                       ),
                       200(   ; envelope
                          24("Carol")   ; leaf
                       )
                    ]
                 )
              ),
              200(   ; envelope
                 221(   ; assertion
                    [
                       200(   ; envelope
                          24("knows")   ; leaf
                       ),
                       200(   ; envelope
                          24("Bob")   ; leaf
                       )
                    ]
                 )
              )
           ]
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(b8d857f6e06a836fbc68ca0ce43e55ceb98eefd949119dab344e11c4ba5a0471)")
        
        XCTAssertEqual(e.format(),
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
        ]
        """)
        
        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }
    
    func testWrapped() throws {
        let e = try Self.wrappedEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           224(   ; wrapped-envelope
              24("Hello.")   ; leaf
           )
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(172a5e51431062e7b13525cbceb8ad8475977444cf28423e21c0d1dcbdfcaf47)")
        
        XCTAssertEqual(e.format(),
        """
        {
            "Hello."
        }
        """)
    }
    
    func testDoubleWrapped() throws {
        let e = try Self.doubleWrappedEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           224(   ; wrapped-envelope
              224(   ; wrapped-envelope
                 24("Hello.")   ; leaf
              )
           )
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digestâ€ , "Digest(8b14f3bcd7c05aac8f2162e7047d7ef5d5eab7d82ee3f9dc4846c70bae4d200b)")
        
        XCTAssertEqual(e.format(),
        """
        {
            {
                "Hello."
            }
        }
        """)
    }
    
    func testAssertionWithAssertions() throws {
        let a = try Envelope(1, 2)
            .addAssertion(Envelope(3, 4))
            .addAssertion(Envelope(5, 6))
        let e = try Envelope(7)
            .addAssertion(a)
        XCTAssertEqual(e.format(),
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

    func testDigestLeaf() throws {
        let digest = Self.basicEnvelope.digest
        let e = try Envelope(digest).checkEncoding()

        XCTAssertEqual(e.format(),
        """
        Digest(8cc96cdb)
        """
        )

        XCTAssertEqual(e.digestâ€ , "Digest(54568793aa0038328ac5fbc6f226a59d6f4caf02dfd7753f4d2cbd8e64ab3e94)")

        XCTAssertEqual(e.diagnostic(annotate: true, context: formatContext),
        """
        200(   ; envelope
           24(   ; leaf
              203(   ; crypto-digest
                 h'8cc96cdb771176e835114a0f8936690b41cfed0df22d014eedd64edaea945d59'
              )
           )
        )
        """
        )
    }
}

