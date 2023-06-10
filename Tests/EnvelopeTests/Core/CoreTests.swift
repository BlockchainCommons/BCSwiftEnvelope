import XCTest
import SecureComponents
import Envelope
import WolfBase

let globalFormatContext = FormatContext(
    tags: globalTags,
    knownValues: globalKnownValues,
    functions: globalFunctions,
    parameters: globalParameters
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
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           24(42)   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(7f83f7bda2d63959d34767689f06d47576683d378d9eb8d09386c9a020395c53)")
        
        XCTAssertEqual(e.format(),
        """
        42
        """
        )
        
        XCTAssertEqual(try e.extractSubject(Int.self), 42)
    }
    
    func testNegativeIntSubject() throws {
        let e = try Envelope(-42).checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           24(-42)   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(9e0ad272780de7aa1dbdfbc99058bb81152f623d3b95b5dfb0a036badfcc9055)")
        
        XCTAssertEqual(e.format(),
        """
        -42
        """
        )
        
        XCTAssertEqual(try e.extractSubject(Int.self), -42)
    }
    
    func testCBOREncodableSubject() throws {
        let e = try Self.basicEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           24("Hello.")   ; leaf
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(8cc96cdb771176e835114a0f8936690b41cfed0df22d014eedd64edaea945d59)")
        
        XCTAssertEqual(e.format(),
        """
        "Hello."
        """
        )
        
        XCTAssertEqual(try e.extractSubject(String.self), "Hello.")
    }
    
    func testKnownValueSubject() throws {
        let e = try Self.knownValueEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           202(4)   ; known-value
        )
        """)
        
        try e.checkEncoding()
        
        XCTAssertEqual(e.digest†, "Digest(49a5f41b242e76fa4ed7083f4fb3b9cab117f3437b38083b7375d6f19f199508)")
        
        XCTAssertEqual(e.format(),
        """
        note
        """)
        
        XCTAssertEqual(try e.extractSubject(KnownValue.self), KnownValue.note)
    }
    
    func testAssertionSubject() throws {
        let e = try Self.assertionEnvelope.checkEncoding()
        
        XCTAssertEqual(e.predicate.digest†, "Digest(db7dd21c5169b4848d2a1bcb0a651c9617cdd90bae29156baaefbb2a8abef5ba)")
        XCTAssertEqual(e.object.digest†, "Digest(13b741949c37b8e09cc3daa3194c58e4fd6b2f14d4b1d0f035a46d6d5a1d3f11)")
        XCTAssertEqual(e.subject.digest†, "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")
        XCTAssertEqual(e.digest†, "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")

        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           201(   ; assertion
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
        
        XCTAssertEqual(e.digest†, "Digest(78d666eb8f4c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2)")
        
        XCTAssertEqual(e.format(),
        """
        "knows": "Bob"
        """)
        
        XCTAssertEqual(e.subject.digest, Envelope("knows", "Bob").digest)
    }
    
    func testSubjectWithAssertion() throws {
        let e = try Self.singleAssertionEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           [
              200(   ; envelope
                 24("Alice")   ; leaf
              ),
              200(   ; envelope
                 201(   ; assertion
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
        
        XCTAssertEqual(e.digest†, "Digest(8955db5e016affb133df56c11fe6c5c82fa3036263d651286d134c7e56c0e9f2)")
        
        XCTAssertEqual(e.format(),
        """
        "Alice" [
            "knows": "Bob"
        ]
        """)
        
        XCTAssertEqual(try e.extractSubject(String.self), "Alice")
    }
    
    func testSubjectWithTwoAssertions() throws {
        let e = try Self.doubleAssertionEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           [
              200(   ; envelope
                 24("Alice")   ; leaf
              ),
              200(   ; envelope
                 201(   ; assertion
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
                 201(   ; assertion
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
        
        XCTAssertEqual(e.digest†, "Digest(b8d857f6e06a836fbc68ca0ce43e55ceb98eefd949119dab344e11c4ba5a0471)")
        
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
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           203(   ; wrapped-envelope
              24("Hello.")   ; leaf
           )
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(172a5e51431062e7b13525cbceb8ad8475977444cf28423e21c0d1dcbdfcaf47)")
        
        XCTAssertEqual(e.format(),
        """
        {
            "Hello."
        }
        """)
    }
    
    func testDoubleWrapped() throws {
        let e = try Self.doubleWrappedEnvelope.checkEncoding()
        
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           203(   ; wrapped-envelope
              203(   ; wrapped-envelope
                 24("Hello.")   ; leaf
              )
           )
        )
        """)
        
        XCTAssertEqual(e.digest†, "Digest(8b14f3bcd7c05aac8f2162e7047d7ef5d5eab7d82ee3f9dc4846c70bae4d200b)")
        
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

        XCTAssertEqual(e.digest†, "Digest(17db10e567ceb05522f0074c27c7d7796cac1d5ce20e45f405ab9063fdeeff1a)")

        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           24(   ; leaf
              204(   ; digest
                 h'8cc96cdb771176e835114a0f8936690b41cfed0df22d014eedd64edaea945d59'
              )
           )
        )
        """
        )
    }
}
