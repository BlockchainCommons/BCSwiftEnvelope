import Testing
import SecureComponents
import Envelope
import WolfBase

struct NonCorrelationTests {
    init() async {
        await addKnownTags()
    }

    @Test func testEnvelopeNonCorrelation() throws {
        let e1 = Envelope("Hello.")
        
        // e1 correlates with its elision
        #expect(e1.isEquivalent(to: e1.elide()))

        // e2 is the same message, but with random salt
        var rng = makeFakeRandomNumberGenerator()
        let e2 = try e1.addSalt(using: &rng).checkEncoding()

        #expect(e2.format() == """
        "Hello." [
            'salt': Salt
        ]
        """)

        #expect(e2.diagnostic() == """
        200(   / envelope /
           [
              201("Hello."),   / leaf /
              {
                 15:
                 201(   / leaf /
                    40018(h'b559bbbf6cce2632')   / salt /
                 )
              }
           ]
        )
        """)

        #expect(e2.treeFormat() == """
        4f0f2d55 NODE
            8cc96cdb subj "Hello."
            dd412f1d ASSERTION
                618975ce pred 'salt'
                7915f200 obj Salt
        """)

        // So even though its content is the same, it doesn't correlate.
        #expect(!e1.isEquivalent(to: e2))

        // And of course, neither does its elision.
        #expect(!e1.isEquivalent(to: e2.elide()))
    }
    
    @Test func testPredicateCorrelation() throws {
        let e1 = try Envelope("Foo")
            .addAssertion(.note, "Bar").checkEncoding()
        let e2 = try Envelope("Baz")
            .addAssertion(.note, "Quux").checkEncoding()

        let e1ExpectedFormat = """
        "Foo" [
            'note': "Bar"
        ]
        """
        #expect(e1.format() == e1ExpectedFormat)

        // e1 and e2 have the same predicate
        #expect(e1.assertions.first!.predicate!.isEquivalent(to: e2.assertions.first!.predicate!))
        
        // Redact the entire contents of e1 without
        // redacting the envelope itself.
        let e1Elided = try e1.elideRevealing(e1).checkEncoding()
        
        let redactedExpectedFormat = """
        ELIDED [
            ELIDED
        ]
        """
        #expect(e1Elided.format() == redactedExpectedFormat)
    }
    
    @Test func testAddSalt() throws {
        // Add salt to every part of an envelope.
        let source = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        let e1 = try Envelope("Alpha")
            .addSalt().checkEncoding()
            .wrap().checkEncoding()
            .addAssertion(
                Envelope(.note).addSalt().checkEncoding(),
                Envelope(source).addSalt().checkEncoding()
            )
        let e1ExpectedFormat = """
        {
            "Alpha" [
                'salt': Salt
            ]
        } [
            'note' [
                'salt': Salt
            ]
            : "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." [
                'salt': Salt
            ]
        ]
        """
        #expect(e1.format() == e1ExpectedFormat)

        let e1Elided = try e1.elideRevealing(e1).checkEncoding()
        
        let redactedExpectedFormat = """
        ELIDED [
            ELIDED
        ]
        """
        #expect(e1Elided.format() == redactedExpectedFormat)
    }
    
    @Test func testAddSaltedAssertion() throws {
        let saltedAssertion = Envelope("knows", "Bob").addSalt()
        let e = try Envelope("Alice")
            .addAssertion(saltedAssertion)
        print(e.format())
    }
}
