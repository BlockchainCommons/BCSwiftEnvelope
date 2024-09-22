import Testing
import SecureComponents
import Envelope
import WolfBase

struct CoreNestingTests {
    @Test func testPredicateEnclosures() throws {
        let alice = Envelope("Alice")
        let knows = Envelope("knows")
        let bob = Envelope("Bob")
        
        let a = Envelope("A")
        let b = Envelope("B")
        
        let knowsBob = Envelope(knows, bob)
        #expect(knowsBob.format() ==
            """
            "knows": "Bob"
            """
        )
        
        let ab = Envelope(a, b)
        #expect(ab.format() ==
            """
            "A": "B"
            """
        )
        
        let knowsABBob = try Envelope(knows.addAssertion(ab), bob).checkEncoding()
        #expect(knowsABBob.format() ==
            """
            "knows" [
                "A": "B"
            ]
            : "Bob"
            """
        )
        
        let knowsBobAB = try Envelope(knows, bob.addAssertion(ab)).checkEncoding()
        #expect(knowsBobAB.format() ==
            """
            "knows": "Bob" [
                "A": "B"
            ]
            """
        )
        
        let knowsBobEncloseAB = try knowsBob
            .addAssertion(ab)
            .checkEncoding()
        #expect(knowsBobEncloseAB.format() ==
            """
            {
                "knows": "Bob"
            } [
                "A": "B"
            ]
            """
        )
        
        let aliceKnowsBob = try alice
            .addAssertion(knowsBob)
            .checkEncoding()
        #expect(aliceKnowsBob.format() ==
            """
            "Alice" [
                "knows": "Bob"
            ]
            """
        )
        
        let aliceABKnowsBob = try aliceKnowsBob
            .addAssertion(ab)
            .checkEncoding()
        #expect(aliceABKnowsBob.format() ==
            """
            "Alice" [
                "A": "B"
                "knows": "Bob"
            ]
            """
        )
        
        let aliceKnowsABBob = try alice
            .addAssertion(Envelope(knows.addAssertion(ab), bob))
            .checkEncoding()
        #expect(aliceKnowsABBob.format() ==
            """
            "Alice" [
                "knows" [
                    "A": "B"
                ]
                : "Bob"
            ]
            """
        )
        
        let aliceKnowsBobAB = try alice
            .addAssertion(Envelope(knows, bob.addAssertion(ab)))
            .checkEncoding()
        #expect(aliceKnowsBobAB.format() ==
            """
            "Alice" [
                "knows": "Bob" [
                    "A": "B"
                ]
            ]
            """
        )
        
        let aliceKnowsABBobAB = try alice
            .addAssertion(Envelope(knows.addAssertion(ab), bob.addAssertion(ab)))
            .checkEncoding()
        #expect(aliceKnowsABBobAB.format() ==
            """
            "Alice" [
                "knows" [
                    "A": "B"
                ]
                : "Bob" [
                    "A": "B"
                ]
            ]
            """
        )
        
        let aliceABKnowsABBobAB = try alice
            .addAssertion(ab)
            .addAssertion(Envelope(knows.addAssertion(ab), bob.addAssertion(ab)))
            .checkEncoding()
        #expect(aliceABKnowsABBobAB.format() ==
            """
            "Alice" [
                "A": "B"
                "knows" [
                    "A": "B"
                ]
                : "Bob" [
                    "A": "B"
                ]
            ]
            """
        )
        
        let aliceABKnowsABBobABEncloseAB = try alice
            .addAssertion(ab)
            .addAssertion(
                Envelope(knows.addAssertion(ab), bob.addAssertion(ab))
                    .addAssertion(ab)
            )
            .checkEncoding()
        #expect(aliceABKnowsABBobABEncloseAB.format() ==
            """
            "Alice" [
                {
                    "knows" [
                        "A": "B"
                    ]
                    : "Bob" [
                        "A": "B"
                    ]
                } [
                    "A": "B"
                ]
                "A": "B"
            ]
            """
        )
    }
    
    @Test func testNestingPlaintext() {
        let envelope = Envelope(plaintextHello)
        
        let expectedFormat =
        """
        "Hello."
        """
        #expect(envelope.format() == expectedFormat)
        
        let elidedEnvelope = envelope.elide()
        #expect(elidedEnvelope.isEquivalent(to: envelope))
        
        let expectedElidedFormat =
        """
        ELIDED
        """
        #expect(elidedEnvelope.format() == expectedElidedFormat)
    }
    
    @Test func testNestingOnce() throws {
        let e1 = Envelope(plaintextHello)
        #expect(e1.format() ==
        """
        "Hello."
        """)
        
        #expect(e1.treeFormat() ==
        """
        8cc96cdb "Hello."
        """)

        let envelope = try e1
            .wrap()
            .checkEncoding()
        
        #expect(envelope.format() ==
        """
        {
            "Hello."
        }
        """)

        #expect(envelope.treeFormat() ==
        """
        172a5e51 WRAPPED
            8cc96cdb subj "Hello."
        """)

        let elidedEnvelope = try Envelope(plaintextHello)
            .elide()
            .wrap()
            .checkEncoding()
        
        #expect(elidedEnvelope.isEquivalent(to: envelope))
        
        #expect(elidedEnvelope.format() ==
        """
        {
            ELIDED
        }
        """)

        #expect(elidedEnvelope.treeFormat() ==
        """
        172a5e51 WRAPPED
            8cc96cdb subj ELIDED
        """)
    }
    
    @Test func testNestingTwice() throws {
        let envelope = try Envelope(plaintextHello)
            .wrap()
            .wrap()
            .checkEncoding()
        
        #expect(envelope.format() ==
        """
        {
            {
                "Hello."
            }
        }
        """)
        
        #expect(envelope.treeFormat() ==
        """
        8b14f3bc WRAPPED
            172a5e51 subj WRAPPED
                8cc96cdb subj "Hello."
        """)

        let target = try envelope
            .unwrap()
            .unwrap()
        let elidedEnvelope = envelope.elideRemoving(target)
        
        #expect(elidedEnvelope.format() ==
        """
        {
            {
                ELIDED
            }
        }
        """)
        #expect(envelope.isEquivalent(to: elidedEnvelope))
        #expect(envelope.isEquivalent(to: elidedEnvelope))

        #expect(elidedEnvelope.treeFormat() ==
        """
        8b14f3bc WRAPPED
            172a5e51 subj WRAPPED
                8cc96cdb subj ELIDED
        """)
    }

    @Test func testAssertionsOnAllPartsOfEnvelope() throws {
        let predicate = Envelope("predicate")
            .addAssertion("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .addAssertion("object-predicate", "object-object")
        let envelope = try Envelope("subject")
            .addAssertion(predicate, object)
            .checkEncoding()

        let expectedFormat =
        """
        "subject" [
            "predicate" [
                "predicate-predicate": "predicate-object"
            ]
            : "object" [
                "object-predicate": "object-object"
            ]
        ]
        """
        #expect(envelope.format() == expectedFormat)
    }
    
    @Test func testAssertionOnBareAssertion() throws {
        let envelope = try Envelope("predicate", "object")
            .addAssertion(Envelope("assertion-predicate", "assertion-object"))
        let expectedFormat =
        """
        {
            "predicate": "object"
        } [
            "assertion-predicate": "assertion-object"
        ]
        """
        #expect(envelope.format() == expectedFormat)
    }
}
