import XCTest
import SecureComponents
import Envelope
import WolfBase

class CoreNestingTests: XCTestCase {
    func testPredicateEnclosures() throws {
        let alice = Envelope("Alice")
        let knows = Envelope("knows")
        let bob = Envelope("Bob")
        
        let a = Envelope("A")
        let b = Envelope("B")
        
        let knowsBob = Envelope(knows, bob)
        XCTAssertEqual(knowsBob.format(),
            """
            "knows": "Bob"
            """
        )
        
        let ab = Envelope(a, b)
        XCTAssertEqual(ab.format(),
            """
            "A": "B"
            """
        )
        
        let knowsABBob = try Envelope(knows.addAssertion(ab), bob).checkEncoding()
        XCTAssertEqual(knowsABBob.format(),
            """
            "knows" [
                "A": "B"
            ]
            : "Bob"
            """
        )
        
        let knowsBobAB = try Envelope(knows, bob.addAssertion(ab)).checkEncoding()
        XCTAssertEqual(knowsBobAB.format(),
            """
            "knows": "Bob" [
                "A": "B"
            ]
            """
        )
        
        let knowsBobEncloseAB = try knowsBob
            .addAssertion(ab)
            .checkEncoding()
        XCTAssertEqual(knowsBobEncloseAB.format(),
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
        XCTAssertEqual(aliceKnowsBob.format(),
            """
            "Alice" [
                "knows": "Bob"
            ]
            """
        )
        
        let aliceABKnowsBob = try aliceKnowsBob
            .addAssertion(ab)
            .checkEncoding()
        XCTAssertEqual(aliceABKnowsBob.format(),
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
        XCTAssertEqual(aliceKnowsABBob.format(),
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
        XCTAssertEqual(aliceKnowsBobAB.format(),
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
        XCTAssertEqual(aliceKnowsABBobAB.format(),
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
        XCTAssertEqual(aliceABKnowsABBobAB.format(),
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
        XCTAssertEqual(aliceABKnowsABBobABEncloseAB.format(),
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
    
    func testNestingPlaintext() {
        let envelope = Envelope(plaintextHello)
        
        let expectedFormat =
        """
        "Hello."
        """
        XCTAssertEqual(envelope.format(), expectedFormat)
        
        let elidedEnvelope = envelope.elide()
        XCTAssert(elidedEnvelope.isEquivalent(to: envelope))
        
        let expectedElidedFormat =
        """
        ELIDED
        """
        XCTAssertEqual(elidedEnvelope.format(), expectedElidedFormat)
    }
    
    func testNestingOnce() throws {
        let e1 = Envelope(plaintextHello)
        XCTAssertEqual(e1.format(),
        """
        "Hello."
        """)
        
        XCTAssertEqual(e1.treeFormat(),
        """
        8cc96cdb "Hello."
        """)

        let envelope = try e1
            .wrap()
            .checkEncoding()
        
        XCTAssertEqual(envelope.format(),
        """
        {
            "Hello."
        }
        """)

        XCTAssertEqual(envelope.treeFormat(),
        """
        172a5e51 WRAPPED
            8cc96cdb subj "Hello."
        """)

        let elidedEnvelope = try Envelope(plaintextHello)
            .elide()
            .wrap()
            .checkEncoding()
        
        XCTAssert(elidedEnvelope.isEquivalent(to: envelope))
        
        XCTAssertEqual(elidedEnvelope.format(),
        """
        {
            ELIDED
        }
        """)

        XCTAssertEqual(elidedEnvelope.treeFormat(),
        """
        172a5e51 WRAPPED
            8cc96cdb subj ELIDED
        """)
    }
    
    func testNestingTwice() throws {
        let envelope = try Envelope(plaintextHello)
            .wrap()
            .wrap()
            .checkEncoding()
        
        XCTAssertEqual(envelope.format(),
        """
        {
            {
                "Hello."
            }
        }
        """)
        
        XCTAssertEqual(envelope.treeFormat(),
        """
        8b14f3bc WRAPPED
            172a5e51 subj WRAPPED
                8cc96cdb subj "Hello."
        """)

        let target = try envelope
            .unwrap()
            .unwrap()
        let elidedEnvelope = envelope.elideRemoving(target)
        
        XCTAssertEqual(elidedEnvelope.format(),
        """
        {
            {
                ELIDED
            }
        }
        """)
        XCTAssert(envelope.isEquivalent(to: elidedEnvelope))
        XCTAssert(envelope.isEquivalent(to: elidedEnvelope))

        XCTAssertEqual(elidedEnvelope.treeFormat(),
        """
        8b14f3bc WRAPPED
            172a5e51 subj WRAPPED
                8cc96cdb subj ELIDED
        """)
    }

    func testAssertionsOnAllPartsOfEnvelope() throws {
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
        XCTAssertEqual(envelope.format(), expectedFormat)
    }
    
    func testAssertionOnBareAssertion() throws {
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
        XCTAssertEqual(envelope.format(), expectedFormat)
    }
}
