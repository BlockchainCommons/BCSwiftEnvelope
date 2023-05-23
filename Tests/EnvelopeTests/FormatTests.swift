import XCTest
import SecureComponents
import Envelope
import WolfBase

class FormatTests: XCTestCase {
    func testPlaintext() throws {
        let envelope = Envelope(plaintextHello)
        XCTAssertEqual(envelope.format(),
        """
        "Hello."
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        8cc96cdb "Hello."
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        "Hello."
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1["8cc96cdb<br/>#quot;Hello.#quot;"]
            style 1 stroke:#55f,stroke-width:3.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["#quot;Hello.#quot;"]
            style 1 stroke:#55f,stroke-width:3.0px
        """)
    }
    
    func testSignedPlaintext() throws {
        let envelope = Envelope(plaintextHello)
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(envelope.format(),
        """
        "Hello." [
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        a6211fb0 NODE
            8cc96cdb subj "Hello."
            b4136c33 ASSERTION
                9d7ba9eb pred verifiedBy
                7d950941 obj Signature
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        "Hello."
            ASSERTION
                verifiedBy
                Signature
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1(("a6211fb0<br/>NODE"))
            2["8cc96cdb<br/>#quot;Hello.#quot;"]
            3(["b4136c33<br/>ASSERTION"])
            4[/"9d7ba9eb<br/>verifiedBy"/]
            5["7d950941<br/>Signature"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["#quot;Hello.#quot;"]
            2(["ASSERTION"])
            3[/"verifiedBy"/]
            4["Signature"]
            1 --> 2
            2 --> 3
            2 --> 4
            style 1 stroke:#55f,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
        """)
    }
    
    func testEncryptSubject() throws {
        let envelope = try Envelope("Alice")
            .addAssertion("knows", "Bob")
            .encryptSubject(with: SymmetricKey(), testNonce: fakeNonce)
        XCTAssertEqual(envelope.format(),
        """
        ENCRYPTED [
            "knows": "Bob"
        ]
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        8955db5e NODE
            13941b48 subj ENCRYPTED
            78d666eb ASSERTION
                db7dd21c pred "knows"
                13b74194 obj "Bob"
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        ENCRYPTED
            ASSERTION
                "knows"
                "Bob"
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1(("8955db5e<br/>NODE"))
            2>"13941b48<br/>ENCRYPTED"]
            3(["78d666eb<br/>ASSERTION"])
            4["db7dd21c<br/>#quot;knows#quot;"]
            5["13b74194<br/>#quot;Bob#quot;"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1>"ENCRYPTED"]
            2(["ASSERTION"])
            3["#quot;knows#quot;"]
            4["#quot;Bob#quot;"]
            1 --> 2
            2 --> 3
            2 --> 4
            style 1 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
        """)
    }
    
    func testTopLevelAssertion() throws {
        let envelope = Envelope("knows", "Bob")
        XCTAssertEqual(envelope.format(),
        """
        "knows": "Bob"
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        78d666eb ASSERTION
            db7dd21c pred "knows"
            13b74194 obj "Bob"
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        ASSERTION
            "knows"
            "Bob"
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1(["78d666eb<br/>ASSERTION"])
            2["db7dd21c<br/>#quot;knows#quot;"]
            3["13b74194<br/>#quot;Bob#quot;"]
            1 -->|pred| 2
            1 -->|obj| 3
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:green,stroke-width:2.0px
            linkStyle 1 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1(["ASSERTION"])
            2["#quot;knows#quot;"]
            3["#quot;Bob#quot;"]
            1 --> 2
            1 --> 3
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
        """)
    }

    func testElidedObject() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
        let elided = envelope.elideRemoving(Envelope("Bob"))
        XCTAssertEqual(elided.format(),
        """
        "Alice" [
            "knows": ELIDED
        ]
        """)
        XCTAssertEqual(elided.treeFormat(),
        """
        8955db5e NODE
            13941b48 subj "Alice"
            78d666eb ASSERTION
                db7dd21c pred "knows"
                13b74194 obj ELIDED
        """)
        XCTAssertEqual(elided.treeFormat(hideNodes: true),
        """
        "Alice"
            ASSERTION
                "knows"
                ELIDED
        """)
        XCTAssertEqual(elided.elementsCount, elided.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(elided.mermaidFormat(),
        """
        graph LR
            1(("8955db5e<br/>NODE"))
            2["13941b48<br/>#quot;Alice#quot;"]
            3(["78d666eb<br/>ASSERTION"])
            4["db7dd21c<br/>#quot;knows#quot;"]
            5{{"13b74194<br/>ELIDED"}}
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(elided.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["#quot;Alice#quot;"]
            2(["ASSERTION"])
            3["#quot;knows#quot;"]
            4{{"ELIDED"}}
            1 --> 2
            2 --> 3
            2 --> 4
            style 1 stroke:#55f,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
        """)
    }

    func testSignedSubject() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(envelope.format(),
        """
        "Alice" [
            "knows": "Bob"
            "knows": "Carol"
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        65f8235d NODE
            13941b48 subj "Alice"
            4012caf2 ASSERTION
                db7dd21c pred "knows"
                afb8122e obj "Carol"
            78d666eb ASSERTION
                db7dd21c pred "knows"
                13b74194 obj "Bob"
            bef4a3a8 ASSERTION
                9d7ba9eb pred verifiedBy
                3bec6b45 obj Signature
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        "Alice"
            ASSERTION
                "knows"
                "Carol"
            ASSERTION
                "knows"
                "Bob"
            ASSERTION
                verifiedBy
                Signature
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1(("65f8235d<br/>NODE"))
            2["13941b48<br/>#quot;Alice#quot;"]
            3(["4012caf2<br/>ASSERTION"])
            4["db7dd21c<br/>#quot;knows#quot;"]
            5["afb8122e<br/>#quot;Carol#quot;"]
            6(["78d666eb<br/>ASSERTION"])
            7["db7dd21c<br/>#quot;knows#quot;"]
            8["13b74194<br/>#quot;Bob#quot;"]
            9(["bef4a3a8<br/>ASSERTION"])
            10[/"9d7ba9eb<br/>verifiedBy"/]
            11["3bec6b45<br/>Signature"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            1 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            1 --> 9
            9 -->|pred| 10
            9 -->|obj| 11
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke:green,stroke-width:2.0px
            linkStyle 9 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["#quot;Alice#quot;"]
            2(["ASSERTION"])
            3["#quot;knows#quot;"]
            4["#quot;Carol#quot;"]
            5(["ASSERTION"])
            6["#quot;knows#quot;"]
            7["#quot;Bob#quot;"]
            8(["ASSERTION"])
            9[/"verifiedBy"/]
            10["Signature"]
            1 --> 2
            2 --> 3
            2 --> 4
            1 --> 5
            5 --> 6
            5 --> 7
            1 --> 8
            8 --> 9
            8 --> 10
            style 1 stroke:#55f,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
        """)

        // Elided Assertions
        var target = Set<Digest>()
        target.insert(envelope)
        target.insert(envelope.subject)
        let elided = envelope.elideRevealing(target)
        XCTAssertEqual(elided.format(),
        """
        "Alice" [
            ELIDED (3)
        ]
        """)
        XCTAssertEqual(elided.treeFormat(),
        """
        65f8235d NODE
            13941b48 subj "Alice"
            4012caf2 ELIDED
            78d666eb ELIDED
            bef4a3a8 ELIDED
        """)
        XCTAssertEqual(elided.treeFormat(hideNodes: true),
        """
        "Alice"
            ELIDED
            ELIDED
            ELIDED
        """)
        XCTAssertEqual(elided.elementsCount, elided.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(elided.mermaidFormat(),
        """
        graph LR
            1(("65f8235d<br/>NODE"))
            2["13941b48<br/>#quot;Alice#quot;"]
            3{{"4012caf2<br/>ELIDED"}}
            4{{"78d666eb<br/>ELIDED"}}
            5{{"bef4a3a8<br/>ELIDED"}}
            1 -->|subj| 2
            1 --> 3
            1 --> 4
            1 --> 5
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 4 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
        """)
        XCTAssertEqual(elided.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["#quot;Alice#quot;"]
            2{{"ELIDED"}}
            3{{"ELIDED"}}
            4{{"ELIDED"}}
            1 --> 2
            1 --> 3
            1 --> 4
            style 1 stroke:#55f,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 3 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 4 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
        """)
    }

    func testWrapThenSign() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
            .addAssertion("knows", "Carol")
            .wrap()
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(envelope.format(),
        """
        {
            "Alice" [
                "knows": "Bob"
                "knows": "Carol"
            ]
        } [
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        58866b08 NODE
            9e3b0673 subj WRAPPED
                b8d857f6 subj NODE
                    13941b48 subj "Alice"
                    4012caf2 ASSERTION
                        db7dd21c pred "knows"
                        afb8122e obj "Carol"
                    78d666eb ASSERTION
                        db7dd21c pred "knows"
                        13b74194 obj "Bob"
            05c6c627 ASSERTION
                9d7ba9eb pred verifiedBy
                5e92bccf obj Signature
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        WRAPPED
            "Alice"
                ASSERTION
                    "knows"
                    "Carol"
                ASSERTION
                    "knows"
                    "Bob"
            ASSERTION
                verifiedBy
                Signature
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        #"""
        graph LR
            1(("58866b08<br/>NODE"))
            2[/"9e3b0673<br/>WRAPPED"\]
            3(("b8d857f6<br/>NODE"))
            4["13941b48<br/>#quot;Alice#quot;"]
            5(["4012caf2<br/>ASSERTION"])
            6["db7dd21c<br/>#quot;knows#quot;"]
            7["afb8122e<br/>#quot;Carol#quot;"]
            8(["78d666eb<br/>ASSERTION"])
            9["db7dd21c<br/>#quot;knows#quot;"]
            10["13b74194<br/>#quot;Bob#quot;"]
            11(["05c6c627<br/>ASSERTION"])
            12[/"9d7ba9eb<br/>verifiedBy"/]
            13["5e92bccf<br/>Signature"]
            1 -->|subj| 2
            2 -->|subj| 3
            3 -->|subj| 4
            3 --> 5
            5 -->|pred| 6
            5 -->|obj| 7
            3 --> 8
            8 -->|pred| 9
            8 -->|obj| 10
            1 --> 11
            11 -->|pred| 12
            11 -->|obj| 13
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke:red,stroke-width:2.0px
            linkStyle 2 stroke:red,stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke:green,stroke-width:2.0px
            linkStyle 5 stroke:#55f,stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke:green,stroke-width:2.0px
            linkStyle 8 stroke:#55f,stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke:green,stroke-width:2.0px
            linkStyle 11 stroke:#55f,stroke-width:2.0px
        """#)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        #"""
        graph LR
            1[/"WRAPPED"\]
            2["#quot;Alice#quot;"]
            3(["ASSERTION"])
            4["#quot;knows#quot;"]
            5["#quot;Carol#quot;"]
            6(["ASSERTION"])
            7["#quot;knows#quot;"]
            8["#quot;Bob#quot;"]
            9(["ASSERTION"])
            10[/"verifiedBy"/]
            11["Signature"]
            1 --> 2
            2 --> 3
            3 --> 4
            3 --> 5
            2 --> 6
            6 --> 7
            6 --> 8
            1 --> 9
            9 --> 10
            9 --> 11
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
        """#)
    }
    
    func testEncryptToRecipients() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let envelope = try Envelope(plaintextHello)
            .encryptSubject(with: fakeContentKey, testNonce: fakeNonce).checkEncoding()
            .addRecipient(bobPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce).checkEncoding()
            .addRecipient(carolPublicKeys, contentKey: fakeContentKey, testKeyMaterial: fakeContentKey, testNonce: fakeNonce).checkEncoding()
        XCTAssertEqual(envelope.format(),
        """
        ENCRYPTED [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        9f130c09 NODE
            8cc96cdb subj ENCRYPTED
            7137c3c2 ASSERTION
                e41178b8 pred hasRecipient
                b0925349 obj SealedMessage
            fdb08145 ASSERTION
                e41178b8 pred hasRecipient
                b0e86e20 obj SealedMessage
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        ENCRYPTED
            ASSERTION
                hasRecipient
                SealedMessage
            ASSERTION
                hasRecipient
                SealedMessage
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1(("9f130c09<br/>NODE"))
            2>"8cc96cdb<br/>ENCRYPTED"]
            3(["7137c3c2<br/>ASSERTION"])
            4[/"e41178b8<br/>hasRecipient"/]
            5["b0925349<br/>SealedMessage"]
            6(["fdb08145<br/>ASSERTION"])
            7[/"e41178b8<br/>hasRecipient"/]
            8["b0e86e20<br/>SealedMessage"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            1 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1>"ENCRYPTED"]
            2(["ASSERTION"])
            3[/"hasRecipient"/]
            4["SealedMessage"]
            5(["ASSERTION"])
            6[/"hasRecipient"/]
            7["SealedMessage"]
            1 --> 2
            2 --> 3
            2 --> 4
            1 --> 5
            5 --> 6
            5 --> 7
            style 1 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
        """)
    }

    func testAssertionPositions() throws {
        let predicate = Envelope("predicate")
            .addAssertion("predicate-predicate", "predicate-object")
        let object = Envelope("object")
            .addAssertion("object-predicate", "object-object")
        let envelope = try Envelope("subject")
            .addAssertion(predicate, object)
            .checkEncoding()
        XCTAssertEqual(envelope.format(),
        """
        "subject" [
            "predicate" [
                "predicate-predicate": "predicate-object"
            ]
            : "object" [
                "object-predicate": "object-object"
            ]
        ]
        """)
        XCTAssertEqual(envelope.treeFormat(),
        """
        e06d7003 NODE
            8e4e62eb subj "subject"
            91a436e0 ASSERTION
                cece8b2c pred NODE
                    d21efb76 subj "predicate"
                    66a0c92b ASSERTION
                        ab829e9f pred "predicate-predicate"
                        f1098628 obj "predicate-object"
                03a99a27 obj NODE
                    fda63155 subj "object"
                    d1878aea ASSERTION
                        88bb262f pred "object-predicate"
                        0bdb89a6 obj "object-object"
        """)
        XCTAssertEqual(envelope.treeFormat(hideNodes: true),
        """
        "subject"
            ASSERTION
                "predicate"
                    ASSERTION
                        "predicate-predicate"
                        "predicate-object"
                "object"
                    ASSERTION
                        "object-predicate"
                        "object-object"
        """)
        XCTAssertEqual(envelope.elementsCount, envelope.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(envelope.mermaidFormat(),
        """
        graph LR
            1(("e06d7003<br/>NODE"))
            2["8e4e62eb<br/>#quot;subject#quot;"]
            3(["91a436e0<br/>ASSERTION"])
            4(("cece8b2c<br/>NODE"))
            5["d21efb76<br/>#quot;predicate#quot;"]
            6(["66a0c92b<br/>ASSERTION"])
            7["ab829e9f<br/>#quot;predicate-predicate#quot;"]
            8["f1098628<br/>#quot;predicate-object#quot;"]
            9(("03a99a27<br/>NODE"))
            10["fda63155<br/>#quot;object#quot;"]
            11(["d1878aea<br/>ASSERTION"])
            12["88bb262f<br/>#quot;object-predicate#quot;"]
            13["0bdb89a6<br/>#quot;object-object#quot;"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            4 -->|subj| 5
            4 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            3 -->|obj| 9
            9 -->|subj| 10
            9 --> 11
            11 -->|pred| 12
            11 -->|obj| 13
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:red,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:red,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
            linkStyle 7 stroke:#55f,stroke-width:2.0px
            linkStyle 8 stroke:red,stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke:green,stroke-width:2.0px
            linkStyle 11 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(envelope.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["#quot;subject#quot;"]
            2(["ASSERTION"])
            3["#quot;predicate#quot;"]
            4(["ASSERTION"])
            5["#quot;predicate-predicate#quot;"]
            6["#quot;predicate-object#quot;"]
            7["#quot;object#quot;"]
            8(["ASSERTION"])
            9["#quot;object-predicate#quot;"]
            10["#quot;object-object#quot;"]
            1 --> 2
            2 --> 3
            3 --> 4
            4 --> 5
            4 --> 6
            2 --> 7
            7 --> 8
            8 --> 9
            8 --> 10
            style 1 stroke:#55f,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:red,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
        """)
    }

    func testComplexMetadata() throws {
        // Assertions made about an CID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the CID and when it is
        // resolved. In other words, the referent of a CID is mutable.
        let author = try Envelope(CID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, "Ayn Rand")
            .checkEncoding()

        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .addAssertion(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .addAssertion(.language, "es")

        let work = try Envelope(CID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .addAssertion(.isA, "novel")
            .addAssertion("isbn", "9780451191144")
            .addAssertion("author", author)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, name_en)
            .addAssertion(.hasName, name_es)
            .checkEncoding()

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary
        // object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = try Envelope(Digest(bookData))
            .addAssertion("work", work)
            .addAssertion("format", "EPUB")
            .addAssertion(.dereferenceVia, "IPFS")
            .checkEncoding()
        
        XCTAssertEqual(bookMetadata.format(),
        """
        Digest(26d05af5) [
            "format": "EPUB"
            "work": CID(7fb90a9d) [
                "author": CID(9c747ace) [
                    dereferenceVia: "LibraryOfCongress"
                    hasName: "Ayn Rand"
                ]
                "isbn": "9780451191144"
                dereferenceVia: "LibraryOfCongress"
                hasName: "Atlas Shrugged" [
                    language: "en"
                ]
                hasName: "La rebelión de Atlas" [
                    language: "es"
                ]
                isA: "novel"
            ]
            dereferenceVia: "IPFS"
        ]
        """)
        XCTAssertEqual(bookMetadata.treeFormat(),
        """
        f41cbb59 NODE
            5d3e9195 subj Digest(26d05af5)
            05edf8ca ASSERTION
                e25b9baf pred dereferenceVia
                15eac58f obj "IPFS"
            953cdab2 ASSERTION
                a9a86b03 pred "format"
                9536cfe0 obj "EPUB"
            a3400534 ASSERTION
                2ddb0b05 pred "work"
                3d2c3a7f obj NODE
                    d8304d46 subj CID(7fb90a9d)
                    1786d8b5 ASSERTION
                        4019420b pred "isbn"
                        69ff76b1 obj "9780451191144"
                    1903fe89 ASSERTION
                        9d0480e0 pred hasName
                        61a11981 obj NODE
                            5e825721 subj "La rebelión de Atlas"
                            62ea333c ASSERTION
                                65fa1c25 pred language
                                b33e79c2 obj "es"
                    212af9fb ASSERTION
                        96f0167d pred isA
                        6d7c7189 obj "novel"
                    21af9ce9 ASSERTION
                        29c09059 pred "author"
                        71bf6c35 obj NODE
                            f4f77a81 subj CID(9c747ace)
                            050a4539 ASSERTION
                                9d0480e0 pred hasName
                                98985bd5 obj "Ayn Rand"
                            24b5a41b ASSERTION
                                e25b9baf pred dereferenceVia
                                34a04547 obj "LibraryOfCongress"
                    24b5a41b ASSERTION
                        e25b9baf pred dereferenceVia
                        34a04547 obj "LibraryOfCongress"
                    3d1f0148 ASSERTION
                        9d0480e0 pred hasName
                        fb15ce3e obj NODE
                            e84c3091 subj "Atlas Shrugged"
                            e6bd65c8 ASSERTION
                                65fa1c25 pred language
                                6700869c obj "en"
        """)
        XCTAssertEqual(bookMetadata.treeFormat(hideNodes: true),
        """
        Digest(26d05af5)
            ASSERTION
                dereferenceVia
                "IPFS"
            ASSERTION
                "format"
                "EPUB"
            ASSERTION
                "work"
                CID(7fb90a9d)
                    ASSERTION
                        "isbn"
                        "9780451191144"
                    ASSERTION
                        hasName
                        "La rebelión de Atlas"
                            ASSERTION
                                language
                                "es"
                    ASSERTION
                        isA
                        "novel"
                    ASSERTION
                        "author"
                        CID(9c747ace)
                            ASSERTION
                                hasName
                                "Ayn Rand"
                            ASSERTION
                                dereferenceVia
                                "LibraryOfCongress"
                    ASSERTION
                        dereferenceVia
                        "LibraryOfCongress"
                    ASSERTION
                        hasName
                        "Atlas Shrugged"
                            ASSERTION
                                language
                                "en"
        """)
        XCTAssertEqual(bookMetadata.elementsCount, bookMetadata.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(bookMetadata.mermaidFormat(),
        """
        graph LR
            1(("f41cbb59<br/>NODE"))
            2["5d3e9195<br/>Digest(26d05af5)"]
            3(["05edf8ca<br/>ASSERTION"])
            4[/"e25b9baf<br/>dereferenceVia"/]
            5["15eac58f<br/>#quot;IPFS#quot;"]
            6(["953cdab2<br/>ASSERTION"])
            7["a9a86b03<br/>#quot;format#quot;"]
            8["9536cfe0<br/>#quot;EPUB#quot;"]
            9(["a3400534<br/>ASSERTION"])
            10["2ddb0b05<br/>#quot;work#quot;"]
            11(("3d2c3a7f<br/>NODE"))
            12["d8304d46<br/>CID(7fb90a9d)"]
            13(["1786d8b5<br/>ASSERTION"])
            14["4019420b<br/>#quot;isbn#quot;"]
            15["69ff76b1<br/>#quot;9780451191144#quot;"]
            16(["1903fe89<br/>ASSERTION"])
            17[/"9d0480e0<br/>hasName"/]
            18(("61a11981<br/>NODE"))
            19["5e825721<br/>#quot;La rebelión de Atlas#quot;"]
            20(["62ea333c<br/>ASSERTION"])
            21[/"65fa1c25<br/>language"/]
            22["b33e79c2<br/>#quot;es#quot;"]
            23(["212af9fb<br/>ASSERTION"])
            24[/"96f0167d<br/>isA"/]
            25["6d7c7189<br/>#quot;novel#quot;"]
            26(["21af9ce9<br/>ASSERTION"])
            27["29c09059<br/>#quot;author#quot;"]
            28(("71bf6c35<br/>NODE"))
            29["f4f77a81<br/>CID(9c747ace)"]
            30(["050a4539<br/>ASSERTION"])
            31[/"9d0480e0<br/>hasName"/]
            32["98985bd5<br/>#quot;Ayn Rand#quot;"]
            33(["24b5a41b<br/>ASSERTION"])
            34[/"e25b9baf<br/>dereferenceVia"/]
            35["34a04547<br/>#quot;LibraryOfCongress#quot;"]
            36(["24b5a41b<br/>ASSERTION"])
            37[/"e25b9baf<br/>dereferenceVia"/]
            38["34a04547<br/>#quot;LibraryOfCongress#quot;"]
            39(["3d1f0148<br/>ASSERTION"])
            40[/"9d0480e0<br/>hasName"/]
            41(("fb15ce3e<br/>NODE"))
            42["e84c3091<br/>#quot;Atlas Shrugged#quot;"]
            43(["e6bd65c8<br/>ASSERTION"])
            44[/"65fa1c25<br/>language"/]
            45["6700869c<br/>#quot;en#quot;"]
            1 -->|subj| 2
            1 --> 3
            3 -->|pred| 4
            3 -->|obj| 5
            1 --> 6
            6 -->|pred| 7
            6 -->|obj| 8
            1 --> 9
            9 -->|pred| 10
            9 -->|obj| 11
            11 -->|subj| 12
            11 --> 13
            13 -->|pred| 14
            13 -->|obj| 15
            11 --> 16
            16 -->|pred| 17
            16 -->|obj| 18
            18 -->|subj| 19
            18 --> 20
            20 -->|pred| 21
            20 -->|obj| 22
            11 --> 23
            23 -->|pred| 24
            23 -->|obj| 25
            11 --> 26
            26 -->|pred| 27
            26 -->|obj| 28
            28 -->|subj| 29
            28 --> 30
            30 -->|pred| 31
            30 -->|obj| 32
            28 --> 33
            33 -->|pred| 34
            33 -->|obj| 35
            11 --> 36
            36 -->|pred| 37
            36 -->|obj| 38
            11 --> 39
            39 -->|pred| 40
            39 -->|obj| 41
            41 -->|subj| 42
            41 --> 43
            43 -->|pred| 44
            43 -->|obj| 45
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:red,stroke-width:3.0px
            style 14 stroke:#55f,stroke-width:3.0px
            style 15 stroke:#55f,stroke-width:3.0px
            style 16 stroke:red,stroke-width:3.0px
            style 17 stroke:#55f,stroke-width:3.0px
            style 18 stroke:red,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:red,stroke-width:3.0px
            style 27 stroke:#55f,stroke-width:3.0px
            style 28 stroke:red,stroke-width:3.0px
            style 29 stroke:#55f,stroke-width:3.0px
            style 30 stroke:red,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:#55f,stroke-width:3.0px
            style 33 stroke:red,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:#55f,stroke-width:3.0px
            style 36 stroke:red,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:#55f,stroke-width:3.0px
            style 39 stroke:red,stroke-width:3.0px
            style 40 stroke:#55f,stroke-width:3.0px
            style 41 stroke:red,stroke-width:3.0px
            style 42 stroke:#55f,stroke-width:3.0px
            style 43 stroke:red,stroke-width:3.0px
            style 44 stroke:#55f,stroke-width:3.0px
            style 45 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke:green,stroke-width:2.0px
            linkStyle 3 stroke:#55f,stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke:green,stroke-width:2.0px
            linkStyle 6 stroke:#55f,stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke:green,stroke-width:2.0px
            linkStyle 9 stroke:#55f,stroke-width:2.0px
            linkStyle 10 stroke:red,stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke:green,stroke-width:2.0px
            linkStyle 13 stroke:#55f,stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke:green,stroke-width:2.0px
            linkStyle 16 stroke:#55f,stroke-width:2.0px
            linkStyle 17 stroke:red,stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke:green,stroke-width:2.0px
            linkStyle 20 stroke:#55f,stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke:green,stroke-width:2.0px
            linkStyle 23 stroke:#55f,stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke:green,stroke-width:2.0px
            linkStyle 26 stroke:#55f,stroke-width:2.0px
            linkStyle 27 stroke:red,stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke:green,stroke-width:2.0px
            linkStyle 30 stroke:#55f,stroke-width:2.0px
            linkStyle 31 stroke-width:2.0px
            linkStyle 32 stroke:green,stroke-width:2.0px
            linkStyle 33 stroke:#55f,stroke-width:2.0px
            linkStyle 34 stroke-width:2.0px
            linkStyle 35 stroke:green,stroke-width:2.0px
            linkStyle 36 stroke:#55f,stroke-width:2.0px
            linkStyle 37 stroke-width:2.0px
            linkStyle 38 stroke:green,stroke-width:2.0px
            linkStyle 39 stroke:#55f,stroke-width:2.0px
            linkStyle 40 stroke:red,stroke-width:2.0px
            linkStyle 41 stroke-width:2.0px
            linkStyle 42 stroke:green,stroke-width:2.0px
            linkStyle 43 stroke:#55f,stroke-width:2.0px
        """)
        XCTAssertEqual(bookMetadata.mermaidFormat(hideNodes: true),
        """
        graph LR
            1["Digest(26d05af5)"]
            2(["ASSERTION"])
            3[/"dereferenceVia"/]
            4["#quot;IPFS#quot;"]
            5(["ASSERTION"])
            6["#quot;format#quot;"]
            7["#quot;EPUB#quot;"]
            8(["ASSERTION"])
            9["#quot;work#quot;"]
            10["CID(7fb90a9d)"]
            11(["ASSERTION"])
            12["#quot;isbn#quot;"]
            13["#quot;9780451191144#quot;"]
            14(["ASSERTION"])
            15[/"hasName"/]
            16["#quot;La rebelión de Atlas#quot;"]
            17(["ASSERTION"])
            18[/"language"/]
            19["#quot;es#quot;"]
            20(["ASSERTION"])
            21[/"isA"/]
            22["#quot;novel#quot;"]
            23(["ASSERTION"])
            24["#quot;author#quot;"]
            25["CID(9c747ace)"]
            26(["ASSERTION"])
            27[/"hasName"/]
            28["#quot;Ayn Rand#quot;"]
            29(["ASSERTION"])
            30[/"dereferenceVia"/]
            31["#quot;LibraryOfCongress#quot;"]
            32(["ASSERTION"])
            33[/"dereferenceVia"/]
            34["#quot;LibraryOfCongress#quot;"]
            35(["ASSERTION"])
            36[/"hasName"/]
            37["#quot;Atlas Shrugged#quot;"]
            38(["ASSERTION"])
            39[/"language"/]
            40["#quot;en#quot;"]
            1 --> 2
            2 --> 3
            2 --> 4
            1 --> 5
            5 --> 6
            5 --> 7
            1 --> 8
            8 --> 9
            8 --> 10
            10 --> 11
            11 --> 12
            11 --> 13
            10 --> 14
            14 --> 15
            14 --> 16
            16 --> 17
            17 --> 18
            17 --> 19
            10 --> 20
            20 --> 21
            20 --> 22
            10 --> 23
            23 --> 24
            23 --> 25
            25 --> 26
            26 --> 27
            26 --> 28
            25 --> 29
            29 --> 30
            29 --> 31
            10 --> 32
            32 --> 33
            32 --> 34
            10 --> 35
            35 --> 36
            35 --> 37
            37 --> 38
            38 --> 39
            38 --> 40
            style 1 stroke:#55f,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:#55f,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            style 14 stroke:red,stroke-width:3.0px
            style 15 stroke:#55f,stroke-width:3.0px
            style 16 stroke:#55f,stroke-width:3.0px
            style 17 stroke:red,stroke-width:3.0px
            style 18 stroke:#55f,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:red,stroke-width:3.0px
            style 27 stroke:#55f,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:red,stroke-width:3.0px
            style 30 stroke:#55f,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:red,stroke-width:3.0px
            style 33 stroke:#55f,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:red,stroke-width:3.0px
            style 36 stroke:#55f,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:red,stroke-width:3.0px
            style 39 stroke:#55f,stroke-width:3.0px
            style 40 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke-width:2.0px
            linkStyle 13 stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke-width:2.0px
            linkStyle 16 stroke-width:2.0px
            linkStyle 17 stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke-width:2.0px
            linkStyle 20 stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke-width:2.0px
            linkStyle 23 stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke-width:2.0px
            linkStyle 26 stroke-width:2.0px
            linkStyle 27 stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke-width:2.0px
            linkStyle 30 stroke-width:2.0px
            linkStyle 31 stroke-width:2.0px
            linkStyle 32 stroke-width:2.0px
            linkStyle 33 stroke-width:2.0px
            linkStyle 34 stroke-width:2.0px
            linkStyle 35 stroke-width:2.0px
            linkStyle 36 stroke-width:2.0px
            linkStyle 37 stroke-width:2.0px
            linkStyle 38 stroke-width:2.0px
        """)
    }

    static let credential = try! Envelope(CID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
        .addAssertion(.isA, "Certificate of Completion")
        .addAssertion(.issuer, "Example Electrical Engineering Board")
        .addAssertion(.controller, "Example Electrical Engineering Board")
        .addAssertion("firstName", "James")
        .addAssertion("lastName", "Maxwell")
        .addAssertion("issueDate", Date(iso8601: "2020-01-01"))
        .addAssertion("expirationDate", Date(iso8601: "2028-01-01"))
        .addAssertion("photo", "This is James Maxwell's photo.")
        .addAssertion("certificateNumber", "123-456-789")
        .addAssertion("subject", "RF and Microwave Engineering")
        .addAssertion("continuingEducationUnits", 1)
        .addAssertion("professionalDevelopmentHours", 15)
        .addAssertion("topics", ["Subject 1", "Subject 2"])
        .wrap()
        .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        .addAssertion(.note, "Signed by Example Electrical Engineering Board")
        .checkEncoding()

    func testCredential() throws {
        XCTAssertEqual(Self.credential.format(),
        """
        {
            CID(4676635a) [
                "certificateNumber": "123-456-789"
                "continuingEducationUnits": 1
                "expirationDate": 2028-01-01
                "firstName": "James"
                "issueDate": 2020-01-01
                "lastName": "Maxwell"
                "photo": "This is James Maxwell's photo."
                "professionalDevelopmentHours": 15
                "subject": "RF and Microwave Engineering"
                "topics": ["Subject 1", "Subject 2"]
                controller: "Example Electrical Engineering Board"
                isA: "Certificate of Completion"
                issuer: "Example Electrical Engineering Board"
            ]
        } [
            note: "Signed by Example Electrical Engineering Board"
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(Self.credential.treeFormat(),
        """
        e1335c97 NODE
            5886e784 subj WRAPPED
                c9860567 subj NODE
                    5fb45cf1 subj CID(4676635a)
                    1f9ff098 ASSERTION
                        9e3bff3a pred "certificateNumber"
                        21c21808 obj "123-456-789"
                    36c254d0 ASSERTION
                        6e5d379f pred "expirationDate"
                        639ae9bf obj 2028-01-01
                    3c114201 ASSERTION
                        5f82a16a pred "lastName"
                        fe4d5230 obj "Maxwell"
                    4a9b2e4d ASSERTION
                        222afe69 pred "issueDate"
                        cb67f31d obj 2020-01-01
                    5171cbaf ASSERTION
                        3976ef74 pred "photo"
                        231b8527 obj "This is James Maxwell's photo."
                    54b3e1e7 ASSERTION
                        f13aa855 pred "professionalDevelopmentHours"
                        dc0e9c36 obj 15
                    5dc6d4e3 ASSERTION
                        4395643b pred "firstName"
                        d6d0b768 obj "James"
                    68895d8e ASSERTION
                        e6bf4dd3 pred "topics"
                        543fcc09 obj ["Subject 1", "Subject 2"]
                    8ec5e912 ASSERTION
                        2b191589 pred "continuingEducationUnits"
                        4bf5122f obj 1
                    922c859a ASSERTION
                        96f0167d pred isA
                        051beee6 obj "Certificate of Completion"
                    caf5ced3 ASSERTION
                        8e4e62eb pred "subject"
                        202c10ef obj "RF and Microwave Engineering"
                    d61e0984 ASSERTION
                        e665c567 pred controller
                        f8489ac1 obj "Example Electrical Engineering Board"
                    ebcbf71f ASSERTION
                        fde30b5c pred issuer
                        f8489ac1 obj "Example Electrical Engineering Board"
            4025e72d ASSERTION
                9d7ba9eb pred verifiedBy
                73316b2b obj Signature
            55b14b17 ASSERTION
                49a5f41b pred note
                f106bad1 obj "Signed by Example Electrical Engineering…"
        """)
        XCTAssertEqual(Self.credential.treeFormat(hideNodes: true),
        """
        WRAPPED
            CID(4676635a)
                ASSERTION
                    "certificateNumber"
                    "123-456-789"
                ASSERTION
                    "expirationDate"
                    2028-01-01
                ASSERTION
                    "lastName"
                    "Maxwell"
                ASSERTION
                    "issueDate"
                    2020-01-01
                ASSERTION
                    "photo"
                    "This is James Maxwell's photo."
                ASSERTION
                    "professionalDevelopmentHours"
                    15
                ASSERTION
                    "firstName"
                    "James"
                ASSERTION
                    "topics"
                    ["Subject 1", "Subject 2"]
                ASSERTION
                    "continuingEducationUnits"
                    1
                ASSERTION
                    isA
                    "Certificate of Completion"
                ASSERTION
                    "subject"
                    "RF and Microwave Engineering"
                ASSERTION
                    controller
                    "Example Electrical Engineering Board"
                ASSERTION
                    issuer
                    "Example Electrical Engineering Board"
            ASSERTION
                verifiedBy
                Signature
            ASSERTION
                note
                "Signed by Example Electrical Engineering…"
        """)
        XCTAssertEqual(Self.credential.elementsCount, Self.credential.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(Self.credential.mermaidFormat(),
        #"""
        graph LR
            1(("e1335c97<br/>NODE"))
            2[/"5886e784<br/>WRAPPED"\]
            3(("c9860567<br/>NODE"))
            4["5fb45cf1<br/>CID(4676635a)"]
            5(["1f9ff098<br/>ASSERTION"])
            6["9e3bff3a<br/>#quot;certificateNumber#quot;"]
            7["21c21808<br/>#quot;123-456-789#quot;"]
            8(["36c254d0<br/>ASSERTION"])
            9["6e5d379f<br/>#quot;expirationDate#quot;"]
            10["639ae9bf<br/>2028-01-01"]
            11(["3c114201<br/>ASSERTION"])
            12["5f82a16a<br/>#quot;lastName#quot;"]
            13["fe4d5230<br/>#quot;Maxwell#quot;"]
            14(["4a9b2e4d<br/>ASSERTION"])
            15["222afe69<br/>#quot;issueDate#quot;"]
            16["cb67f31d<br/>2020-01-01"]
            17(["5171cbaf<br/>ASSERTION"])
            18["3976ef74<br/>#quot;photo#quot;"]
            19["231b8527<br/>#quot;This is James Maxwell's photo.#quot;"]
            20(["54b3e1e7<br/>ASSERTION"])
            21["f13aa855<br/>#quot;professionalDevelopmentHours#quot;"]
            22["dc0e9c36<br/>15"]
            23(["5dc6d4e3<br/>ASSERTION"])
            24["4395643b<br/>#quot;firstName#quot;"]
            25["d6d0b768<br/>#quot;James#quot;"]
            26(["68895d8e<br/>ASSERTION"])
            27["e6bf4dd3<br/>#quot;topics#quot;"]
            28["543fcc09<br/>[#quot;Subject 1#quot;, #quot;Subject 2#quot;]"]
            29(["8ec5e912<br/>ASSERTION"])
            30["2b191589<br/>#quot;continuingEducationUnits#quot;"]
            31["4bf5122f<br/>1"]
            32(["922c859a<br/>ASSERTION"])
            33[/"96f0167d<br/>isA"/]
            34["051beee6<br/>#quot;Certificate of Completion#quot;"]
            35(["caf5ced3<br/>ASSERTION"])
            36["8e4e62eb<br/>#quot;subject#quot;"]
            37["202c10ef<br/>#quot;RF and Microwave Engineering#quot;"]
            38(["d61e0984<br/>ASSERTION"])
            39[/"e665c567<br/>controller"/]
            40["f8489ac1<br/>#quot;Example Electrical Engineering Board#quot;"]
            41(["ebcbf71f<br/>ASSERTION"])
            42[/"fde30b5c<br/>issuer"/]
            43["f8489ac1<br/>#quot;Example Electrical Engineering Board#quot;"]
            44(["4025e72d<br/>ASSERTION"])
            45[/"9d7ba9eb<br/>verifiedBy"/]
            46["73316b2b<br/>Signature"]
            47(["55b14b17<br/>ASSERTION"])
            48[/"49a5f41b<br/>note"/]
            49["f106bad1<br/>#quot;Signed by Example Electrical Engineering…#quot;"]
            1 -->|subj| 2
            2 -->|subj| 3
            3 -->|subj| 4
            3 --> 5
            5 -->|pred| 6
            5 -->|obj| 7
            3 --> 8
            8 -->|pred| 9
            8 -->|obj| 10
            3 --> 11
            11 -->|pred| 12
            11 -->|obj| 13
            3 --> 14
            14 -->|pred| 15
            14 -->|obj| 16
            3 --> 17
            17 -->|pred| 18
            17 -->|obj| 19
            3 --> 20
            20 -->|pred| 21
            20 -->|obj| 22
            3 --> 23
            23 -->|pred| 24
            23 -->|obj| 25
            3 --> 26
            26 -->|pred| 27
            26 -->|obj| 28
            3 --> 29
            29 -->|pred| 30
            29 -->|obj| 31
            3 --> 32
            32 -->|pred| 33
            32 -->|obj| 34
            3 --> 35
            35 -->|pred| 36
            35 -->|obj| 37
            3 --> 38
            38 -->|pred| 39
            38 -->|obj| 40
            3 --> 41
            41 -->|pred| 42
            41 -->|obj| 43
            1 --> 44
            44 -->|pred| 45
            44 -->|obj| 46
            1 --> 47
            47 -->|pred| 48
            47 -->|obj| 49
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:#55f,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:red,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:red,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            style 14 stroke:red,stroke-width:3.0px
            style 15 stroke:#55f,stroke-width:3.0px
            style 16 stroke:#55f,stroke-width:3.0px
            style 17 stroke:red,stroke-width:3.0px
            style 18 stroke:#55f,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:red,stroke-width:3.0px
            style 27 stroke:#55f,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:red,stroke-width:3.0px
            style 30 stroke:#55f,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:red,stroke-width:3.0px
            style 33 stroke:#55f,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:red,stroke-width:3.0px
            style 36 stroke:#55f,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:red,stroke-width:3.0px
            style 39 stroke:#55f,stroke-width:3.0px
            style 40 stroke:#55f,stroke-width:3.0px
            style 41 stroke:red,stroke-width:3.0px
            style 42 stroke:#55f,stroke-width:3.0px
            style 43 stroke:#55f,stroke-width:3.0px
            style 44 stroke:red,stroke-width:3.0px
            style 45 stroke:#55f,stroke-width:3.0px
            style 46 stroke:#55f,stroke-width:3.0px
            style 47 stroke:red,stroke-width:3.0px
            style 48 stroke:#55f,stroke-width:3.0px
            style 49 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke:red,stroke-width:2.0px
            linkStyle 2 stroke:red,stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke:green,stroke-width:2.0px
            linkStyle 5 stroke:#55f,stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke:green,stroke-width:2.0px
            linkStyle 8 stroke:#55f,stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke:green,stroke-width:2.0px
            linkStyle 11 stroke:#55f,stroke-width:2.0px
            linkStyle 12 stroke-width:2.0px
            linkStyle 13 stroke:green,stroke-width:2.0px
            linkStyle 14 stroke:#55f,stroke-width:2.0px
            linkStyle 15 stroke-width:2.0px
            linkStyle 16 stroke:green,stroke-width:2.0px
            linkStyle 17 stroke:#55f,stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke:green,stroke-width:2.0px
            linkStyle 20 stroke:#55f,stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke:green,stroke-width:2.0px
            linkStyle 23 stroke:#55f,stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke:green,stroke-width:2.0px
            linkStyle 26 stroke:#55f,stroke-width:2.0px
            linkStyle 27 stroke-width:2.0px
            linkStyle 28 stroke:green,stroke-width:2.0px
            linkStyle 29 stroke:#55f,stroke-width:2.0px
            linkStyle 30 stroke-width:2.0px
            linkStyle 31 stroke:green,stroke-width:2.0px
            linkStyle 32 stroke:#55f,stroke-width:2.0px
            linkStyle 33 stroke-width:2.0px
            linkStyle 34 stroke:green,stroke-width:2.0px
            linkStyle 35 stroke:#55f,stroke-width:2.0px
            linkStyle 36 stroke-width:2.0px
            linkStyle 37 stroke:green,stroke-width:2.0px
            linkStyle 38 stroke:#55f,stroke-width:2.0px
            linkStyle 39 stroke-width:2.0px
            linkStyle 40 stroke:green,stroke-width:2.0px
            linkStyle 41 stroke:#55f,stroke-width:2.0px
            linkStyle 42 stroke-width:2.0px
            linkStyle 43 stroke:green,stroke-width:2.0px
            linkStyle 44 stroke:#55f,stroke-width:2.0px
            linkStyle 45 stroke-width:2.0px
            linkStyle 46 stroke:green,stroke-width:2.0px
            linkStyle 47 stroke:#55f,stroke-width:2.0px
        """#)
        XCTAssertEqual(Self.credential.mermaidFormat(hideNodes: true),
        #"""
        graph LR
            1[/"WRAPPED"\]
            2["CID(4676635a)"]
            3(["ASSERTION"])
            4["#quot;certificateNumber#quot;"]
            5["#quot;123-456-789#quot;"]
            6(["ASSERTION"])
            7["#quot;expirationDate#quot;"]
            8["2028-01-01"]
            9(["ASSERTION"])
            10["#quot;lastName#quot;"]
            11["#quot;Maxwell#quot;"]
            12(["ASSERTION"])
            13["#quot;issueDate#quot;"]
            14["2020-01-01"]
            15(["ASSERTION"])
            16["#quot;photo#quot;"]
            17["#quot;This is James Maxwell's photo.#quot;"]
            18(["ASSERTION"])
            19["#quot;professionalDevelopmentHours#quot;"]
            20["15"]
            21(["ASSERTION"])
            22["#quot;firstName#quot;"]
            23["#quot;James#quot;"]
            24(["ASSERTION"])
            25["#quot;topics#quot;"]
            26["[#quot;Subject 1#quot;, #quot;Subject 2#quot;]"]
            27(["ASSERTION"])
            28["#quot;continuingEducationUnits#quot;"]
            29["1"]
            30(["ASSERTION"])
            31[/"isA"/]
            32["#quot;Certificate of Completion#quot;"]
            33(["ASSERTION"])
            34["#quot;subject#quot;"]
            35["#quot;RF and Microwave Engineering#quot;"]
            36(["ASSERTION"])
            37[/"controller"/]
            38["#quot;Example Electrical Engineering Board#quot;"]
            39(["ASSERTION"])
            40[/"issuer"/]
            41["#quot;Example Electrical Engineering Board#quot;"]
            42(["ASSERTION"])
            43[/"verifiedBy"/]
            44["Signature"]
            45(["ASSERTION"])
            46[/"note"/]
            47["#quot;Signed by Example Electrical Engineering…#quot;"]
            1 --> 2
            2 --> 3
            3 --> 4
            3 --> 5
            2 --> 6
            6 --> 7
            6 --> 8
            2 --> 9
            9 --> 10
            9 --> 11
            2 --> 12
            12 --> 13
            12 --> 14
            2 --> 15
            15 --> 16
            15 --> 17
            2 --> 18
            18 --> 19
            18 --> 20
            2 --> 21
            21 --> 22
            21 --> 23
            2 --> 24
            24 --> 25
            24 --> 26
            2 --> 27
            27 --> 28
            27 --> 29
            2 --> 30
            30 --> 31
            30 --> 32
            2 --> 33
            33 --> 34
            33 --> 35
            2 --> 36
            36 --> 37
            36 --> 38
            2 --> 39
            39 --> 40
            39 --> 41
            1 --> 42
            42 --> 43
            42 --> 44
            1 --> 45
            45 --> 46
            45 --> 47
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:#55f,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            style 12 stroke:red,stroke-width:3.0px
            style 13 stroke:#55f,stroke-width:3.0px
            style 14 stroke:#55f,stroke-width:3.0px
            style 15 stroke:red,stroke-width:3.0px
            style 16 stroke:#55f,stroke-width:3.0px
            style 17 stroke:#55f,stroke-width:3.0px
            style 18 stroke:red,stroke-width:3.0px
            style 19 stroke:#55f,stroke-width:3.0px
            style 20 stroke:#55f,stroke-width:3.0px
            style 21 stroke:red,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:#55f,stroke-width:3.0px
            style 24 stroke:red,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:#55f,stroke-width:3.0px
            style 27 stroke:red,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:#55f,stroke-width:3.0px
            style 30 stroke:red,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:#55f,stroke-width:3.0px
            style 33 stroke:red,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:#55f,stroke-width:3.0px
            style 36 stroke:red,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:#55f,stroke-width:3.0px
            style 39 stroke:red,stroke-width:3.0px
            style 40 stroke:#55f,stroke-width:3.0px
            style 41 stroke:#55f,stroke-width:3.0px
            style 42 stroke:red,stroke-width:3.0px
            style 43 stroke:#55f,stroke-width:3.0px
            style 44 stroke:#55f,stroke-width:3.0px
            style 45 stroke:red,stroke-width:3.0px
            style 46 stroke:#55f,stroke-width:3.0px
            style 47 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke-width:2.0px
            linkStyle 13 stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke-width:2.0px
            linkStyle 16 stroke-width:2.0px
            linkStyle 17 stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke-width:2.0px
            linkStyle 20 stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke-width:2.0px
            linkStyle 23 stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke-width:2.0px
            linkStyle 26 stroke-width:2.0px
            linkStyle 27 stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke-width:2.0px
            linkStyle 30 stroke-width:2.0px
            linkStyle 31 stroke-width:2.0px
            linkStyle 32 stroke-width:2.0px
            linkStyle 33 stroke-width:2.0px
            linkStyle 34 stroke-width:2.0px
            linkStyle 35 stroke-width:2.0px
            linkStyle 36 stroke-width:2.0px
            linkStyle 37 stroke-width:2.0px
            linkStyle 38 stroke-width:2.0px
            linkStyle 39 stroke-width:2.0px
            linkStyle 40 stroke-width:2.0px
            linkStyle 41 stroke-width:2.0px
            linkStyle 42 stroke-width:2.0px
            linkStyle 43 stroke-width:2.0px
            linkStyle 44 stroke-width:2.0px
            linkStyle 45 stroke-width:2.0px
        """#)
    }
    
    func testRedactedCredential() throws {
        let credential = Self.credential
        var target: Set<Digest> = []
        target.insert(credential)
        for assertion in credential.assertions {
            target.insert(assertion.deepDigests)
        }
        target.insert(credential.subject)
        let content = try credential.subject.unwrap()
        target.insert(content)
        target.insert(content.subject)
        target.insert(try content.assertion(withPredicate: "firstName").shallowDigests)
        target.insert(try content.assertion(withPredicate: "lastName").shallowDigests)
        target.insert(try content.assertion(withPredicate: .isA).shallowDigests)
        target.insert(try content.assertion(withPredicate: .issuer).shallowDigests)
        target.insert(try content.assertion(withPredicate: "subject").shallowDigests)
        target.insert(try content.assertion(withPredicate: "expirationDate").shallowDigests)
        let redactedCredential = credential.elideRevealing(target)
        let warranty = try redactedCredential
            .wrap()
            .addAssertion("employeeHiredDate", Date(iso8601: "2022-01-01"))
            .addAssertion("employeeStatus", "active")
            .wrap()
            .addAssertion(.note, "Signed by Employer Corp.")
            .sign(with: bobPrivateKeys, randomGenerator: generateFakeRandomNumbers)
            .checkEncoding()
        XCTAssertEqual(warranty.format(),
        """
        {
            {
                {
                    CID(4676635a) [
                        "expirationDate": 2028-01-01
                        "firstName": "James"
                        "lastName": "Maxwell"
                        "subject": "RF and Microwave Engineering"
                        isA: "Certificate of Completion"
                        issuer: "Example Electrical Engineering Board"
                        ELIDED (7)
                    ]
                } [
                    note: "Signed by Example Electrical Engineering Board"
                    verifiedBy: Signature
                ]
            } [
                "employeeHiredDate": 2022-01-01
                "employeeStatus": "active"
            ]
        } [
            note: "Signed by Employer Corp."
            verifiedBy: Signature
        ]
        """)
        XCTAssertEqual(warranty.treeFormat(),
        """
        204c1cc5 NODE
            6ef5d69b subj WRAPPED
                08c5bd4a subj NODE
                    bb862fc3 subj WRAPPED
                        e1335c97 subj NODE
                            5886e784 subj WRAPPED
                                c9860567 subj NODE
                                    5fb45cf1 subj CID(4676635a)
                                    1f9ff098 ELIDED
                                    36c254d0 ASSERTION
                                        6e5d379f pred "expirationDate"
                                        639ae9bf obj 2028-01-01
                                    3c114201 ASSERTION
                                        5f82a16a pred "lastName"
                                        fe4d5230 obj "Maxwell"
                                    4a9b2e4d ELIDED
                                    5171cbaf ELIDED
                                    54b3e1e7 ELIDED
                                    5dc6d4e3 ASSERTION
                                        4395643b pred "firstName"
                                        d6d0b768 obj "James"
                                    68895d8e ELIDED
                                    8ec5e912 ELIDED
                                    922c859a ASSERTION
                                        96f0167d pred isA
                                        051beee6 obj "Certificate of Completion"
                                    caf5ced3 ASSERTION
                                        8e4e62eb pred "subject"
                                        202c10ef obj "RF and Microwave Engineering"
                                    d61e0984 ELIDED
                                    ebcbf71f ASSERTION
                                        fde30b5c pred issuer
                                        f8489ac1 obj "Example Electrical Engineering Board"
                            4025e72d ASSERTION
                                9d7ba9eb pred verifiedBy
                                73316b2b obj Signature
                            55b14b17 ASSERTION
                                49a5f41b pred note
                                f106bad1 obj "Signed by Example Electrical Engineering…"
                    4c159c16 ASSERTION
                        e1ae011e pred "employeeHiredDate"
                        13b5a817 obj 2022-01-01
                    e071508b ASSERTION
                        d03e7352 pred "employeeStatus"
                        1d7a790d obj "active"
            8f255569 ASSERTION
                49a5f41b pred note
                f59806d2 obj "Signed by Employer Corp."
            a9973eab ASSERTION
                9d7ba9eb pred verifiedBy
                a05ce2dc obj Signature
        """)
        XCTAssertEqual(warranty.treeFormat(hideNodes: true),
        """
        WRAPPED
            WRAPPED
                WRAPPED
                    CID(4676635a)
                        ELIDED
                        ASSERTION
                            "expirationDate"
                            2028-01-01
                        ASSERTION
                            "lastName"
                            "Maxwell"
                        ELIDED
                        ELIDED
                        ELIDED
                        ASSERTION
                            "firstName"
                            "James"
                        ELIDED
                        ELIDED
                        ASSERTION
                            isA
                            "Certificate of Completion"
                        ASSERTION
                            "subject"
                            "RF and Microwave Engineering"
                        ELIDED
                        ASSERTION
                            issuer
                            "Example Electrical Engineering Board"
                    ASSERTION
                        verifiedBy
                        Signature
                    ASSERTION
                        note
                        "Signed by Example Electrical Engineering…"
                ASSERTION
                    "employeeHiredDate"
                    2022-01-01
                ASSERTION
                    "employeeStatus"
                    "active"
            ASSERTION
                note
                "Signed by Employer Corp."
            ASSERTION
                verifiedBy
                Signature
        """)
        XCTAssertEqual(warranty.elementsCount, warranty.treeFormat().split(separator: "\n").count)
        XCTAssertEqual(warranty.mermaidFormat(),
        #"""
        graph LR
            1(("204c1cc5<br/>NODE"))
            2[/"6ef5d69b<br/>WRAPPED"\]
            3(("08c5bd4a<br/>NODE"))
            4[/"bb862fc3<br/>WRAPPED"\]
            5(("e1335c97<br/>NODE"))
            6[/"5886e784<br/>WRAPPED"\]
            7(("c9860567<br/>NODE"))
            8["5fb45cf1<br/>CID(4676635a)"]
            9{{"1f9ff098<br/>ELIDED"}}
            10(["36c254d0<br/>ASSERTION"])
            11["6e5d379f<br/>#quot;expirationDate#quot;"]
            12["639ae9bf<br/>2028-01-01"]
            13(["3c114201<br/>ASSERTION"])
            14["5f82a16a<br/>#quot;lastName#quot;"]
            15["fe4d5230<br/>#quot;Maxwell#quot;"]
            16{{"4a9b2e4d<br/>ELIDED"}}
            17{{"5171cbaf<br/>ELIDED"}}
            18{{"54b3e1e7<br/>ELIDED"}}
            19(["5dc6d4e3<br/>ASSERTION"])
            20["4395643b<br/>#quot;firstName#quot;"]
            21["d6d0b768<br/>#quot;James#quot;"]
            22{{"68895d8e<br/>ELIDED"}}
            23{{"8ec5e912<br/>ELIDED"}}
            24(["922c859a<br/>ASSERTION"])
            25[/"96f0167d<br/>isA"/]
            26["051beee6<br/>#quot;Certificate of Completion#quot;"]
            27(["caf5ced3<br/>ASSERTION"])
            28["8e4e62eb<br/>#quot;subject#quot;"]
            29["202c10ef<br/>#quot;RF and Microwave Engineering#quot;"]
            30{{"d61e0984<br/>ELIDED"}}
            31(["ebcbf71f<br/>ASSERTION"])
            32[/"fde30b5c<br/>issuer"/]
            33["f8489ac1<br/>#quot;Example Electrical Engineering Board#quot;"]
            34(["4025e72d<br/>ASSERTION"])
            35[/"9d7ba9eb<br/>verifiedBy"/]
            36["73316b2b<br/>Signature"]
            37(["55b14b17<br/>ASSERTION"])
            38[/"49a5f41b<br/>note"/]
            39["f106bad1<br/>#quot;Signed by Example Electrical Engineering…#quot;"]
            40(["4c159c16<br/>ASSERTION"])
            41["e1ae011e<br/>#quot;employeeHiredDate#quot;"]
            42["13b5a817<br/>2022-01-01"]
            43(["e071508b<br/>ASSERTION"])
            44["d03e7352<br/>#quot;employeeStatus#quot;"]
            45["1d7a790d<br/>#quot;active#quot;"]
            46(["8f255569<br/>ASSERTION"])
            47[/"49a5f41b<br/>note"/]
            48["f59806d2<br/>#quot;Signed by Employer Corp.#quot;"]
            49(["a9973eab<br/>ASSERTION"])
            50[/"9d7ba9eb<br/>verifiedBy"/]
            51["a05ce2dc<br/>Signature"]
            1 -->|subj| 2
            2 -->|subj| 3
            3 -->|subj| 4
            4 -->|subj| 5
            5 -->|subj| 6
            6 -->|subj| 7
            7 -->|subj| 8
            7 --> 9
            7 --> 10
            10 -->|pred| 11
            10 -->|obj| 12
            7 --> 13
            13 -->|pred| 14
            13 -->|obj| 15
            7 --> 16
            7 --> 17
            7 --> 18
            7 --> 19
            19 -->|pred| 20
            19 -->|obj| 21
            7 --> 22
            7 --> 23
            7 --> 24
            24 -->|pred| 25
            24 -->|obj| 26
            7 --> 27
            27 -->|pred| 28
            27 -->|obj| 29
            7 --> 30
            7 --> 31
            31 -->|pred| 32
            31 -->|obj| 33
            5 --> 34
            34 -->|pred| 35
            34 -->|obj| 36
            5 --> 37
            37 -->|pred| 38
            37 -->|obj| 39
            3 --> 40
            40 -->|pred| 41
            40 -->|obj| 42
            3 --> 43
            43 -->|pred| 44
            43 -->|obj| 45
            1 --> 46
            46 -->|pred| 47
            46 -->|obj| 48
            1 --> 49
            49 -->|pred| 50
            49 -->|obj| 51
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:red,stroke-width:3.0px
            style 5 stroke:red,stroke-width:3.0px
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:red,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 10 stroke:red,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px
            style 13 stroke:red,stroke-width:3.0px
            style 14 stroke:#55f,stroke-width:3.0px
            style 15 stroke:#55f,stroke-width:3.0px
            style 16 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 17 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 18 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 19 stroke:red,stroke-width:3.0px
            style 20 stroke:#55f,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 23 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 24 stroke:red,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:#55f,stroke-width:3.0px
            style 27 stroke:red,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:#55f,stroke-width:3.0px
            style 30 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 31 stroke:red,stroke-width:3.0px
            style 32 stroke:#55f,stroke-width:3.0px
            style 33 stroke:#55f,stroke-width:3.0px
            style 34 stroke:red,stroke-width:3.0px
            style 35 stroke:#55f,stroke-width:3.0px
            style 36 stroke:#55f,stroke-width:3.0px
            style 37 stroke:red,stroke-width:3.0px
            style 38 stroke:#55f,stroke-width:3.0px
            style 39 stroke:#55f,stroke-width:3.0px
            style 40 stroke:red,stroke-width:3.0px
            style 41 stroke:#55f,stroke-width:3.0px
            style 42 stroke:#55f,stroke-width:3.0px
            style 43 stroke:red,stroke-width:3.0px
            style 44 stroke:#55f,stroke-width:3.0px
            style 45 stroke:#55f,stroke-width:3.0px
            style 46 stroke:red,stroke-width:3.0px
            style 47 stroke:#55f,stroke-width:3.0px
            style 48 stroke:#55f,stroke-width:3.0px
            style 49 stroke:red,stroke-width:3.0px
            style 50 stroke:#55f,stroke-width:3.0px
            style 51 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke:red,stroke-width:2.0px
            linkStyle 1 stroke:red,stroke-width:2.0px
            linkStyle 2 stroke:red,stroke-width:2.0px
            linkStyle 3 stroke:red,stroke-width:2.0px
            linkStyle 4 stroke:red,stroke-width:2.0px
            linkStyle 5 stroke:red,stroke-width:2.0px
            linkStyle 6 stroke:red,stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
            linkStyle 9 stroke:green,stroke-width:2.0px
            linkStyle 10 stroke:#55f,stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke:green,stroke-width:2.0px
            linkStyle 13 stroke:#55f,stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke-width:2.0px
            linkStyle 16 stroke-width:2.0px
            linkStyle 17 stroke-width:2.0px
            linkStyle 18 stroke:green,stroke-width:2.0px
            linkStyle 19 stroke:#55f,stroke-width:2.0px
            linkStyle 20 stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke-width:2.0px
            linkStyle 23 stroke:green,stroke-width:2.0px
            linkStyle 24 stroke:#55f,stroke-width:2.0px
            linkStyle 25 stroke-width:2.0px
            linkStyle 26 stroke:green,stroke-width:2.0px
            linkStyle 27 stroke:#55f,stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke-width:2.0px
            linkStyle 30 stroke:green,stroke-width:2.0px
            linkStyle 31 stroke:#55f,stroke-width:2.0px
            linkStyle 32 stroke-width:2.0px
            linkStyle 33 stroke:green,stroke-width:2.0px
            linkStyle 34 stroke:#55f,stroke-width:2.0px
            linkStyle 35 stroke-width:2.0px
            linkStyle 36 stroke:green,stroke-width:2.0px
            linkStyle 37 stroke:#55f,stroke-width:2.0px
            linkStyle 38 stroke-width:2.0px
            linkStyle 39 stroke:green,stroke-width:2.0px
            linkStyle 40 stroke:#55f,stroke-width:2.0px
            linkStyle 41 stroke-width:2.0px
            linkStyle 42 stroke:green,stroke-width:2.0px
            linkStyle 43 stroke:#55f,stroke-width:2.0px
            linkStyle 44 stroke-width:2.0px
            linkStyle 45 stroke:green,stroke-width:2.0px
            linkStyle 46 stroke:#55f,stroke-width:2.0px
            linkStyle 47 stroke-width:2.0px
            linkStyle 48 stroke:green,stroke-width:2.0px
            linkStyle 49 stroke:#55f,stroke-width:2.0px
        """#)
        XCTAssertEqual(warranty.mermaidFormat(hideNodes: true),
        #"""
        graph LR
            1[/"WRAPPED"\]
            2[/"WRAPPED"\]
            3[/"WRAPPED"\]
            4["CID(4676635a)"]
            5{{"ELIDED"}}
            6(["ASSERTION"])
            7["#quot;expirationDate#quot;"]
            8["2028-01-01"]
            9(["ASSERTION"])
            10["#quot;lastName#quot;"]
            11["#quot;Maxwell#quot;"]
            12{{"ELIDED"}}
            13{{"ELIDED"}}
            14{{"ELIDED"}}
            15(["ASSERTION"])
            16["#quot;firstName#quot;"]
            17["#quot;James#quot;"]
            18{{"ELIDED"}}
            19{{"ELIDED"}}
            20(["ASSERTION"])
            21[/"isA"/]
            22["#quot;Certificate of Completion#quot;"]
            23(["ASSERTION"])
            24["#quot;subject#quot;"]
            25["#quot;RF and Microwave Engineering#quot;"]
            26{{"ELIDED"}}
            27(["ASSERTION"])
            28[/"issuer"/]
            29["#quot;Example Electrical Engineering Board#quot;"]
            30(["ASSERTION"])
            31[/"verifiedBy"/]
            32["Signature"]
            33(["ASSERTION"])
            34[/"note"/]
            35["#quot;Signed by Example Electrical Engineering…#quot;"]
            36(["ASSERTION"])
            37["#quot;employeeHiredDate#quot;"]
            38["2022-01-01"]
            39(["ASSERTION"])
            40["#quot;employeeStatus#quot;"]
            41["#quot;active#quot;"]
            42(["ASSERTION"])
            43[/"note"/]
            44["#quot;Signed by Employer Corp.#quot;"]
            45(["ASSERTION"])
            46[/"verifiedBy"/]
            47["Signature"]
            1 --> 2
            2 --> 3
            3 --> 4
            4 --> 5
            4 --> 6
            6 --> 7
            6 --> 8
            4 --> 9
            9 --> 10
            9 --> 11
            4 --> 12
            4 --> 13
            4 --> 14
            4 --> 15
            15 --> 16
            15 --> 17
            4 --> 18
            4 --> 19
            4 --> 20
            20 --> 21
            20 --> 22
            4 --> 23
            23 --> 24
            23 --> 25
            4 --> 26
            4 --> 27
            27 --> 28
            27 --> 29
            3 --> 30
            30 --> 31
            30 --> 32
            3 --> 33
            33 --> 34
            33 --> 35
            2 --> 36
            36 --> 37
            36 --> 38
            2 --> 39
            39 --> 40
            39 --> 41
            1 --> 42
            42 --> 43
            42 --> 44
            1 --> 45
            45 --> 46
            45 --> 47
            style 1 stroke:red,stroke-width:3.0px
            style 2 stroke:red,stroke-width:3.0px
            style 3 stroke:red,stroke-width:3.0px
            style 4 stroke:#55f,stroke-width:3.0px
            style 5 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 6 stroke:red,stroke-width:3.0px
            style 7 stroke:#55f,stroke-width:3.0px
            style 8 stroke:#55f,stroke-width:3.0px
            style 9 stroke:red,stroke-width:3.0px
            style 10 stroke:#55f,stroke-width:3.0px
            style 11 stroke:#55f,stroke-width:3.0px
            style 12 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 13 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 14 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 15 stroke:red,stroke-width:3.0px
            style 16 stroke:#55f,stroke-width:3.0px
            style 17 stroke:#55f,stroke-width:3.0px
            style 18 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 19 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 20 stroke:red,stroke-width:3.0px
            style 21 stroke:#55f,stroke-width:3.0px
            style 22 stroke:#55f,stroke-width:3.0px
            style 23 stroke:red,stroke-width:3.0px
            style 24 stroke:#55f,stroke-width:3.0px
            style 25 stroke:#55f,stroke-width:3.0px
            style 26 stroke:#55f,stroke-width:3.0px,stroke-dasharray:5.0 5.0
            style 27 stroke:red,stroke-width:3.0px
            style 28 stroke:#55f,stroke-width:3.0px
            style 29 stroke:#55f,stroke-width:3.0px
            style 30 stroke:red,stroke-width:3.0px
            style 31 stroke:#55f,stroke-width:3.0px
            style 32 stroke:#55f,stroke-width:3.0px
            style 33 stroke:red,stroke-width:3.0px
            style 34 stroke:#55f,stroke-width:3.0px
            style 35 stroke:#55f,stroke-width:3.0px
            style 36 stroke:red,stroke-width:3.0px
            style 37 stroke:#55f,stroke-width:3.0px
            style 38 stroke:#55f,stroke-width:3.0px
            style 39 stroke:red,stroke-width:3.0px
            style 40 stroke:#55f,stroke-width:3.0px
            style 41 stroke:#55f,stroke-width:3.0px
            style 42 stroke:red,stroke-width:3.0px
            style 43 stroke:#55f,stroke-width:3.0px
            style 44 stroke:#55f,stroke-width:3.0px
            style 45 stroke:red,stroke-width:3.0px
            style 46 stroke:#55f,stroke-width:3.0px
            style 47 stroke:#55f,stroke-width:3.0px
            linkStyle 0 stroke-width:2.0px
            linkStyle 1 stroke-width:2.0px
            linkStyle 2 stroke-width:2.0px
            linkStyle 3 stroke-width:2.0px
            linkStyle 4 stroke-width:2.0px
            linkStyle 5 stroke-width:2.0px
            linkStyle 6 stroke-width:2.0px
            linkStyle 7 stroke-width:2.0px
            linkStyle 8 stroke-width:2.0px
            linkStyle 9 stroke-width:2.0px
            linkStyle 10 stroke-width:2.0px
            linkStyle 11 stroke-width:2.0px
            linkStyle 12 stroke-width:2.0px
            linkStyle 13 stroke-width:2.0px
            linkStyle 14 stroke-width:2.0px
            linkStyle 15 stroke-width:2.0px
            linkStyle 16 stroke-width:2.0px
            linkStyle 17 stroke-width:2.0px
            linkStyle 18 stroke-width:2.0px
            linkStyle 19 stroke-width:2.0px
            linkStyle 20 stroke-width:2.0px
            linkStyle 21 stroke-width:2.0px
            linkStyle 22 stroke-width:2.0px
            linkStyle 23 stroke-width:2.0px
            linkStyle 24 stroke-width:2.0px
            linkStyle 25 stroke-width:2.0px
            linkStyle 26 stroke-width:2.0px
            linkStyle 27 stroke-width:2.0px
            linkStyle 28 stroke-width:2.0px
            linkStyle 29 stroke-width:2.0px
            linkStyle 30 stroke-width:2.0px
            linkStyle 31 stroke-width:2.0px
            linkStyle 32 stroke-width:2.0px
            linkStyle 33 stroke-width:2.0px
            linkStyle 34 stroke-width:2.0px
            linkStyle 35 stroke-width:2.0px
            linkStyle 36 stroke-width:2.0px
            linkStyle 37 stroke-width:2.0px
            linkStyle 38 stroke-width:2.0px
            linkStyle 39 stroke-width:2.0px
            linkStyle 40 stroke-width:2.0px
            linkStyle 41 stroke-width:2.0px
            linkStyle 42 stroke-width:2.0px
            linkStyle 43 stroke-width:2.0px
            linkStyle 44 stroke-width:2.0px
            linkStyle 45 stroke-width:2.0px
        """#)
        print(warranty.hex(annotate: true, context: formatContext))
    }
}
