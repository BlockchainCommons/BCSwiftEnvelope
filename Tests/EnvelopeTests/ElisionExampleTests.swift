import Testing
import SecureComponents
import Envelope
import WolfBase
import Foundation

struct ElisionExampleTests {
    @Test func testRedactionExample2() throws {
        var rng = makeFakeRandomNumberGenerator()
        let credential = try Envelope(ARID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
            .addType("Certificate of Completion")
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
            .sign(with: alicePrivateKeys, using: &rng)
            .addAssertion(.note, "Signed by Example Electrical Engineering Board")
            .checkEncoding()
        #expect(credential.ur† == "ur:envelope/lstpspmntpsotansgshdcxfgkoiahtjthnissawsfhzcmyyldsutfzcttefpaxjtmobsbwimcaleykvsdtgajnoytpsojsiaihjpjyiniyiniahsjyihglkpjnidihjptpsojeeheyeodpeeecendpemetesoytpsojtihksjoinjphsjyinjljtfyhsjyihtpsosecyjncscxaeoytpsoisjzhsjkjyglhsjnihtpsoiogthsksktihjzjzoytpsoininjkjkkpihfyhsjyihtpsosecyhybdvyaeoyadtpsokscffxihjpjyiniyiniahsjyihcxjliycxfxjljnjojzihjyinjljtoytpsoihjoisjljyjltpsoksckghisinjkcxinjkcxgehsjnihjkcxgthsksktihjzjzdijkcxjoisjljyjldmoytpsokscejojpjliyihjkjkinjljthsjzfyihkoihjzjljojnihjtjyfdjlkpjpjktpsobsoytpsoiniyinjpjkjyglhsjnihtpsoihgehsjnihjkoytpsoiyjyjljoiniajktpsolfingukpidimihiajycxehingukpidimihiajycxeyoytpsokscsiajljtjyinjtkpinjtiofeiekpiahsjyinjljtgojtinjyjktpsoadoyattpsoksdkfekshsjnjojzihcxfejzihiajyjpiniahsjzcxfejtioinjtihihjpinjtiocxfwjlhsjpieoytpsoiojkkpidimihiajytpsokscegmfgcxhsjtiecxgtiniajpjlkthskoihcxfejtioinjtihihjpinjtiooybttpsoksdkfekshsjnjojzihcxfejzihiajyjpiniahsjzcxfejtioinjtihihjpinjtiocxfwjlhsjpieoyaxtpsotansghhdfzcebwzmctresbkockbnpekbfdgtflsrzcplkozslbhkkelgasihqzjkdetkdspdlnsbrltnaozorkhpsgesoydyoejeuonbnbiswltegaioencpnycltdrelrwsrklkttoyaatpsoksdmguiniojtihiecxidkkcxfekshsjnjojzihcxfejzihiajyjpiniahsjzcxfejtioinjtihihjpinjtiocxfwjlhsjpiechcetahn")
        #expect(credential.format() ==
        """
        {
            ARID(4676635a) [
                'isA': "Certificate of Completion"
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
                'controller': "Example Electrical Engineering Board"
                'issuer': "Example Electrical Engineering Board"
            ]
        } [
            'note': "Signed by Example Electrical Engineering Board"
            'verifiedBy': Signature
        ]
        """)
        
        var target: Set<Digest> = []
        
        /// With an empty target, the entire document is elided.
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            ELIDED
            """
            )
        }
        
        /// By adding the top-level digest of the document, its macro structure is revealed. The subject of the document is the drivers license proper. The two assertions are the `.note` and `.verifiedBy` assertions.
        target.insert(credential)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            ELIDED [
                ELIDED (2)
            ]
            """
            )
        }
        
        /// We add the complete hierarchy of digests that comprise all the assertions on the document. This reveals the signature.
        for assertion in credential.assertions {
            target.insert(assertion.deepDigests)
        }
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            ELIDED [
                'note': "Signed by Example Electrical Engineering Board"
                'verifiedBy': Signature
            ]
            """
            )
        }
        
        /// We insert the digest of the document's subject. The subject is a wrapped envelope, which is still elided.
        target.insert(credential.subject)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            {
                ELIDED
            } [
                'note': "Signed by Example Electrical Engineering Board"
                'verifiedBy': Signature
            ]
            """
            )
        }

        /// We insert the digest of the wrapped envelope, revealing its macro structure. This is the actual content of the document.
        let content = try credential.subject.unwrap()
        target.insert(content)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            {
                ELIDED [
                    ELIDED (13)
                ]
            } [
                'note': "Signed by Example Electrical Engineering Board"
                'verifiedBy': Signature
            ]
            """
            )
        }
        
        /// We insert the digest of the wrapped envelope's subject, revealing the employee's ARID according to the certifying agency.
        target.insert(content.subject)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            {
                ARID(4676635a) [
                    ELIDED (13)
                ]
            } [
                'note': "Signed by Example Electrical Engineering Board"
                'verifiedBy': Signature
            ]
            """
            )
        }

        /// The only actual assertions we want to reveal are `firstName`, `lastName`, `.isA`, `issuer`, `subject` and `expirationDate`, so we do this by finding those specific assertions by their predicate. The `shallowDigests` attribute returns just a necessary set of attributes to reveal the assertion, its predicate, and its object (yes, all three of them need to be revealed) but *not* any deeper assertions on them.
        target.insert(try content.assertion(withPredicate: "firstName").shallowDigests)
        target.insert(try content.assertion(withPredicate: "lastName").shallowDigests)
        target.insert(try content.assertion(withPredicate: .isA).shallowDigests)
        target.insert(try content.assertion(withPredicate: .issuer).shallowDigests)
        target.insert(try content.assertion(withPredicate: "subject").shallowDigests)
        target.insert(try content.assertion(withPredicate: "expirationDate").shallowDigests)
        let redactedCredential = credential.elideRevealing(target)
        #expect(redactedCredential.format() ==
        """
        {
            ARID(4676635a) [
                'isA': "Certificate of Completion"
                "expirationDate": 2028-01-01
                "firstName": "James"
                "lastName": "Maxwell"
                "subject": "RF and Microwave Engineering"
                'issuer': "Example Electrical Engineering Board"
                ELIDED (7)
            ]
        } [
            'note': "Signed by Example Electrical Engineering Board"
            'verifiedBy': Signature
        ]
        """
        )
        
        let warranty = try redactedCredential
            .wrap()
            .addAssertion("employeeHiredDate", Date(iso8601: "2022-01-01"))
            .addAssertion("employeeStatus", "active")
            .wrap()
            .addAssertion(.note, "Signed by Employer Corp.")
            .sign(with: bobPrivateKeys)
            .checkEncoding()
        #expect(warranty.format() ==
        """
        {
            {
                {
                    ARID(4676635a) [
                        'isA': "Certificate of Completion"
                        "expirationDate": 2028-01-01
                        "firstName": "James"
                        "lastName": "Maxwell"
                        "subject": "RF and Microwave Engineering"
                        'issuer': "Example Electrical Engineering Board"
                        ELIDED (7)
                    ]
                } [
                    'note': "Signed by Example Electrical Engineering Board"
                    'verifiedBy': Signature
                ]
            } [
                "employeeHiredDate": 2022-01-01
                "employeeStatus": "active"
            ]
        } [
            'note': "Signed by Employer Corp."
            'verifiedBy': Signature
        ]
        """
        )
        
        let edits = credential.diff(target: warranty)
//        print(credential.cborData.count)
//        print(warranty.cborData.count)
//        print(edits.cborData.count)
//        print(edits.format())
        #expect(try credential.transform(edits: edits).isIdentical(to: warranty))
    }
    
    @Test func testRedactionExample() throws {
        let credential = try Envelope(ARID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
            .addAssertion("firstName", "John")
            .addAssertion("lastName", "Smith")
            .addAssertion("address", "123 Main St.")
            .addAssertion("birthDate", Date(iso8601: "1970-01-01"))
            .addAssertion("photo", "This is John Smith's photo.")
            .addAssertion("dlNumber", "123-456-789")
            .addAssertion("nonCommercialVehicleEndorsement", true)
            .addAssertion("motorocycleEndorsement", true)
            .addAssertion(.issuer, "State of Example")
            .addAssertion(.controller, "State of Example")
            .wrap()
            .sign(with: alicePrivateKeys)
            .addAssertion(.note, "Signed by the State of Example")
            .checkEncoding()
        #expect(credential.format() ==
        """
        {
            ARID(4676635a) [
                "address": "123 Main St."
                "birthDate": 1970-01-01
                "dlNumber": "123-456-789"
                "firstName": "John"
                "lastName": "Smith"
                "motorocycleEndorsement": true
                "nonCommercialVehicleEndorsement": true
                "photo": "This is John Smith's photo."
                'controller': "State of Example"
                'issuer': "State of Example"
            ]
        } [
            'note': "Signed by the State of Example"
            'verifiedBy': Signature
        ]
        """
        )
        
        var target: Set<Digest> = []
        
        /// With an empty target, the entire document is elided.
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            ELIDED
            """
            )
        }
        
        /// By adding the top-level digest of the document, its macro structure is revealed. The subject of the document is the drivers license proper. The two assertions are the `.note` and `.verifiedBy` assertions.
        target.insert(credential)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            ELIDED [
                ELIDED (2)
            ]
            """
            )
        }
        
        /// We add the complete hierarchy of digests that comprise all the assertions on the document. This reveals the signature.
        for assertion in credential.assertions {
            target.insert(assertion.deepDigests)
        }
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            ELIDED [
                'note': "Signed by the State of Example"
                'verifiedBy': Signature
            ]
            """
            )
        }
        
        /// We insert the digest of the document's subject. The subject is a wrapped envelope, which is still elided.
        target.insert(credential.subject)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            {
                ELIDED
            } [
                'note': "Signed by the State of Example"
                'verifiedBy': Signature
            ]
            """
            )
        }

        /// We insert the digest of the wrapped envelope, revealing its macro structure. This is the actual content of the document.
        let content = try credential.subject.unwrap()
        target.insert(content)
        with(credential.elideRevealing(target)) {
            #expect($0.format() ==
            """
            {
                ELIDED [
                    ELIDED (10)
                ]
            } [
                'note': "Signed by the State of Example"
                'verifiedBy': Signature
            ]
            """
            )
//            print($0.mermaidFormat())
        }
        
        /// The only actual assertions we want to reveal are `birthDate` and `photo`, so we do this by finding those specific assertions by their predicate. The `shallowDigests` attribute returns just a necessary set of attributes to reveal the assertion, its predicate, and its object (yes, all three of them need to be revealed) but *not* any deeper assertions on them.
        target.insert(try content.assertion(withPredicate: "birthDate").shallowDigests)
        target.insert(try content.assertion(withPredicate: "photo").shallowDigests)
        let redactedCredential = credential.elideRevealing(target)
        #expect(redactedCredential.format() ==
        """
        {
            ELIDED [
                "birthDate": 1970-01-01
                "photo": "This is John Smith's photo."
                ELIDED (8)
            ]
        } [
            'note': "Signed by the State of Example"
            'verifiedBy': Signature
        ]
        """
        )
        
        // print(target.count) // 15
    }
    
    @Test func testPositions() throws {
        let envelope = Envelope("Alice")
            .addAssertion("knows", "Bob")
        #expect(envelope.format() ==
        """
        "Alice" [
            "knows": "Bob"
        ]
        """
        )

        with(try envelope.elideRemoving(envelope).checkEncoding()) { e in
            #expect(e.format() ==
            """
            ELIDED
            """
            )
        }

        let key = SymmetricKey()
        with(try envelope.elideRemoving(envelope, action: .encrypt(key)).checkEncoding()) { e in
            #expect(e.format() ==
            """
            ENCRYPTED
            """
            )
        }

        with(try envelope.elideRemoving(envelope, action: .compress).checkEncoding()) { e in
            #expect(e.format() ==
            """
            COMPRESSED
            """
            )
        }

        with(try envelope.elideRemoving(envelope.subject).checkEncoding()) { e in
            #expect(e.format() ==
            """
            ELIDED [
                "knows": "Bob"
            ]
            """
            )
        }

        with(try envelope.elideRemoving(envelope.subject, action: .encrypt(key)).checkEncoding()) { e in
            #expect(e.format() ==
            """
            ENCRYPTED [
                "knows": "Bob"
            ]
            """
            )
        }

        with(try envelope.elideRemoving(envelope.subject, action: .compress).checkEncoding()) { e in
            #expect(e.format() ==
            """
            COMPRESSED [
                "knows": "Bob"
            ]
            """
            )
        }

        let assertion = envelope.assertions.first!
        with(try envelope.elideRemoving(assertion).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                ELIDED
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion, action: .encrypt(key)).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                ENCRYPTED
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion, action: .compress).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                COMPRESSED
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion.predicate!).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                ELIDED: "Bob"
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion.predicate!, action: .encrypt(key)).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                ENCRYPTED: "Bob"
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion.predicate!, action: .compress).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                COMPRESSED: "Bob"
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion.object!).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                "knows": ELIDED
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion.object!, action: .encrypt(key)).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                "knows": ENCRYPTED
            ]
            """
            )
        }

        with(try envelope.elideRemoving(assertion.object!, action: .compress).checkEncoding()) { e in
            #expect(e.format() ==
            """
            "Alice" [
                "knows": COMPRESSED
            ]
            """
            )
        }
    }
}
