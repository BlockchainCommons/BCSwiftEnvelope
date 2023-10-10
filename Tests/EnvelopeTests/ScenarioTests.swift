import XCTest
import SecureComponents
import Envelope
import WolfBase

class ScenarioTests: XCTestCase {
    func testComplexMetadata() throws {
        // Assertions made about an ARID are considered part of a distributed set. Which
        // assertions are returned depends on who resolves the ARID and when it is
        // resolved. In other words, the referent of an ARID is mutable.
        let author = try Envelope(ARID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .addAssertion(.dereferenceVia, "LibraryOfCongress")
            .addAssertion(.hasName, "Ayn Rand")
            .checkEncoding()

        // Assertions made on a literal value are considered part of the same set of
        // assertions made on the digest of that value.
        let name_en = Envelope("Atlas Shrugged")
            .addAssertion(.language, "en")

        let name_es = Envelope("La rebelión de Atlas")
            .addAssertion(.language, "es")

        let work = try Envelope(ARID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .addType("novel")
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

        let expectedFormat =
        """
        Digest(26d05af5) [
            "format": "EPUB"
            "work": ARID(7fb90a9d) [
                'isA': "novel"
                "author": ARID(9c747ace) [
                    'dereferenceVia': "LibraryOfCongress"
                    'hasName': "Ayn Rand"
                ]
                "isbn": "9780451191144"
                'dereferenceVia': "LibraryOfCongress"
                'hasName': "Atlas Shrugged" [
                    'language': "en"
                ]
                'hasName': "La rebelión de Atlas" [
                    'language': "es"
                ]
            ]
            'dereferenceVia': "IPFS"
        ]
        """
        XCTAssertEqual(bookMetadata.format(), expectedFormat)
    }

    func testIdentifier() throws {
        // An analogue of a DID document, which identifies an entity. The
        // document itself can be referred to by its ARID, while the signed document
        // can be referred to by its digest.

        let aliceUnsignedDocument = try Envelope(aliceIdentifier)
            .addAssertion(.controller, aliceIdentifier)
            .addAssertion(.publicKeys, alicePublicKeys)
            .checkEncoding()

        let aliceSignedDocument = try aliceUnsignedDocument
            .wrap()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
            .checkEncoding()

        let expectedFormat =
        """
        {
            ARID(d44c5e0a) [
                'controller': ARID(d44c5e0a)
                'publicKeys': PublicKeyBase
            ]
        } [
            'verifiedBy': Signature [
                'note': "Made by Alice."
            ]
        ]
        """
//        print(aliceSignedDocument.format())
        XCTAssertEqual(aliceSignedDocument.format(), expectedFormat)

        // Signatures have a random component, so anything with a signature will have a
        // non-deterministic digest. Therefore, the two results of signing the same object
        // twice with the same private key will not compare as equal. This means that each
        // signing is a particular event that can never be repeated.

        let aliceSignedDocument2 = try aliceUnsignedDocument
            .wrap()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
            .checkEncoding()

        XCTAssertFalse(aliceSignedDocument.isEquivalent(to: aliceSignedDocument2))

        // ➡️ ☁️ ➡️

        // A registrar checks the signature on Alice's submitted identifier document,
        // performs any other necessary validity checks, and then extracts her ARID from
        // it.
        let aliceCID = try aliceSignedDocument.verifySignature(from: alicePublicKeys)
            .unwrap()
            // other validity checks here
            .extractSubject(ARID.self)

        // The registrar creates its own registration document using Alice's ARID as the
        // subject, incorporating Alice's signed document, and adding its own signature.
        let aliceURL = URL(string: "https://exampleledger.com/arid/\(aliceCID.data.hex)")!
        let aliceRegistration = try Envelope(aliceCID)
            .addAssertion(.entity, aliceSignedDocument)
            .addAssertion(.dereferenceVia, aliceURL)
            .wrap()
            .sign(with: exampleLedgerPrivateKeys, note: "Made by ExampleLedger.")
            .checkEncoding()

        let expectedRegistrationFormat =
        """
        {
            ARID(d44c5e0a) [
                'dereferenceVia': URI(https://exampleledger.com/arid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                'entity': {
                    ARID(d44c5e0a) [
                        'controller': ARID(d44c5e0a)
                        'publicKeys': PublicKeyBase
                    ]
                } [
                    'verifiedBy': Signature [
                        'note': "Made by Alice."
                    ]
                ]
            ]
        } [
            'verifiedBy': Signature [
                'note': "Made by ExampleLedger."
            ]
        ]
        """
        XCTAssertEqual(aliceRegistration.format(), expectedRegistrationFormat)

        // Alice receives the registration document back, validates its signature, and
        // extracts the URI that now points to her record.
        let aliceURI = try aliceRegistration
            .verifySignature(from: exampleLedgerPublicKeys)
            .unwrap()
            .extractObject(URL.self, forPredicate: .dereferenceVia)
        XCTAssertEqual(aliceURI†, "https://exampleledger.com/arid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")

        // Alice wants to introduce herself to Bob, so Bob needs to know she controls her
        // identifier. Bob sends a challenge:
        let aliceChallenge = try Envelope(Nonce())
            .addAssertion(.note, "Challenge to Alice from Bob.")
            .checkEncoding()

        let aliceChallengeExpectedFormat =
        """
        Nonce [
            'note': "Challenge to Alice from Bob."
        ]
        """
        XCTAssertEqual(aliceChallenge.format(), aliceChallengeExpectedFormat)

        // Alice responds by adding her registered URI to the nonce, and signing it.
        let aliceChallengeResponse = try aliceChallenge
            .wrap()
            .addAssertion(.dereferenceVia, aliceURI)
            .wrap()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
            .checkEncoding()

        let aliceChallengeResponseExpectedFormat =
        """
        {
            {
                Nonce [
                    'note': "Challenge to Alice from Bob."
                ]
            } [
                'dereferenceVia': URI(https://exampleledger.com/arid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
            ]
        } [
            'verifiedBy': Signature [
                'note': "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceChallengeResponse.format(), aliceChallengeResponseExpectedFormat)

        // Bob receives Alice's response, and first checks that the nonce is the once he sent.
        let responseNonce = try aliceChallengeResponse
            .unwrap()
            .unwrap()
        XCTAssert(aliceChallenge.isEquivalent(to: responseNonce))

        // Bob then extracts Alice's registered URI
        let responseURI = try aliceChallengeResponse
            .unwrap()
            .extractObject(URL.self, forPredicate: .dereferenceVia)
        XCTAssertEqual(responseURI.absoluteString, "https://exampleledger.com/arid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")

        // Bob uses the URI to ask ExampleLedger for Alice's identifier document, then
        // checks ExampleLedgers's signature. Bob trusts ExampleLedger's validation of
        // Alice's original document, so doesn't bother to check it for internal
        // consistency, and instead goes ahead and extracts Alice's public keys from it.
        let aliceDocumentPublicKeys = try aliceRegistration
            .verifySignature(from: exampleLedgerPublicKeys)
            .unwrap()
            .object(forPredicate: .entity)
            .unwrap()
            .extractObject(PublicKeyBase.self, forPredicate: .publicKeys)

        // Finally, Bob uses Alice's public keys to validate the challenge he sent her.
        try aliceChallengeResponse.verifySignature(from: aliceDocumentPublicKeys)
    }

    func testCredential() throws {
        // John Smith's identifier
        let johnSmithIdentifier = ARID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!

        // A photo of John Smith
        let johnSmithImage = Envelope("John Smith smiling")
            .addAssertion(.note, "This is an image of John Smith.")
            .addAssertion(.dereferenceVia, "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999")

        // John Smith's Permanent Resident Card issued by the State of Example
        let johnSmithResidentCard = {
            var rng = makeFakeRandomNumberGenerator()
            return try! Envelope(ARID(‡"174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8")!)
            .addType("credential")
            .addAssertion("dateIssued", Date(iso8601: "2022-04-27"))
            .addAssertion(.issuer, Envelope(stateIdentifier)
                .addAssertion(.note, "Issued by the State of Example")
                .addAssertion(.dereferenceVia, URL(string: "https://exampleledger.com/arid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!)
            )
            .addAssertion(.holder, Envelope(johnSmithIdentifier)
                .addType("Person")
                .addType("Permanent Resident")
                .addAssertion("givenName", "JOHN")
                .addAssertion("familyName", "SMITH")
                .addAssertion("sex", "MALE")
                .addAssertion("birthDate", Date(iso8601: "1974-02-18"))
                .addAssertion("image", johnSmithImage)
                .addAssertion("lprCategory", "C09")
                .addAssertion("lprNumber", "999-999-999")
                .addAssertion("birthCountry", Envelope("bs").addAssertion(.note, "The Bahamas"))
                .addAssertion("residentSince", Date(iso8601: "2018-01-07"))
            )
            .addAssertion(.note, "The State of Example recognizes JOHN SMITH as a Permanent Resident.")
            .wrap()
            .sign(with: statePrivateKeys, note: "Made by the State of Example.", using: &rng)
            .checkEncoding()
        }()

        // Validate the state's signature
        try johnSmithResidentCard.verifySignature(from: statePublicKeys)

        //print(johnSmithResidentCard.format())
        
        let expectedFormat =
        """
        {
            ARID(174842ea) [
                'isA': "credential"
                "dateIssued": 2022-04-27
                'holder': ARID(78bc3000) [
                    'isA': "Permanent Resident"
                    'isA': "Person"
                    "birthCountry": "bs" [
                        'note': "The Bahamas"
                    ]
                    "birthDate": 1974-02-18
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": "John Smith smiling" [
                        'dereferenceVia': "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        'note': "This is an image of John Smith."
                    ]
                    "lprCategory": "C09"
                    "lprNumber": "999-999-999"
                    "residentSince": 2018-01-07
                    "sex": "MALE"
                ]
                'issuer': ARID(04363d5f) [
                    'dereferenceVia': URI(https://exampleledger.com/arid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    'note': "Issued by the State of Example"
                ]
                'note': "The State of Example recognizes JOHN SMITH as a Permanent Resident."
            ]
        } [
            'verifiedBy': Signature [
                'note': "Made by the State of Example."
            ]
        ]
        """
        XCTAssertEqual(johnSmithResidentCard.format(), expectedFormat)

        //print(johnSmithResidentCard.diagAnnotated)

        // John wishes to identify himself to a third party using his government-issued
        // credential, but does not wish to reveal more than his name, his photo, and the
        // fact that the state has verified his identity.

        // Redaction is performed by building a set of `Digest`s that will be revealed. All
        // digests not present in the target set will be replaced with elision markers
        // containing only the hash of what has been elided, thus preserving the hash
        // tree including revealed signatures. If a higher-level object is elided, then
        // everything it contains will also be elided, so if a deeper object is to be
        // revealed, all of its parent objects also need to be revealed, even though not
        // everything *about* the parent objects must be revealed.

        // Start a target set
        var target: Set<Digest> = []

        // Reveal the card. Without this, everything about the card would be elided.
        let top = johnSmithResidentCard
        target.insert(top)

        // Reveal everything about the state's signature on the card
        try target.insert(top.assertion(withPredicate: .verifiedBy).deepDigests)

        // Reveal the top level of the card.
        target.insert(top.shallowDigests)

        let card = try top.unwrap()
        target.insert(card)
        target.insert(card.subject)

        // Reveal everything about the `isA` and `issuer` assertions at the top level of the card.
        try target.insert(card.assertion(withPredicate: .isA).deepDigests)
        try target.insert(card.assertion(withPredicate: .issuer).deepDigests)

        // Reveal the `holder` assertion on the card, but not any of its sub-assertions.
        let holder = try card.assertion(withPredicate: .holder)
        target.insert(holder.shallowDigests)

        // Within the `holder` assertion, reveal everything about just the `givenName`, `familyName`, and `image` assertions.
        let holderObject = holder.object!
        try target.insert(holderObject.assertion(withPredicate: "givenName").deepDigests)
        try target.insert(holderObject.assertion(withPredicate: "familyName").deepDigests)
        try target.insert(holderObject.assertion(withPredicate: "image").deepDigests)

        // Perform the elision
        let elidedCredential = try top.elideRevealing(target).checkEncoding()

        // Verify that the elided credential compares equal to the original credential.
        XCTAssert(elidedCredential.isEquivalent(to: johnSmithResidentCard))

        // Verify that the state's signature on the elided card is still valid.
        try elidedCredential.verifySignature(from: statePublicKeys)
        
        XCTAssertEqual(elidedCredential.urString, "ur:envelope/lftpsplntpcstansgshdcxchfdfwwdsrzofytsyndsvetsndkbbelbtdmuskhfdtyntbcprocktyatktaxaosphdcxfnstoxfwdaglhlmywzpafwmnfdzezmkisgfhtaetihtibemedpnsuevswtcngwpaoybtlstpcstansgshdcxaaenfsheytmseorfbsbzktrdrdfybkwntkeegetaveghzstattdertbswsihahvsoyaatpcsksckgajkjkkpihiecxidkkcxjyisihcxgujyhsjyihcxjliycxfekshsjnjojzihoyastpcstpcxksheisjyjyjojkftdldlihkshsjnjojzihjzihieioihjpdmiajljndlhsjpiniedldyeeeoeneoieeciyiyesesemeoeoidiadyiyehecememidhsidhseeeedyhsiyehiaiyeoeeeehsieesiheeeceeiyhsieesieeheyetiadydyiyihiyenecdyecihetoybalktpcstansgshdcxksrfdyaeflkootmhhpsfrhronbeytkjpdwwdwtrkzocygawdwfcshepyhdaysguohdcxbwjsinwkcmahnefdmsfdgtltkpdppdbdwnfdhhwfjyptvddimucwrycavameetssoytpcsimiyhsjninjzkkglhsjnihtpcsihgugtgaghfdoytpcsinioinkoihjtglhsjnihtpcsiegegwfdglhdcxhdcamnzeftfppdwzpmjojluypebnbeplzeptzesfkgfholssdtkgveimonnlsosehdcxjscnletijkdssosnvljpbklrhpihrpjtfwtnwecflolsolfmkbnlndosmdadztsboytpcsihinjnhsioihlstpcsjpgejlisjtcxgujninjyiscxjkjninjzinjtiooyastpcskshsisjyjyjojkftdldlihkshsjnjojzihjzihieioihjpdmiajljndlieinioihjkjydleoenidiheodyemeyenidihiyideneciahseheoideheoenhsiheyesieetdyetehiyeneeemeseyiaeyemdyeyeeehecihidendyhsieehiaecenihieeoeoiaesesesoyaatpcsksctghisinjkcxinjkcxhsjtcxinjnhsioihcxjliycxgejlisjtcxgujninjyisdmhdcxnsmkylvtfseegsgotaammhcezebdgwhyhhyljkrhwfqzoskgeosodsgmpmhgzchhhdcxosfmfplpfxvefzoybncfwzgtfewdcapsqdkkuolagdtdltvwfdttvorflocwzegahdcxtbcffdrptpstzmmomdktssmegedwvdecgadtdsreaygtdifwmokimwaodwbyuozmhdcxvyidloaagdetmopfrnbwleidmeioftfptavtlnptprvohnfpmtcegdseamceotwyhdcxzejocerptnaxchswvossceasnehkgefyptmhndretdghwtwepymwoyrocmnntddioyadtpcsimiajpihieihjtjyinhsjzhdcxwmesosbwlupscfiopltaemchmdzmtllrgraxlnrhwnkbfmlrveadrtlobspspmmsoyaxlftpcstansghhdfzqdwtmnhlgegylkasmhvtguaadtbstohstekbolkpastlrecltasgadcwtljtnlrhvlecrplufyvacfkevacpesbkdesfpfkpoyosylwzlbvosfyldtdejnbtioprdmoxoyaatpcskscagthsieihcxidkkcxjyisihcxgujyhsjyihcxjliycxfekshsjnjojzihdmjzveesyk")
        
        let expectedElidedFormat =
        """
        {
            ARID(174842ea) [
                'isA': "credential"
                'holder': ARID(78bc3000) [
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": "John Smith smiling" [
                        'dereferenceVia': "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        'note': "This is an image of John Smith."
                    ]
                    ELIDED (8)
                ]
                'issuer': ARID(04363d5f) [
                    'dereferenceVia': URI(https://exampleledger.com/arid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    'note': "Issued by the State of Example"
                ]
                ELIDED (2)
            ]
        } [
            'verifiedBy': Signature [
                'note': "Made by the State of Example."
            ]
        ]
        """
        XCTAssertEqual(elidedCredential.format(), expectedElidedFormat)
        

        
        XCTAssertEqual(elidedCredential.taggedCBOR.cborData.hex, "d8c882d8c886d818d99c4c5820174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c858203cc7a442254e5d8ff2b1428e48feff7dca3fd93865d010912d9cdee8f0234fb1a10d83d818d99c4c582004363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8a104d818781e49737375656420627920746865205374617465206f66204578616d706c65a109d818d820785f68747470733a2f2f6578616d706c656c65646765722e636f6d2f617269642f30343336336435666639393733336263306631353737626162613434306166316366333434616439653435346661643964313238633030666566363530356538a10e8cd818d99c4c582078bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc5820137169f416059f4897484d87752da80bf1485cf374a9e727931bbd1de69138c4a1d8186a66616d696c794e616d65d81865534d495448a1d81869676976656e4e616d65d818644a4f484e5820581d8efe3a41a8f2ad706fdbaf0c10aefea9fecc7b3fa6c4297be46aa599c9c1582071238ad07326c9cde3720a845b65b66e42daed198883a63e7e999ba79501fccba1d81865696d61676583d818724a6f686e20536d69746820736d696c696e67a109d818786168747470733a2f2f6578616d706c656c65646765722e636f6d2f6469676573742f33366265333037323662656662363563613133623133366165323964383038316636343739326332373032343135656236306164316335366564333363393939a104d818781f5468697320697320616e20696d616765206f66204a6f686e20536d6974682e58209c98f7e03d344c55d906901cfe0b4f5e5cf773b9f3b4a77b33c92652ad57fd5c5820a73e418543e440a10c19f24d45ea1dacb379dc8050d287e548d1e2bc881bfe495820d61948b6d8c7ff929577c4914a2ce735492926b5084d2742927d94022c11dcff5820e1628804503892b0be138a6291673a41d9e086a9b2e26041961c50c1061ca3ee5820fe701cb6da0317c6e2c41c099f594a44a9909bb5d254f0edab94a1b8169ed227a101d8186a63726564656e7469616c5820eb39a7138bac1967aed9371795ffd5844b0386b9f17e3e84e401c0880facad97a10382d818d99c545840b3f08e5d4a518c0990e05304290fce61d37ea67509d5b521d9ca011bd56e99b9e335b68b44e6197ce622390a28ccb075a1a7f7f27fe2ccf729286d0d67b22ea4a104d818781d4d61646520627920746865205374617465206f66204578616d706c652e")
        
        XCTAssertEqual(elidedCredential.diagnostic(annotate: true, context: globalFormatContext), """
        200(   / envelope /
           [
              200(   / envelope /
                 [
                    24(   / leaf /
                       40012(   / arid /
                          h'174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8'
                       )
                    ),
                    h'3cc7a442254e5d8ff2b1428e48feff7dca3fd93865d010912d9cdee8f0234fb1',
                    {
                       13:
                       [
                          24(   / leaf /
                             40012(   / arid /
                                h'04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8'
                             )
                          ),
                          {
                             4:
                             24(   / leaf /
                                "Issued by the State of Example"
                             )
                          },
                          {
                             9:
                             24(   / leaf /
                                32(
                                   "https://exampleledger.com/arid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8"
                                )
                             )
                          }
                       ]
                    },
                    {
                       14:
                       [
                          24(   / leaf /
                             40012(   / arid /
                                h'78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc'
                             )
                          ),
                          h'137169f416059f4897484d87752da80bf1485cf374a9e727931bbd1de69138c4',
                          {
                             24("familyName"):   / leaf /
                             24("SMITH")   / leaf /
                          },
                          {
                             24("givenName"):   / leaf /
                             24("JOHN")   / leaf /
                          },
                          h'581d8efe3a41a8f2ad706fdbaf0c10aefea9fecc7b3fa6c4297be46aa599c9c1',
                          h'71238ad07326c9cde3720a845b65b66e42daed198883a63e7e999ba79501fccb',
                          {
                             24("image"):   / leaf /
                             [
                                24("John Smith smiling"),   / leaf /
                                {
                                   9:
                                   24(   / leaf /
                                      "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                                   )
                                },
                                {
                                   4:
                                   24(   / leaf /
                                      "This is an image of John Smith."
                                   )
                                }
                             ]
                          },
                          h'9c98f7e03d344c55d906901cfe0b4f5e5cf773b9f3b4a77b33c92652ad57fd5c',
                          h'a73e418543e440a10c19f24d45ea1dacb379dc8050d287e548d1e2bc881bfe49',
                          h'd61948b6d8c7ff929577c4914a2ce735492926b5084d2742927d94022c11dcff',
                          h'e1628804503892b0be138a6291673a41d9e086a9b2e26041961c50c1061ca3ee',
                          h'fe701cb6da0317c6e2c41c099f594a44a9909bb5d254f0edab94a1b8169ed227'
                       ]
                    },
                    {
                       1:
                       24("credential")   / leaf /
                    },
                    h'eb39a7138bac1967aed9371795ffd5844b0386b9f17e3e84e401c0880facad97'
                 ]
              ),
              {
                 3:
                 [
                    24(   / leaf /
                       40020(   / signature /
                          h'b3f08e5d4a518c0990e05304290fce61d37ea67509d5b521d9ca011bd56e99b9e335b68b44e6197ce622390a28ccb075a1a7f7f27fe2ccf729286d0d67b22ea4'
                       )
                    ),
                    {
                       4:
                       24(   / leaf /
                          "Made by the State of Example."
                       )
                    }
                 ]
              }
           ]
        )
        """)
        
        XCTAssertEqual(elidedCredential.treeFormat(), """
        7da760aa NODE
            2f50e5e7 subj WRAPPED
                ee1bfc78 subj NODE
                    6c1c5596 subj ARID(174842ea)
                    3cc7a442 ELIDED
                    728e7274 ASSERTION
                        6dd16ba3 pred 'issuer'
                        33257537 obj NODE
                            cf8241fe subj ARID(04363d5f)
                            4be120e3 ASSERTION
                                0fcd6a39 pred 'note'
                                c6e07baa obj "Issued by the State of Example"
                            f451ae8e ASSERTION
                                cdb6a696 pred 'dereferenceVia'
                                d5cb18e7 obj URI(https://exampleledger.com/arid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    b02071bd ASSERTION
                        9a7ea0eb pred 'holder'
                        95ce7a1a obj NODE
                            db53cadb subj ARID(78bc3000)
                            137169f4 ELIDED
                            1e1b5a40 ASSERTION
                                a4760522 pred "familyName"
                                e9a5913e obj "SMITH"
                            460df727 ASSERTION
                                b771d812 pred "givenName"
                                f3e7ec3d obj "JOHN"
                            581d8efe ELIDED
                            71238ad0 ELIDED
                            746ca150 ASSERTION
                                763303e5 pred "image"
                                8ed5acce obj NODE
                                    28252e90 subj "John Smith smiling"
                                    2822e493 ASSERTION
                                        cdb6a696 pred 'dereferenceVia'
                                        21b4b63e obj "https://exampleledger.com/digest/36be307…"
                                    ef16f1af ASSERTION
                                        0fcd6a39 pred 'note'
                                        6ad445db obj "This is an image of John Smith."
                            9c98f7e0 ELIDED
                            a73e4185 ELIDED
                            d61948b6 ELIDED
                            e1628804 ELIDED
                            fe701cb6 ELIDED
                    be100e9e ASSERTION
                        2be2d79b pred 'isA'
                        c2e5cb01 obj "credential"
                    eb39a713 ELIDED
            34ceffc8 ASSERTION
                d0e39e78 pred 'verifiedBy'
                a89b685b obj NODE
                    bf52495c subj Signature
                    f763da80 ASSERTION
                        0fcd6a39 pred 'note'
                        ae039855 obj "Made by the State of Example."
        """)

        // Encrypt instead of elide
        let key = SymmetricKey()
        let encryptedCredential = try top.elideRevealing(target, action: .encrypt(key)).checkEncoding()
        //print(encryptedCredential.format())
        let expectedEncryptedFormat =
        """
        {
            ARID(174842ea) [
                'isA': "credential"
                'holder': ARID(78bc3000) [
                    "familyName": "SMITH"
                    "givenName": "JOHN"
                    "image": "John Smith smiling" [
                        'dereferenceVia': "https://exampleledger.com/digest/36be30726befb65ca13b136ae29d8081f64792c2702415eb60ad1c56ed33c999"
                        'note': "This is an image of John Smith."
                    ]
                    ENCRYPTED (8)
                ]
                'issuer': ARID(04363d5f) [
                    'dereferenceVia': URI(https://exampleledger.com/arid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
                    'note': "Issued by the State of Example"
                ]
                ENCRYPTED (2)
            ]
        } [
            'verifiedBy': Signature [
                'note': "Made by the State of Example."
            ]
        ]
        """
        XCTAssertEqual(encryptedCredential.format(), expectedEncryptedFormat)
    }

    /// See [The Art of Immutable Architecture, by Michael L. Perry](https://amzn.to/3Kszr1p).
    func testHistoricalModeling() throws {
        //
        // Declare Actors
        //

//        let johnSmithIdentifier = ARID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!
//        let johnSmithPrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
//        let johnSmithPublicKeys = johnSmithPrivateKeys.publicKeys
//        let johnSmithDocument = Envelope(johnSmithIdentifier)
//            .add(.hasName, "John Smith")
//            .add(.dereferenceVia, URL(string: "https://exampleledger.com/arid/78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!)

//        let acmeCorpPrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
//        let acmeCorpPublicKeys = acmeCorpPrivateKeys.publicKeys
        let acmeCorpIdentifier = ARID(‡"361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!
        let acmeCorpDocument = try Envelope(acmeCorpIdentifier)
            .addAssertion(.hasName, "Acme Corp.")
            .addAssertion(.dereferenceVia, URL(string: "https://exampleledger.com/arid/361235424efc81cedec7eb983a97bbe74d7972f778486f93881e5eed577d0aa7")!)
            .checkEncoding()

        //
        // Declare Products
        //

        let qualityProduct = try Envelope(ARID(‡"5bcca01f5f370ceb3b7365f076e9600e294d4da6ddf7a616976c87775ea8f0f1")!)
            .addType("Product")
            .addAssertion(.hasName, "Quality Widget")
            .addAssertion("seller", acmeCorpDocument)
            .addAssertion("priceEach", "10.99")
            .checkEncoding()

        let cheapProduct = try Envelope(ARID(‡"ae464c5f9569ae23ff9a75e83caf485fb581d1ef9da147ca086d10e3d6f93e64")!)
            .addType("Product")
            .addAssertion(.hasName, "Cheap Widget")
            .addAssertion("seller", acmeCorpDocument)
            .addAssertion("priceEach", "4.99")
            .checkEncoding()

        //
        // Declare a Purchase Order
        //

        // Since the line items of a PurchaseOrder may be mutated before being finalized,
        // they are not declared as part of the creation of the PurchaseOrder itself.

        let purchaseOrder = try Envelope(ARID(‡"1bebb5b6e447f819d5a4cb86409c5da1207d1460672dfe903f55cde833549625")!)
            .addType("PurchaseOrder")
            .addAssertion(.hasName, "PO 123")
            .checkEncoding()

        //
        // Add Line Items to the Purchase Order
        //

        // A line item's subject is a reference to the digest of the specific purchase
        // order object. This forms a successor -> predecessor relationship to the purchase
        // order.
        //
        // A line item's product is the ARID of the product. The product document found by
        // referencing the product's ARID may change over time, for instance the price may
        // be updated. The line item therefore captures the current price from the product
        // document in its priceEach assertion.

        let line1 = try Envelope(purchaseOrder.digest)
            .addType("PurchaseOrderLineItem")
            .addAssertion("product", qualityProduct.extractSubject(ARID.self))
            .addAssertion(.hasName, qualityProduct.object(forPredicate: .hasName))
            .addAssertion("priceEach", qualityProduct.object(forPredicate: "priceEach"))
            .addAssertion("quantity", 4)
            .checkEncoding()

        let line2 = try Envelope(purchaseOrder.digest)
            .addType("PurchaseOrderLineItem")
            .addAssertion("product", cheapProduct.extractSubject(ARID.self))
            .addAssertion(.hasName, cheapProduct.object(forPredicate: .hasName))
            .addAssertion("priceEach", cheapProduct.object(forPredicate: "priceEach"))
            .addAssertion("quantity", 3)
            .checkEncoding()

        let line2ExpectedFormat =
        """
        Digest(3d0b1fb6) [
            'isA': "PurchaseOrderLineItem"
            "priceEach": "4.99"
            "product": ARID(ae464c5f)
            "quantity": 3
            'hasName': "Cheap Widget"
        ]
        """
        XCTAssertEqual(line2.format(), line2ExpectedFormat)

//        let revokeLine1 = Envelope(purchaseOrder.digest)
//            .add(Assertion(revoke: Reference(digest: line1.digest)))
//        print(revokeLine1.format())

        let purchaseOrderProjection = try purchaseOrder
            .addAssertion("lineItem", line1)
            .addAssertion("lineItem", line2)
//            .revoke(line1.digest)
            .checkEncoding()

        let purchaseOrderProjectionExpectedFormat =
        """
        ARID(1bebb5b6) [
            'isA': "PurchaseOrder"
            "lineItem": Digest(3d0b1fb6) [
                'isA': "PurchaseOrderLineItem"
                "priceEach": "10.99"
                "product": ARID(5bcca01f)
                "quantity": 4
                'hasName': "Quality Widget"
            ]
            "lineItem": Digest(3d0b1fb6) [
                'isA': "PurchaseOrderLineItem"
                "priceEach": "4.99"
                "product": ARID(ae464c5f)
                "quantity": 3
                'hasName': "Cheap Widget"
            ]
            'hasName': "PO 123"
        ]
        """
        XCTAssertEqual(purchaseOrderProjection.format(), purchaseOrderProjectionExpectedFormat)
    }
    
    func testExampleCredential() {
        let omarCID = ARID()
        let omarPrivateKey = PrivateKeyBase()
        let _/*omar*/ = Envelope(omarCID)
            .addAssertion(.hasName, "Omar Chaim")
            .addAssertion("githubID", "omarc-bc-guy")
            .addAssertion("pubkeyURL", "https://github.com/omarc-bc-guy.keys")
            .wrap()
            .sign(with: omarPrivateKey, note: "Self-signed by Omar.")
        
        let jonathanCID = ARID()
        let jonathanPrivateKey = PrivateKeyBase()
        let jonathanPublicKey = jonathanPrivateKey.publicKeys
        let ur = jonathanPublicKey.ur
        let _/*jonathan*/ = Envelope(jonathanCID)
            .addAssertion(.hasName, "Jonathan Jakes")
            .addAssertion("githubID", "jojokes")
            .addAssertion("pubkey", ur.string)
            .wrap()
            .sign(with: jonathanPrivateKey, note: "Self-signed by Jonathan")

        let certCID = ARID()
        let _/*cert*/ = Envelope(certCID)
            .addAssertion(.issuer, Envelope(omarCID).addAssertion(.note, "Omar's ARID"))
            .addAssertion("subject", Envelope(jonathanCID).addAssertion(.note, "Jonathan's ARID"))
            .addType("Assessment of Blockchain Tech Writing Expertise")
            .wrap()
            .sign(with: omarPrivateKey, note: "Signed by Omar")
        
//        print(omar.format())
//        print(jonathan.format())
//        print(cert.format())
    }
}
