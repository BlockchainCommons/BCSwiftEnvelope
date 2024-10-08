import Testing
import SecureComponents
import Envelope
import WolfBase
import Foundation

struct ProofTests {
    @Test func testFriendsList() throws {
        /// This document contains a list of people Alice knows. Each "knows" assertion has
        /// been salted so if the assertions have been elided one can't merely guess at who
        /// she knows by pairing the "knows" predicate with the names of possibly-known
        /// associates and comparing the resulting digests to the elided digests in the
        /// document.
        let aliceFriends = Envelope("Alice")
            .addAssertion("knows", "Bob", salted: true)
            .addAssertion("knows", "Carol", salted: true)
            .addAssertion("knows", "Dan", salted: true)
        #expect(aliceFriends.format() ==
        """
        "Alice" [
            {
                "knows": "Bob"
            } [
                'salt': Salt
            ]
            {
                "knows": "Carol"
            } [
                'salt': Salt
            ]
            {
                "knows": "Dan"
            } [
                'salt': Salt
            ]
        ]
        """
        )
        
        /// Alice provides just the root digest of her document to a third party. This is
        /// simply an envelope in which everything has been elided and nothing revealed.
        let aliceFriendsRoot = aliceFriends.elideRevealing([])
        #expect(aliceFriendsRoot.format() == "ELIDED")
        
        /// Now Alice wants to prove to the third party that her document contains a "knows
        /// Bob" assertion. To do this, she produces a proof that is an envelope with the
        /// minimal structure of digests included so that the proof envelope has the same
        /// digest as the completely elided envelope, but also exposes the digest of the
        /// target of the proof.
        ///
        /// Note that in the proof the digests of the two other elided "knows" assertions
        /// are present, but because they have been salted, the third party cannot easily
        /// guess who else she knows.
        let knowsBobAssertion = Envelope("knows", "Bob")
        let aliceKnowsBobProof = try aliceFriends.proof(contains: knowsBobAssertion)!.checkEncoding()
        #expect(aliceKnowsBobProof.format() ==
        """
        ELIDED [
            ELIDED [
                ELIDED
            ]
            ELIDED (2)
        ]
        """
        )
        
        /// The third party then uses the previously known and trusted root to confirm that
        /// the envelope does indeed contain a "knows bob" assertion.
        #expect(aliceFriendsRoot.confirm(contains: knowsBobAssertion, proof: aliceKnowsBobProof))
    }
    
    @Test func testMultiPosition() throws {
        let aliceFriends = Envelope("Alice")
            .addAssertion("knows", "Bob", salted: true)
            .addAssertion("knows", "Carol", salted: true)
            .addAssertion("knows", "Dan", salted: true)

        /// In some cases the target of a proof might exist at more than one position in an
        /// envelope. An example target from Alice's list of friends would be any envelope
        /// containing "knows" as its subject. Since all three "knows" assertions use this
        /// as their predicate, that identical envelope exists in three different positions
        /// in the outer envelope.
        ///
        /// Note that revealing all positions of the "knows" predicate in this envelope also
        /// reveals the digest of the salt for each assertion, which might make Alice's other
        /// associates easier to guess.
        let knowsProof = try aliceFriends.proof(contains: Envelope("knows"))!.checkEncoding()
        #expect(knowsProof.format() ==
        """
        ELIDED [
            {
                ELIDED: ELIDED
            } [
                ELIDED
            ]
            {
                ELIDED: ELIDED
            } [
                ELIDED
            ]
            {
                ELIDED: ELIDED
            } [
                ELIDED
            ]
        ]
        """
        )
    }
    
    @Test func testVerifiableCredential() throws {
        let arid = Envelope(ARID(‡"4676635a6e6068c2ef3ffd8ff726dd401fd341036e920f136a1d8af5e829496d")!)
        let credential = try arid
            .addAssertion("firstName", "John", salted: true)
            .addAssertion("lastName", "Smith", salted: true)
            .addAssertion("address", "123 Main St.", salted: true)
            .addAssertion("birthDate", Date(iso8601: "1970-01-01"), salted: true)
            .addAssertion("photo", "This is John Smith's photo.", salted: true)
            .addAssertion("dlNumber", "123-456-789", salted: true)
            .addAssertion("nonCommercialVehicleEndorsement", true, salted: true)
            .addAssertion("motorocycleEndorsement", true, salted: true)
            .addAssertion(.issuer, "State of Example")
            .addAssertion(.controller, "State of Example")
            .wrap()
            .sign(with: alicePrivateKeys)
            .addAssertion(.note, "Signed by the State of Example")
        
        let credentialRoot = credential.elideRevealing([])

        /// In this case the holder of a credential wants to prove a single assertion from it, the address.
        let addressAssertion = Envelope("address", "123 Main St.")
        let addressProof = try credential.proof(contains: addressAssertion)!.checkEncoding()
        /// The proof includes digests from all the elided assertions.
        #expect(addressProof.format() ==
        """
        {
            ELIDED [
                ELIDED [
                    ELIDED
                ]
                ELIDED (9)
            ]
        } [
            ELIDED (2)
        ]
        """
        )

        /// The proof confirms the address, as intended.
        #expect(credentialRoot.confirm(contains: addressAssertion, proof: addressProof))

        /// Assertions without salt can also be confirmed.
        let issuerAssertion = Envelope(.issuer, "State of Example")
        #expect(credentialRoot.confirm(contains: issuerAssertion, proof: addressProof))

        /// The proof cannot be used to confirm salted assertions.
        let firstNameAssertion = Envelope("firstName", "John")
        #expect(!credentialRoot.confirm(contains: firstNameAssertion, proof: addressProof))
    }
}
