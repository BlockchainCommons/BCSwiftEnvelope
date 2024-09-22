import Testing
import SecureComponents
import Envelope
import WolfBase

struct TestFunction {
    private func twoPlusThree() -> Envelope {
        return Envelope(function: .add)
            .addParameter(.lhs, value: 2)
            .addParameter(.rhs, value: 3)
    }
    
    @Test func testKnown() {
        let envelope = twoPlusThree()
        let expectedFormat = """
        «add» [
            ❰lhs❱: 2
            ❰rhs❱: 3
        ]
        """
        #expect(envelope.format() == expectedFormat)
    }
    
    @Test func testNamed() {
        let envelope = Envelope(function: "foo")
            .addParameter("bar", value: 2)
            .addParameter("baz", value: 3)
        
        let expectedFormat = """
        «"foo"» [
            ❰"bar"❱: 2
            ❰"baz"❱: 3
        ]
        """
        #expect(envelope.format() == expectedFormat)
    }
    
    @Test func testRequest() {
        let requestID = ARID(‡"c66be27dbad7cd095ca77647406d07976dc0f35f0d4d654bb0e96dd227a1e9fc")!
        
        let requestEnvelope = Envelope(request: requestID, body: twoPlusThree())
        #expect(requestEnvelope.format() == """
        request(ARID(c66be27d)) [
            'body': «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """)

        let responseEnvelope = Envelope(response: requestID, result: 5)
        #expect(responseEnvelope.format() == """
        response(ARID(c66be27d)) [
            'result': 5
        ]
        """)

        let errorResponse = Envelope(response: requestID, error: "Internal Server Error")
        #expect(errorResponse.format() == """
        response(ARID(c66be27d)) [
            'error': "Internal Server Error"
        ]
        """)
        
        let unknownErrorResponse = Envelope(error: "Decryption failure")
        #expect(unknownErrorResponse.format() == """
        response('Unknown') [
            'error': "Decryption failure"
        ]
        """)
    }
}
