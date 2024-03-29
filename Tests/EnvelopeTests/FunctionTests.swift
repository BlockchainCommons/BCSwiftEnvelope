import XCTest
import SecureComponents
import Envelope
import WolfBase

class TestFunction: XCTestCase {
    private func twoPlusThree() -> Envelope {
        return Envelope(function: .add)
            .addParameter(.lhs, value: 2)
            .addParameter(.rhs, value: 3)
    }
    
    func testKnown() {
        let envelope = twoPlusThree()
        let expectedFormat = """
        «add» [
            ❰lhs❱: 2
            ❰rhs❱: 3
        ]
        """
        XCTAssertEqual(envelope.format(), expectedFormat)
    }
    
    func testNamed() {
        let envelope = Envelope(function: "foo")
            .addParameter("bar", value: 2)
            .addParameter("baz", value: 3)
        
        let expectedFormat = """
        «"foo"» [
            ❰"bar"❱: 2
            ❰"baz"❱: 3
        ]
        """
        XCTAssertEqual(envelope.format(), expectedFormat)
    }
    
    func testRequest() {
        let requestID = ARID(‡"c66be27dbad7cd095ca77647406d07976dc0f35f0d4d654bb0e96dd227a1e9fc")!
        
        let requestEnvelope = Envelope(request: requestID, body: twoPlusThree())
        XCTAssertEqual(requestEnvelope.format(), """
        request(ARID(c66be27d)) [
            'body': «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """)

        let responseEnvelope = Envelope(response: requestID, result: 5)
        XCTAssertEqual(responseEnvelope.format(), """
        response(ARID(c66be27d)) [
            'result': 5
        ]
        """)

        let errorResponse = Envelope(response: requestID, error: "Internal Server Error")
        XCTAssertEqual(errorResponse.format(), """
        response(ARID(c66be27d)) [
            'error': "Internal Server Error"
        ]
        """)
        
        let unknownErrorResponse = Envelope(error: "Decryption failure")
        XCTAssertEqual(unknownErrorResponse.format(), """
        response('Unknown') [
            'error': "Decryption failure"
        ]
        """)
    }
}
