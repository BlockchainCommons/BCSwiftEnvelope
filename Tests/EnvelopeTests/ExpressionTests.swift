import Testing
import SecureComponents
import Envelope
import WolfBase

struct ExpressionTests {
    let arid = ARID(‡"be74063a9e65855271432f5a4c1e877dea75aff0beaad47dc24260d93b4ea27b")!

    @Test func testRequest() throws {
        let request = Envelope(
            request: arid,
            body: Envelope(function: .add)
                .addParameter(.lhs, value: 2)
                .addParameter(.rhs, value: 3))
        #expect(request.format() == """
        request(ARID(be74063a)) [
            'body': «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """)
        
        #expect(try request.requestID == arid)
        let requestBody = try request.requestBody
        #expect(requestBody.format() == """
        «add» [
            ❰lhs❱: 2
            ❰rhs❱: 3
        ]
        """)

        #expect(try requestBody.function == .add)
        #expect(try requestBody.extractObject(Int.self, forParameter: .lhs) == 2)
        #expect(try requestBody.extractObject(Int.self, forParameter: .rhs) == 3)
    }
    
    @Test func testResponse() throws {
        let response = Envelope(response: arid, result: 5)
        #expect(response.format() == """
        response(ARID(be74063a)) [
            'result': 5
        ]
        """)
        
        #expect(try response.responseID == arid)
        #expect(!response.isError)
        #expect(try response.extractResult(Int.self) == 5)
    }
    
    @Test func testOKResponse() throws {
        let response = Envelope(response: arid)
        #expect(response.format() == """
        response(ARID(be74063a)) [
            'result': 'OK'
        ]
        """)
        #expect(try response.isResultOK)
    }
    
    @Test func testError() throws {
        let errorResponse = Envelope(response: arid, error: "Internal Server Error")
        #expect(errorResponse.isError)
        #expect(try !errorResponse.isResponseIDUnknown)
        #expect(errorResponse.format() == """
        response(ARID(be74063a)) [
            'error': "Internal Server Error"
        ]
        """)
        #expect(try errorResponse.extractError(String.self) == "Internal Server Error")
    }
    
    @Test func testImmediateError() throws {
        let errorResponse = Envelope(error: "Decryption Failed")
        #expect(errorResponse.isError)
        #expect(try errorResponse.isResponseIDUnknown)
        #expect(errorResponse.format() == """
        response('Unknown') [
            'error': "Decryption Failed"
        ]
        """)
    }
}
