import XCTest
import SecureComponents
import Envelope
import WolfBase

class ExpressionTests: XCTestCase {
    let arid = ARID(‡"be74063a9e65855271432f5a4c1e877dea75aff0beaad47dc24260d93b4ea27b")!

    func testRequest() throws {
        let request = Envelope(
            request: arid,
            body: Envelope(function: .add)
                .addParameter(.lhs, value: 2)
                .addParameter(.rhs, value: 3))
        XCTAssertEqual(request.format(context: globalFormatContext), """
        request(ARID(be74063a)) [
            'body': «add» [
                ❰lhs❱: 2
                ❰rhs❱: 3
            ]
        ]
        """)
        
        XCTAssertEqual(try request.requestID, arid)
        let requestBody = try request.requestBody
        XCTAssertEqual(requestBody.format(context: globalFormatContext), """
        «add» [
            ❰lhs❱: 2
            ❰rhs❱: 3
        ]
        """)

        XCTAssertEqual(try requestBody.function, .add)
        XCTAssertEqual(try requestBody.extractObject(Int.self, forParameter: .lhs), 2)
        XCTAssertEqual(try requestBody.extractObject(Int.self, forParameter: .rhs), 3)
    }
    
    func testResponse() throws {
        let response = Envelope(response: arid, result: 5)
        XCTAssertEqual(response.format(context: globalFormatContext), """
        response(ARID(be74063a)) [
            'result': 5
        ]
        """)
        
        XCTAssertEqual(try response.responseID, arid)
        XCTAssertFalse(response.isError)
        XCTAssertEqual(try response.extractResult(Int.self), 5)
    }
    
    func testOKResponse() throws {
        let response = Envelope(response: arid)
        XCTAssertEqual(response.format(context: globalFormatContext), """
        response(ARID(be74063a)) [
            'result': 'OK'
        ]
        """)
        XCTAssertTrue(try response.isResultOK)
    }
    
    func testError() throws {
        let errorResponse = Envelope(response: arid, error: "Internal Server Error")
        XCTAssertTrue(errorResponse.isError)
        XCTAssertFalse(try errorResponse.isResponseIDUnknown)
        XCTAssertEqual(errorResponse.format(context: globalFormatContext), """
        response(ARID(be74063a)) [
            'error': "Internal Server Error"
        ]
        """)
        XCTAssertEqual(try errorResponse.extractError(String.self), "Internal Server Error")
    }
    
    func testImmediateError() throws {
        let errorResponse = Envelope(error: "Decryption Failed")
        XCTAssertTrue(errorResponse.isError)
        XCTAssertTrue(try errorResponse.isResponseIDUnknown)
        XCTAssertEqual(errorResponse.format(context: globalFormatContext), """
        response('Unknown') [
            'error': "Decryption Failed"
        ]
        """)
    }
}
