import XCTest
import SecureComponents
import Envelope
import WolfBase

class ExpressionTests: XCTestCase {
    func testRequestResponse() throws {
        let cid = CID()

        let request = Envelope(
            request: cid,
            body: Envelope(function: .add)
                .addParameter(.lhs, value: 2)
                .addParameter(.rhs, value: 3))
        print(request.format(context: formatContext))
        
        let response = Envelope(
            response: cid, result: 5)
        print(response.format(context: formatContext))

        let errorResponse = Envelope(response: cid, error: "Internal Server Error")
        print(errorResponse.format(context: formatContext))
    }
}
