import XCTest
import SecureComponents
import Envelope
import WolfBase

class TypeTests: XCTestCase {
    func testKnownValue() throws {
        let envelope = try Envelope(.verifiedBy).checkEncoding()
        XCTAssertEqual(envelope.format(), "verifiedBy")
    }

    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07")).checkEncoding()
        XCTAssertEqual(envelope.format(), "2018-01-07")
    }
}
