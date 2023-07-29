import XCTest
import SecureComponents
import Envelope
import WolfBase

class TypeTests: XCTestCase {
    func testKnownValue() throws {
        let envelope = try Envelope(.verifiedBy).checkEncoding()
        XCTAssertEqual(envelope.description, ".knownValue(verifiedBy)")
        XCTAssertEqual(envelope.digest†, "Digest(9d7ba9eb8986332bf3e6f3f96b36d937176d95b556441b18612b9c06edc9b7e1)")
        XCTAssertEqual(envelope.format(), "verifiedBy")
        XCTAssertEqual(envelope.urString, "ur:envelope/axgrbdrnem")
    }

    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07")).checkEncoding()
        XCTAssertEqual(envelope.format(), "2018-01-07")
    }
}
