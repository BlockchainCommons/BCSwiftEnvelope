import XCTest
import SecureComponents
import Envelope
import WolfBase

class TypeTests: XCTestCase {
    func testKnownValue() throws {
        let envelope = try Envelope(.verifiedBy).checkEncoding()
        XCTAssertEqual(envelope.description, ".knownValue(verifiedBy)")
        XCTAssertEqual(envelope.digest†, "Digest(d0e39e788c0d8f0343af4588db21d3d51381db454bdf710a9a1891aaa537693c)")
        XCTAssertEqual(envelope.format(), "'verifiedBy'")
        XCTAssertEqual(envelope.urString, "ur:envelope/axgrbdrnem")
    }

    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07")).checkEncoding()
        XCTAssertEqual(envelope.format(), "2018-01-07")
        print(envelope.diagnostic(annotate: true, context: globalFormatContext))
        print(envelope.diagnostic())
        
        let e = Envelope(Date(timeIntervalSince1970: 1693454262.5))//.checkEncoding()
        print(e.format(context: globalFormatContext))
        print(e.diagnostic(annotate: true, context: globalFormatContext))
        print(e.diagnostic())
    }
}
