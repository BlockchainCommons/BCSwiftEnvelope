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
        XCTAssertEqual(envelope.urString, "ur:envelope/tpsgaxtystteve")
    }

    func testDate() throws {
        let envelope = try Envelope(Date(iso8601: "2018-01-07")).checkEncoding()
        XCTAssertEqual(envelope.format(), "2018-01-07")
    }
    
    func testFakeData() throws {
        let data = generateFakeRandomNumbers(100)
        XCTAssertEqual(data, ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed518684c556472008a67932f7c682125b50cb72e8216f6906358fdaf28d3545532daee0c5bb5023f50cd8e71ec14901ac746c576c481b893be6656b80622b3a564e59b4e2")
    }
    
    func testFakeNumbers() throws {
        var rng = makeFakeRandomGenerator()
        let array = (0..<100).map { _ in Int32.random(in: -50...50, using: &rng) }
        XCTAssertEqual(array†, "[-43, -6, 43, -34, -34, 17, -9, 24, 17, -29, -32, -44, 12, -15, -46, 20, 50, -31, -50, 36, -28, -23, 6, -27, -31, -45, -27, 26, 31, -23, 24, 19, -32, 43, -18, -17, 6, -13, -1, -27, 4, -48, -4, -44, -6, 17, -15, 22, 15, 20, -25, -35, -33, -27, -17, -44, -27, 15, -14, -38, -29, -12, 8, 43, 49, -42, -11, -1, -42, -26, -25, 22, -13, 14, 42, -29, -38, 17, 2, 5, 5, -31, 27, -3, 39, -12, 42, 46, -17, -25, -46, -19, 16, 2, -45, 41, 12, -22, 43, -11]")
    }
}
