import XCTest
import SecureComponents
import Envelope
import WolfBase

class CompressionTests: XCTestCase {
    let source = "Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium."
    func testCompress() throws {
        print(source)
        let original = Envelope(source)
        XCTAssertEqual(original.cborData.count, 371)
        let compressed = try original.compress().checkEncoding(tags: globalTags)
        XCTAssertEqual(compressed.cborData.count, 282)

        XCTAssertEqual(original.digest, compressed.digest)
        let uncompressed = try compressed.uncompress().checkEncoding(tags: globalTags)
        XCTAssertEqual(uncompressed.digest, original.digest)
        XCTAssertEqual(uncompressed.structuralDigest, original.structuralDigest)
    }
    
    func testCompressSubject() throws {
        var rng = makeFakeRandomNumberGenerator()
        let original = Envelope("Alice")
            .addAssertion(.note, source)
            .wrap()
            .sign(with: alicePrivateKeys, using: &rng)
        XCTAssertEqual(original.cborData.count, 482)
        XCTAssertEqual(original.treeFormat(context: globalFormatContext), """
        1f87e614 NODE
            9065b9d5 subj WRAPPED
                4aa501b7 subj NODE
                    13941b48 subj "Alice"
                    cb07a196 ASSERTION
                        49a5f41b pred note
                        e343c9b4 obj "Lorem ipsum dolor sit amet consectetur a…"
            a689e27d ASSERTION
                9d7ba9eb pred verifiedBy
                051e3ce1 obj Signature
        """)
        let compressed = try original.compressSubject().checkEncoding(tags: globalTags)
        XCTAssertEqual(compressed.cborData.count, 391)
        XCTAssertEqual(compressed.treeFormat(context: globalFormatContext), """
        1f87e614 NODE
            9065b9d5 subj COMPRESSED
            a689e27d ASSERTION
                9d7ba9eb pred verifiedBy
                051e3ce1 obj Signature
        """)
        let uncompressed = try compressed.uncompressSubject().checkEncoding(tags: globalTags)
        XCTAssertEqual(uncompressed.digest, original.digest)
        XCTAssertEqual(uncompressed.structuralDigest, original.structuralDigest)
    }
}
