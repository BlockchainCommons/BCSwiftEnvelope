import XCTest
import SecureComponents
import Envelope
import WolfBase

class CompressionTests: XCTestCase {
    let source = "Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium."
    func testCompress() throws {
//        print(source)
        let original = Envelope(source)
        XCTAssertEqual(original.cborData.count, 369)
        let compressed = try original.compress().checkEncoding(tags: globalTags)
        XCTAssertEqual(compressed.cborData.count, 281)

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
        XCTAssertEqual(original.cborData.count, 456)
        XCTAssertEqual(original.treeFormat(), """
        9ed291b0 NODE
            d7183f04 subj WRAPPED
                7f35e345 subj NODE
                    13941b48 subj "Alice"
                    9fb69539 ASSERTION
                        0fcd6a39 pred 'note'
                        e343c9b4 obj "Lorem ipsum dolor sit amet consectetur a…"
            2f87ba42 ASSERTION
                d0e39e78 pred 'verifiedBy'
                dd386db5 obj Signature
        """)
        let compressed = try original.compressSubject().checkEncoding(tags: globalTags)
        XCTAssertEqual(compressed.cborData.count, 372)
        XCTAssertEqual(compressed.treeFormat(), """
        9ed291b0 NODE
            d7183f04 subj COMPRESSED
            2f87ba42 ASSERTION
                d0e39e78 pred 'verifiedBy'
                dd386db5 obj Signature
        """)
        let uncompressed = try compressed.uncompressSubject().checkEncoding(tags: globalTags)
        XCTAssertEqual(uncompressed.digest, original.digest)
        XCTAssertEqual(uncompressed.structuralDigest, original.structuralDigest)
    }
}
