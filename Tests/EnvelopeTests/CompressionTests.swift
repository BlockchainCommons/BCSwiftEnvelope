import XCTest
import SecureComponents
import Envelope
import WolfBase

class CompressionTests: XCTestCase {
    let source = """
        Lorem ipsum dolor sit amet consectetur adipiscing elit mi
        nibh ornare proin blandit diam ridiculus, faucibus mus
        dui eu vehicula nam donec dictumst sed vivamus bibendum
        aliquet efficitur. Felis imperdiet sodales dictum morbi
        vivamus augue dis duis aliquet velit ullamcorper porttitor,
        lobortis dapibus hac purus aliquam natoque iaculis blandit
        montes nunc pretium.
        """
    func testCompress() throws {
        let original = Envelope(source)
        XCTAssertEqual(original.cborData.count, 371)
        let compressed = original.compress()
        XCTAssertEqual(compressed.cborData.count, 252)

        XCTAssertEqual(original.digest, compressed.digest)
        let uncompressed = try compressed.uncompress()
        XCTAssertEqual(uncompressed.digest, original.digest)
        XCTAssertEqual(uncompressed.structuralDigest, original.structuralDigest)
    }
    
    func testCompressSubject() throws {
        let original = Envelope("Alice")
            .addAssertion(.note, source)
            .wrap()
            .sign(with: alicePrivateKeys, randomGenerator: generateFakeRandomNumbers)
        XCTAssertEqual(original.cborData.count, 482)
        XCTAssertEqual(original.treeFormat(context: formatContext), """
        19a0c95c NODE
            b2d791c3 subj WRAPPED
                14881a1f subj NODE
                    13941b48 subj "Alice"
                    2a23230d ASSERTION
                        49a5f41b pred note
                        27bd67e6 obj "Lorem ipsum dolor sit amet consectetur a…"
            b69b976d ASSERTION
                9d7ba9eb pred verifiedBy
                52762b01 obj Signature
        """
        )
        let compressed = original.compressSubject()
        XCTAssertEqual(compressed.cborData.count, 359)
        XCTAssertEqual(compressed.treeFormat(context: formatContext), """
        19a0c95c NODE
            b2d791c3 subj COMPRESSED
            b69b976d ASSERTION
                9d7ba9eb pred verifiedBy
                52762b01 obj Signature
        """
        )
        let uncompressed = try compressed.uncompressSubject()
        XCTAssertEqual(uncompressed.digest, original.digest)
        XCTAssertEqual(uncompressed.structuralDigest, original.structuralDigest)
    }
}
