import Testing
import SecureComponents
import Envelope
import WolfBase

struct CompressionTests {
    let source = "Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium."
    
    @Test func testCompress() throws {
        let original = Envelope(source)
        #expect(original.cborData.count == 369)
        let compressed = try original.compress().checkEncoding(tags: globalTags)
        #expect(compressed.cborData.count == 281)

        #expect(original.digest == compressed.digest)
        let uncompressed = try compressed.uncompress().checkEncoding(tags: globalTags)
        #expect(uncompressed.digest == original.digest)
        #expect(uncompressed.structuralDigest == original.structuralDigest)
    }
    
    @Test func testCompressSubject() throws {
        var rng = makeFakeRandomNumberGenerator()
        let original = Envelope("Alice")
            .addAssertion(.note, source)
            .wrap()
            .sign(with: alicePrivateKeys, using: &rng)
        #expect(original.cborData.count == 456)
        #expect(original.treeFormat() == """
        ec608f27 NODE
            d7183f04 subj WRAPPED
                7f35e345 subj NODE
                    13941b48 subj "Alice"
                    9fb69539 ASSERTION
                        0fcd6a39 pred 'note'
                        e343c9b4 obj "Lorem ipsum dolor sit amet consectetur a…"
            0db2ee20 ASSERTION
                d0e39e78 pred 'verifiedBy'
                f0d3ce4c obj Signature
        """)
        let compressed = try original.compressSubject().checkEncoding(tags: globalTags)
        #expect(compressed.cborData.count == 372)
        #expect(compressed.treeFormat() == """
        ec608f27 NODE
            d7183f04 subj COMPRESSED
            0db2ee20 ASSERTION
                d0e39e78 pred 'verifiedBy'
                f0d3ce4c obj Signature
        """)
        let uncompressed = try compressed.uncompressSubject().checkEncoding(tags: globalTags)
        #expect(uncompressed.digest == original.digest)
        #expect(uncompressed.structuralDigest == original.structuralDigest)
    }
}
