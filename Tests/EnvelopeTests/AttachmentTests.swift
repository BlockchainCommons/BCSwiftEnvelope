import Testing
import Envelope
import WolfBase

struct AttachmentTests {
    @Test func testAttachment() throws {
        let seed = Seed(
            data: ‡"82f32c855d3d542256180810797e0073",
            name: "Alice's Seed",
            note: "This is the note."
        )!
        let seedEnvelope = seed.envelope
            .addAttachment("Attachment Data V1", vendor: "com.example", conformsTo: "https://example.com/seed-attachment/v1")
            .addAttachment("Attachment Data V2", vendor: "com.example", conformsTo: "https://example.com/seed-attachment/v2")
        #expect(seedEnvelope.envelope.format() == """
        Bytes(16) [
            'isA': 'Seed'
            'attachment': {
                "Attachment Data V1"
            } [
                'conformsTo': "https://example.com/seed-attachment/v1"
                'vendor': "com.example"
            ]
            'attachment': {
                "Attachment Data V2"
            } [
                'conformsTo': "https://example.com/seed-attachment/v2"
                'vendor': "com.example"
            ]
            'hasName': "Alice's Seed"
            'note': "This is the note."
        ]
        """)
        #expect(try seedEnvelope.attachments().count == 2)
        #expect(try seedEnvelope.attachments(withVendor: "com.example").count == 2)
        let v1Attachment = try seedEnvelope.attachment(conformingTo: "https://example.com/seed-attachment/v1")
        #expect(try v1Attachment.attachmentPayload.format() ==
        """
        "Attachment Data V1"
        """)
        #expect(try v1Attachment.attachmentVendor == "com.example")
        #expect(try v1Attachment.attachmentConformsTo == "https://example.com/seed-attachment/v1")
        
        let seedEnvelope2 = try seed.envelope.addAssertions(seedEnvelope.attachments())
        #expect(seedEnvelope2.isEquivalent(to: seedEnvelope))
    }
}
