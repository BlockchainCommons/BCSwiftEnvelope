import Testing
import SecureComponents
import Envelope
import WolfBase

struct CoreEncodingTests {
    init() async {
        await addKnownTags()
    }
    
    @Test func testDigest() throws {
        try Envelope(Digest("Hello.")).checkEncoding()
    }

    @Test func test1() throws {
        let e = try Envelope(plaintextHello).checkEncoding()
        #expect(e.diagnostic() ==
            """
            200(   / envelope /
               201("Hello.")   / leaf /
            )
            """
        )
    }
    
    @Test func test2() throws {
        let array: CBOR = [1, 2, 3]
        let e = try Envelope(array).checkEncoding()
        #expect(e.diagnostic() ==
            """
            200(   / envelope /
               201(   / leaf /
                  [1, 2, 3]
               )
            )
            """
        )
    }
    
    @Test func test3() throws {
        let e1 = try Envelope("A", "B").checkEncoding()
        let e2 = try Envelope("C", "D").checkEncoding()
        let e3 = try Envelope("E", "F").checkEncoding()
        
        let e4 = try e2.addAssertion(e3)
        #expect(e4.format() ==
        """
        {
            "C": "D"
        } [
            "E": "F"
        ]
        """
        )
        
        #expect(e4.diagnostic() ==
        """
        200(   / envelope /
           [
              {
                 201("C"):   / leaf /
                 201("D")   / leaf /
              },
              {
                 201("E"):   / leaf /
                 201("F")   / leaf /
              }
           ]
        )
        """)
        
        try e4.checkEncoding()

        let e5 = try e1.addAssertion(e4)
        
        #expect(e5.format() ==
            """
            {
                "A": "B"
            } [
                {
                    "C": "D"
                } [
                    "E": "F"
                ]
            ]
            """
        )

        #expect(e5.diagnostic() ==
            """
            200(   / envelope /
               [
                  {
                     201("A"):   / leaf /
                     201("B")   / leaf /
                  },
                  [
                     {
                        201("C"):   / leaf /
                        201("D")   / leaf /
                     },
                     {
                        201("E"):   / leaf /
                        201("F")   / leaf /
                     }
                  ]
               ]
            )
            """
        )
        
        try e5.checkEncoding()
    }
}
