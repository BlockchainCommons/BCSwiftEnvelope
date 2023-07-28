import XCTest
import SecureComponents
import Envelope
import WolfBase

class CoreEncodingTests: XCTestCase {
    func testDigest() throws {
        try Envelope(Digest("Hello.")).checkEncoding()
    }

    func test1() throws {
        let e = try Envelope(plaintextHello).checkEncoding()
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
            """
            200(   ; envelope
               24("Hello.")   ; leaf
            )
            """
        )
    }
    
    func test2() throws {
        let array: CBOR = [1, 2, 3]
        let e = try Envelope(array).checkEncoding()
        XCTAssertEqual(e.diagnostic(annotate: true, context: globalFormatContext),
            """
            200(   ; envelope
               24(   ; leaf
                  [1, 2, 3]
               )
            )
            """
        )
    }
    
    func test3() throws {
        let e1 = try Envelope("A", "B").checkEncoding()
        let e2 = try Envelope("C", "D").checkEncoding()
        let e3 = try Envelope("E", "F").checkEncoding()
        
        let e4 = try e2.addAssertion(e3)
        XCTAssertEqual(e4.format(),
        """
        {
            "C": "D"
        } [
            "E": "F"
        ]
        """
        )
        
        XCTAssertEqual(e4.diagnostic(annotate: true, context: globalFormatContext),
        """
        200(   ; envelope
           [
              200(   ; envelope
                 {
                    200(   ; envelope
                       24("C")   ; leaf
                    ):
                    200(   ; envelope
                       24("D")   ; leaf
                    )
                 }
              ),
              200(   ; envelope
                 {
                    200(   ; envelope
                       24("E")   ; leaf
                    ):
                    200(   ; envelope
                       24("F")   ; leaf
                    )
                 }
              )
           ]
        )
        """)
        
        try e4.checkEncoding()

        let e5 = try e1.addAssertion(e4)
        
        XCTAssertEqual(e5.format(),
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

        XCTAssertEqual(e5.diagnostic(annotate: true, context: globalFormatContext),
            """
            200(   ; envelope
               [
                  200(   ; envelope
                     {
                        200(   ; envelope
                           24("A")   ; leaf
                        ):
                        200(   ; envelope
                           24("B")   ; leaf
                        )
                     }
                  ),
                  200(   ; envelope
                     [
                        200(   ; envelope
                           {
                              200(   ; envelope
                                 24("C")   ; leaf
                              ):
                              200(   ; envelope
                                 24("D")   ; leaf
                              )
                           }
                        ),
                        200(   ; envelope
                           {
                              200(   ; envelope
                                 24("E")   ; leaf
                              ):
                              200(   ; envelope
                                 24("F")   ; leaf
                              )
                           }
                        )
                     ]
                  )
               ]
            )
            """
        )
        
        try e5.checkEncoding()
    }
}
