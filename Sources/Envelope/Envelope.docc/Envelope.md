# ``Envelope``

Gordian Envelope: A flexible container for structured data.

## Overview

The envelope protocol specifies a structured format for hierarchical binary data focused on the ability to transmit it in a privacy-focused way. Envelopes are designed to facilitate "smart documents" and have a number of unique features including: easy representation of a variety of semantic structures, a built-in Merkle-like digest tree, deterministic representation using CBOR, and the ability for the holder of a document to selectively encrypt or elide specific parts of a document without invalidating the document structure including the digest tree, or any cryptographic signatures that rely on it.

## Resources

- [IETF Draft Specification: The Envelope Structured Data Format](https://datatracker.ietf.org/doc/draft-mcnally-envelope/)
- [Video: Introduction to Gordian Envelope](https://www.youtube.com/watch?v=kQm7irWFi5U)
- [Video: Gordian Architecture: Why CBOR?](https://www.youtube.com/watch?v=uoD5_Vr6qzw)
- [Video: Diffing with Gordian Envelope](https://www.youtube.com/watch?v=kXk_XTACqh8)

## Topics

### Essentials

- <doc:Overview>
- <doc:Examples>
- ``Envelope/Envelope``

### Creating an Envelope with a Subject

- ``Envelope/Envelope/init(_:)-2fdao``
- ``Envelope/Envelope/init(_:)-8c8jv``

### Adding Assertions to an Envelope

- ``Envelope/Envelope/addAssertion(_:_:salted:)-277sn``
- ``Envelope/Envelope/addAssertion(_:_:salted:)-9sf9h``
- ``Envelope/Envelope/addAssertion(_:salted:)``
- ``Envelope/Envelope/addAssertion(if:_:_:salted:)-1by3y``
- ``Envelope/Envelope/addAssertion(if:_:_:salted:)-58rqr``
- ``Envelope/Envelope/addAssertion(if:_:salted:)``
- ``Envelope/Envelope/addAssertions(_:salted:)``

### Viewing Envelope Contents

- <doc:Notation>
- <doc:OutputFormats>
- ``Envelope/Envelope/format``
- ``Envelope/Envelope/treeFormat(hideNodes:highlighting:)``
- ``Envelope/Envelope/diag``
- ``Envelope/Envelope/diagAnnotated``
- ``Envelope/Envelope/dump``
- ``Envelope/Envelope/mermaidFormat(hideNodes:layoutDirection:theme:)``
- ``Envelope/Envelope/MermaidOptions``

### Comparing Envelopes for Semantic Equivalence

- ``Envelope/Envelope/digest``
- ``Envelope/Envelope/isEquivalent(to:)``

### Comparing Envelopes for Structural Identicality

- ``Envelope/Envelope/structuralDigest``
- ``Envelope/Envelope/isIdentical(to:)``

### Working With the Envelope Subject

- ``Envelope/Envelope/subject``
- ``Envelope/Envelope/extractSubject(_:)``
- ``Envelope/Envelope/isSubjectAssertion``
- ``Envelope/Envelope/isSubjectElided``
- ``Envelope/Envelope/isSubjectEncrypted``
- ``Envelope/Envelope/isSubjectObscured``
- ``Envelope/Envelope/replaceSubject(with:)``
- ``Envelope/Envelope/KnownValue-swift.struct``

### Working with Assertions

- ``Envelope/Envelope/init(_:_:)-7fxwn``
- ``Envelope/Envelope/init(_:_:)-8vvce``
- ``Envelope/Envelope/predicate``
- ``Envelope/Envelope/object``
- ``Envelope/Envelope/assertion-swift.property``
- ``Envelope/Envelope/assertions``
- ``Envelope/Envelope/hasAssertions``
- ``Envelope/Envelope/isSubjectAssertion``
- ``Envelope/Envelope/assertion(withPredicate:)-7asyh``
- ``Envelope/Envelope/assertion(withPredicate:)-8hkhz``
- ``Envelope/Envelope/assertion(withPredicate:)-p6cf``
- ``Envelope/Envelope/assertions(withPredicate:)-5u4ly``
- ``Envelope/Envelope/assertions(withPredicate:)-5znmy``
- ``Envelope/Envelope/assertions(withPredicate:)-817l4``
- ``Envelope/Envelope/extractObject(_:forPredicate:)-237rm``
- ``Envelope/Envelope/extractObject(_:forPredicate:)-atjk``
- ``Envelope/Envelope/extractObject(_:forPredicate:)-doan``
- ``Envelope/Envelope/extractObject(forPredicate:)-7at6i``
- ``Envelope/Envelope/extractObject(forPredicate:)-8h0e3``
- ``Envelope/Envelope/extractObject(forPredicate:)-786xl``
- ``Envelope/Envelope/extractObjects(_:forPredicate:)-9ghw6``
- ``Envelope/Envelope/extractObjects(_:forPredicate:)-9lujg``
- ``Envelope/Envelope/extractObjects(forPredicate:)-1cnrl``
- ``Envelope/Envelope/extractObjects(forPredicate:)-9hhb5``
- ``Envelope/Envelope/isA(_:)``
- ``Envelope/Envelope/id(_:)``
- ``Envelope/Envelope/removeAssertion(_:)``
- ``Envelope/Envelope/replaceAssertion(_:with:)``
- ``Envelope/Envelope/Assertion-swift.struct``

### Elision

- <doc:Elision>
- ``Envelope/Envelope/elide()``
- ``Envelope/Envelope/isElided``
- ``Envelope/Envelope/isSubjectElided``
- ``Envelope/Envelope/shallowDigests``
- ``Envelope/Envelope/deepDigests``
- ``Envelope/Envelope/digests(levelLimit:)``
- ``Envelope/Envelope/elideRemoving(_:encryptingWith:)-66yx0``
- ``Envelope/Envelope/elideRemoving(_:encryptingWith:)-4p0a2``
- ``Envelope/Envelope/elideRemoving(_:encryptingWith:)-8tgiz``
- ``Envelope/Envelope/elideRevealing(_:encryptingWith:)-8o34i``
- ``Envelope/Envelope/elideRevealing(_:encryptingWith:)-139hi``
- ``Envelope/Envelope/elideRevealing(_:encryptingWith:)-3aeex``
- ``Envelope/Envelope/elide(_:isRevealing:encryptingWith:)-8qngj``
- ``Envelope/Envelope/elide(_:isRevealing:encryptingWith:)-8w1o6``
- ``Envelope/Envelope/elide(_:isRevealing:encryptingWith:)-i3mw``
- ``Envelope/Envelope/unelide(_:)``

### Wrapping Envelopes

- ``Envelope/Envelope/wrap()``
- ``Envelope/Envelope/unwrap()``

### Working with the Structure of Envelopes

- ``Envelope/Envelope/isLeaf``
- ``Envelope/Envelope/isKnownValue``
- ``Envelope/Envelope/isNode``
- ``Envelope/Envelope/isWrapped``
- ``Envelope/Envelope/isInternal``
- ``Envelope/Envelope/isObscured``
- ``Envelope/Envelope/leaf``
- ``Envelope/Envelope/knownValue-swift.property``

### Recursively Walking the Envelope Structure

- ``Envelope/Envelope/elementsCount``
- ``Envelope/Envelope/walk(hideNodes:visit:)``
- ``Envelope/Envelope/Visitor``
- ``Envelope/Envelope/EdgeType``

### Signatures

- ``Envelope/Envelope/sign(with:tag:randomGenerator:)``
- ``Envelope/Envelope/sign(with:note:tag:randomGenerator:)``
- ``Envelope/Envelope/sign(with:uncoveredAssertions:tag:randomGenerator:)``
- ``Envelope/Envelope/verifiedBy(signature:note:)``
- ``Envelope/Envelope/signatures``
- ``Envelope/Envelope/isVerifiedSignature(_:publicKeys:)``
- ``Envelope/Envelope/verifySignature(from:)``
- ``Envelope/Envelope/hasVerifiedSignature(from:)``
- ``Envelope/Envelope/verifySignature(_:publicKeys:)``
- ``Envelope/Envelope/verifySignatures(from:threshold:)``
- ``Envelope/Envelope/hasVerifiedSignatures(from:threshold:)``

### Symmetric Key Encryption

- ``Envelope/Envelope/encryptSubject(with:testNonce:)``
- ``Envelope/Envelope/decryptSubject(with:)``
- ``Envelope/Envelope/isEncrypted``
- ``Envelope/Envelope/isSubjectEncrypted``

### Public Key Encryption

- ``Envelope/Envelope/encryptSubject(to:)-hn8e``
- ``Envelope/Envelope/encryptSubject(to:)-40mwd``
- ``Envelope/Envelope/addRecipient(_:contentKey:testKeyMaterial:testNonce:)``
- ``Envelope/Envelope/hasRecipient(_:contentKey:testKeyMaterial:testNonce:)``
- ``Envelope/Envelope/recipients``
- ``Envelope/Envelope/decrypt(to:)``

### Encoding and Decoding Envelopes

- ``Envelope/Envelope/taggedCBOR``
- ``Envelope/Envelope/ur``
- ``Envelope/Envelope/urString``
- ``Envelope/Envelope/init(taggedCBOR:)``
- ``Envelope/Envelope/init(ur:)``
- ``Envelope/Envelope/init(urString:)``

### Splitting Envelopes with SSKR

- ``Envelope/Envelope/split(groupThreshold:groups:contentKey:testRandomGenerator:)``
- ``Envelope/Envelope/init(shares:)``
- ``Envelope/Envelope/addSSKRShare(_:)``

### Noncorrelation

- <doc:Noncorrelation>
- ``Envelope/Envelope/addSalt()``
- ``Envelope/Envelope/addSalt(_:)-9lg7y``
- ``Envelope/Envelope/addSalt(_:)-7vbe0``
- ``Envelope/Envelope/addSalt(_:)-8vq5g``
- ``Envelope/Envelope/addSalt(using:)``

### Existence Proofs

- <doc:ExistenceProofs>
- ``Envelope/Envelope/proof(contains:)-jpk9``
- ``Envelope/Envelope/proof(contains:)-fnjv``
- ``Envelope/Envelope/confirm(contains:using:)-28uny``
- ``Envelope/Envelope/confirm(contains:using:)-bjef``

### Diffing Envelopes

- <doc:Diffing>
- ``Envelope/Envelope/diff(target:)``
- ``Envelope/Envelope/transform(edits:)``

### Envelope Expressions

- <doc:Expressions>

### Envelope Expressions: Functions

- ``Envelope/Envelope/init(function:)-1k57u``
- ``Envelope/Envelope/init(function:)-20y6m``
- ``Envelope/Envelope/init(function:name:)``
- ``Envelope/Envelope/FunctionIdentifier``

### Envelope Expressions: Parameters

- ``Envelope/Envelope/addParameter(_:value:)-1xchn``
- ``Envelope/Envelope/addParameter(_:value:)-8f3k5``
- ``Envelope/Envelope/ParameterIdentifier``
- ``Envelope/Envelope/extractObject(_:forParameter:)``
- ``Envelope/Envelope/extractObjects(_:forParameter:)``

### Envelope Expressions: Requests and Responses

- ``Envelope/Envelope/init(request:body:)``
- ``Envelope/Envelope/init(response:result:)``
- ``Envelope/Envelope/init(response:results:)``
- ``Envelope/Envelope/init(response:error:)``
- ``Envelope/Envelope/init(error:)``
- ``Envelope/Envelope/result()``
- ``Envelope/Envelope/results()``
- ``Envelope/Envelope/result(_:)``
- ``Envelope/Envelope/results(_:)``
- ``Envelope/Envelope/isResultOK()``
- ``Envelope/Envelope/error(_:)``

### Debugging Tools

- ``Envelope/Envelope/checkEncoding()``
- ``Envelope/Envelope/Error``

### Test Vectors

- <doc:EnvelopeTestVectors>
- <doc:SSKRTestVectors>
