# ``Envelope``

Gordian Envelope: A flexible container for structured data.

## Overview

The envelope protocol specifies a structured format for hierarchical binary data focused on the ability to transmit it in a privacy-focused way. Envelopes are designed to facilitate "smart documents" and have a number of unique features including: easy representation of a variety of semantic structures, a built-in Merkle-like digest tree, deterministic representation using CBOR, and the ability for the holder of a document to selectively encrypt or elide specific parts of a document without invalidating the document structure including the digest tree, or any cryptographic signatures that rely on it.

## Source Code

- [BCSwiftEnvelope](https://github.com/blockchaincommons/BCSwiftEnvelope) repo at GitHub.

## Resources

- [IETF Draft Specification: The Envelope Structured Data Format](https://datatracker.ietf.org/doc/draft-mcnally-envelope/)
- [Video: Introduction to Gordian Envelope](https://www.youtube.com/watch?v=kQm7irWFi5U)
- [Video: Gordian Architecture: Why CBOR?](https://www.youtube.com/watch?v=uoD5_Vr6qzw)
- [Video: Diffing with Gordian Envelope](https://www.youtube.com/watch?v=kXk_XTACqh8)

## Documentation on GitHub

- [Envelope Overview](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Overview.md) - A high-level introduction to Gordian Envelope.
- [Examples](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Overview.md) - High-level examples of API usage.
- [Envelope Notation](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Notation.md) - A simplified textual notation for pretty-printing envelope instances.
- [Output Formats](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/OutputFormats.md) - A comparison of the various Envelope output formats.
- [Elision and Redaction](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Elision.md) - Removing information without invalidating the digest tree.
- [Noncorrelation](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Noncorrelation.md) - A discussion of noncorrelation, salt, and related concepts.
- [Inclusion Proofs](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/InclusionProofs.md) - Computing and verifying minimal proofs that an envelope contains some target information.
- [Diffing Envelopes](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Diffing.md) - Computing and applying the changes between two envelopes.
- [Envelope Expressions](https://github.com/BlockchainCommons/Gordian/blob/master/Envelope/Expressions.md) - Encoding machine-evaluatable expressions using envelopes.

## Topics

### Essentials

- <doc:OverviewArticle>
- <doc:Examples>
- ``Envelope/Envelope``

### Creating an Envelope with a Subject

- ``Envelope/Envelope/init(_:)-2fdao``
- ``Envelope/Envelope/init(_:)-34o49``

### Adding Assertions to an Envelope

- ``Envelope/Envelope/addAssertion(_:_:salted:)-277sn``
- ``Envelope/Envelope/addAssertion(_:_:salted:)-7l0kw``
- ``Envelope/Envelope/addAssertion(_:salted:)``
- ``Envelope/Envelope/addAssertion(if:_:_:salted:)-1by3y``
- ``Envelope/Envelope/addAssertion(if:_:_:salted:)-4jn3r``
- ``Envelope/Envelope/addAssertion(if:_:salted:)``
- ``Envelope/Envelope/addAssertions(_:salted:)``

### Viewing Envelope Contents

- <doc:Notation>
- <doc:OutputFormats>
- ``Envelope/Envelope/format(context:)``
- ``Envelope/Envelope/treeFormat(hideNodes:highlighting:context:)``
- ``Envelope/Envelope/diagnostic(annotate:context:)``
- ``Envelope/Envelope/hex(annotate:context:)``
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
- ``Envelope/KnownValue``

### Working with Assertions

- ``Envelope/Envelope/init(_:_:)-7fxwn``
- ``Envelope/Envelope/init(_:_:)-5h6a6``
- ``Envelope/Envelope/predicate``
- ``Envelope/Envelope/object``
- ``Envelope/Envelope/assertion``
- ``Envelope/Envelope/assertions``
- ``Envelope/Envelope/hasAssertions``
- ``Envelope/Envelope/isSubjectAssertion``
- ``Envelope/Envelope/assertion(withPredicate:)-8hkhz``
- ``Envelope/Envelope/assertion(withPredicate:)-3dqv7``
- ``Envelope/Envelope/assertion(withPredicate:)-1ujsv``
- ``Envelope/Envelope/assertions(withPredicate:)-5znmy``
- ``Envelope/Envelope/assertions(withPredicate:)-3l05k``
- ``Envelope/Envelope/assertions(withPredicate:)-44zyw``
- ``Envelope/Envelope/extractObject(_:forPredicate:)-23b00``
- ``Envelope/Envelope/extractObject(_:forPredicate:)-1lsfm``
- ``Envelope/Envelope/extractObject(_:forPredicate:)-675fq``
- ``Envelope/Envelope/extractObjects(_:forPredicate:)-85q2w``
- ``Envelope/Envelope/object(forPredicate:)-atr9``
- ``Envelope/Envelope/object(forPredicate:)-3pxqr``
- ``Envelope/Envelope/object(forPredicate:)-40b0q``
- ``Envelope/Envelope/objects(forPredicate:)-72jru``
- ``Envelope/Envelope/objects(forPredicate:)-1xpx1``
- ``Envelope/Envelope/isA(_:)``
- ``Envelope/Envelope/id(_:)``
- ``Envelope/Envelope/removeAssertion(_:)``
- ``Envelope/Envelope/replaceAssertion(_:with:)``
- ``Envelope/Assertion``

### Elision

- <doc:Elision>
- ``Envelope/Envelope/elide()``
- ``Envelope/Envelope/isElided``
- ``Envelope/Envelope/isSubjectElided``
- ``Envelope/Envelope/shallowDigests``
- ``Envelope/Envelope/deepDigests``
- ``Envelope/Envelope/digests(levelLimit:)``
- ``Envelope/Envelope/elideRemoving(_:action:)-4qvgb``
- ``Envelope/Envelope/elideRemoving(_:action:)-3w305``
- ``Envelope/Envelope/elideRemoving(_:action:)-94hor``
- ``Envelope/Envelope/elideRevealing(_:action:)-6hjlp``
- ``Envelope/Envelope/elideRevealing(_:action:)-8brht``
- ``Envelope/Envelope/elideRevealing(_:action:)-8g4hj``
- ``Envelope/Envelope/elide(_:isRevealing:action:)-9gy3k``
- ``Envelope/Envelope/elide(_:isRevealing:action:)-12xz7``
- ``Envelope/Envelope/elide(_:isRevealing:action:)-97kvt``
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
- ``Envelope/Envelope/knownValue``

### Recursively Walking the Envelope Structure

- ``Envelope/Envelope/elementsCount``
- ``Envelope/Envelope/walk(hideNodes:visit:)``
- ``Envelope/Envelope/Visitor``
- ``Envelope/Envelope/EdgeType``

### Signatures

- ``Envelope/Envelope/sign(with:tag:)``
- ``Envelope/Envelope/sign(with:note:tag:)``
- ``Envelope/Envelope/sign(with:uncoveredAssertions:tag:)``
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
- ``Envelope/Envelope/init(taggedCBOR:)``
- ``Envelope/Envelope/ur``
- ``Envelope/Envelope/init(ur:)``
- ``Envelope/Envelope/urString``
- ``Envelope/Envelope/init(urString:)``
- ``Envelope/Envelope/untaggedCBOR``
- ``Envelope/Envelope/init(untaggedCBOR:)``

### Splitting Envelopes with SSKR

- ``Envelope/Envelope/init(shares:)``
- ``Envelope/Envelope/addSSKRShare(_:)``

### Noncorrelation

- <doc:Noncorrelation>
- ``Envelope/Envelope/addSalt()``
- ``Envelope/Envelope/addSalt(_:)-9lg7y``
- ``Envelope/Envelope/addSalt(_:)-7vbe0``
- ``Envelope/Envelope/addSalt(_:)-8vq5g``

### Inclusion Proofs

- <doc:InclusionProofs>
- ``Envelope/Envelope/proof(contains:)-jpk9``
- ``Envelope/Envelope/proof(contains:)-fnjv``
- ``Envelope/Envelope/confirm(contains:proof:)-7h8bb``
- ``Envelope/Envelope/confirm(contains:proof:)-83824``

### Diffing Envelopes

- <doc:Diffing>
- ``Envelope/Envelope/diff(target:)``
- ``Envelope/Envelope/transform(edits:)``

### Envelope Expressions

- <doc:Expressions>

### Envelope Expressions: Functions

- ``Envelope/Envelope/init(function:)-9uddl``
- ``Envelope/Envelope/init(function:)-1k57u``
- ``Envelope/Envelope/init(function:)-n6hx``
- ``Envelope/Function``

### Envelope Expressions: Parameters

- ``Envelope/Envelope/addParameter(_:value:)-2y1wr``
- ``Envelope/Envelope/addParameter(_:value:)-1e5yr``
- ``Envelope/Parameter``
- ``Envelope/Envelope/extractObject(_:forParameter:)``
- ``Envelope/Envelope/extractObjects(_:forParameter:)``
- ``Envelope/Envelope/parameter(_:value:)-12r6u``
- ``Envelope/Envelope/parameter(_:value:)-6o9s3``

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
- ``Envelope/Envelope/isResultOK``
- ``Envelope/Envelope/error(_:)``

### Debugging Tools

- ``Envelope/checkEncoding(tags:)``
- ``Envelope/EnvelopeError``

### Test Vectors

- <doc:EnvelopeTestVectors>
- <doc:SSKRTestVectors>
