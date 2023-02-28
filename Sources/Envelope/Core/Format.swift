import Foundation
import WolfBase
import SecureComponents

public struct FormatContext {
    public let tags: KnownTagsDict
    public let functions: KnownFunctions
    public let parameters: KnownParameters
    
    public init(tags: KnownTagsDict = [], functions: KnownFunctions = [], parameters: KnownParameters = []) {
        self.tags = tags
        self.functions = functions
        self.parameters = parameters
    }
}

extension FormatContext: KnownTags {
    public func assignedName(for tag: Tag) -> String? {
        tags.assignedName(for: tag)
    }
    
    public func name(for tag: Tag) -> String {
        tags.name(for: tag)
    }
}

/// Support for the various text output formats for ``Envelope``.

public extension Envelope {
    /// Returns the envelope notation for this envelope.
    ///
    /// See <doc:Notation> for a description of envelope notation.
    func format(context: FormatContext? = nil) -> String {
        formatItem(context: context).format.trim()
    }

    /// Returns the CBOR diagnostic notation for this envelope.
    ///
    /// See [RFC-8949 §8](https://www.rfc-editor.org/rfc/rfc8949.html#name-diagnostic-notation)
    /// for information on CBOR diagnostic notation.
    func diagnostic(annotate: Bool = false, context: FormatContext? = nil) -> String {
        cbor.diagnostic(annotate: annotate, knownTags: context)
    }

    /// Returns the CBOR hex dump of this envelope.
    ///
    /// See [RFC-8949](https://www.rfc-editor.org/rfc/rfc8949.html) for information on
    /// the CBOR binary format.
    func dump(annotate: Bool = false, context: FormatContext? = nil) -> String {
        cbor.hex(annotate: annotate, knownTags: context)
    }
}

protocol EnvelopeFormat {
    func formatItem(context: FormatContext?) -> EnvelopeFormatItem
}

extension Digest: EnvelopeFormat {
    func formatItem(context: FormatContext?) -> EnvelopeFormatItem {
        return .item(data.prefix(8).hex)
    }
}

extension CID: EnvelopeFormat {
    func formatItem(context: FormatContext?) -> EnvelopeFormatItem {
        return .item(data.hex)
    }
}

extension Assertion: EnvelopeFormat {
    func formatItem(context: FormatContext?) -> EnvelopeFormatItem {
        .list([predicate.formatItem(context: context), ": ", object.formatItem(context: context)])
    }
}

extension KnownValue: EnvelopeFormat {
    func formatItem(context: FormatContext?) -> EnvelopeFormatItem {
        .item(name)
    }
}

extension CBOR {
    func envelopeSummary(maxLength: Int = .max, context: FormatContext?) -> String {
        do {
            switch self {
            case .unsigned(let n):
                return String(n)
            case .negative(let n):
                return String(n)
            case .bytes(let data):
                return "Bytes(\(data.count))"
            case .text(let string):
                return (string.count > maxLength ? string.prefix(count: maxLength).trim() + "…" : string)
                    .replacingOccurrences(of: "\n", with: "\\n")
                    .flanked(.quote)
            case .array(let elements):
                return elements.map { $0.envelopeSummary(maxLength: maxLength, context: context) }.joined(separator: ", ").flanked("[", "]")
            case CBOR.tagged(let tag, let cbor):
                switch tag {
                case Envelope.cborTag:
                    return "Envelope"
                case KnownValue.cborTag:
                    guard
                        case let CBOR.unsigned(rawValue) = cbor,
                        case let predicate = KnownValue(rawValue: rawValue)
                    else {
                        return "<not a known value>"
                    }
                    return predicate†
                case Signature.cborTag:
                    return "Signature"
                case Nonce.cborTag:
                    return "Nonce"
                case Salt.cborTag:
                    return "Salt"
                case SealedMessage.cborTag:
                    return "SealedMessage"
                case SSKRShare.cborTag:
                    return "SSKRShare"
                case PublicKeyBase.cborTag:
                    return "PublicKeyBase"
                case Date.cborTag:
                    let date = try Date(untaggedCBOR: cbor)
                    var s = date.ISO8601Format()
                    if s.count == 20 && s.hasSuffix("T00:00:00Z") {
                        s = s.prefix(count: 10)
                    }
                    return s
                case CID.cborTag:
                    return try CID(untaggedCBOR: cbor).shortDescription.flanked("CID(", ")")
                case URL.cborTag:
                    return try URL(untaggedCBOR: cbor)†.flanked("URI(", ")")
                case UUID.cborTag:
                    return try UUID(untaggedCBOR: cbor)†.flanked("UUID(", ")")
                case Digest.cborTag:
                    return try Digest(untaggedCBOR: cbor).shortDescription.flanked("Digest(", ")")
                case Function.cborTag:
                    return try KnownFunctions.name(for: Function(untaggedCBOR: cbor), knownFunctions: context?.functions).flanked("«", "»")
                case Parameter.cborTag:
                    return try KnownParameters.name(for: Parameter(untaggedCBOR: cbor), knownParameters: context?.parameters).flanked("❰", "❱")
                case Envelope.requestCBORTag:
                    return Envelope(cbor).format(context: context).flanked("request(", ")")
                case Envelope.responseCBORTag:
                    return Envelope(cbor).format(context: context).flanked("response(", ")")
                default:
                    let name = name(for: tag, knownTags: context)
                    return "\(name)(\(cbor.envelopeSummary(maxLength: maxLength, context: context)))"
                }
            case .map(_):
                return "Map"
            case .simple(let v):
                return v.description
            }
        } catch {
            return "<error>"
        }
    }
}

extension CBOR: EnvelopeFormat {
    func formatItem(context: FormatContext? = nil) -> EnvelopeFormatItem {
        do {
            switch self {
            case CBOR.tagged(Envelope.cborTag, cbor):
                return try Envelope(untaggedCBOR: cbor).formatItem(context: context)
            default:
                return .item(envelopeSummary(context: context))
            }
        } catch {
            return "<error>"
        }
    }
}

extension Envelope: EnvelopeFormat {
    func formatItem(context: FormatContext? = nil) -> EnvelopeFormatItem {
        switch self {
        case .leaf(let cbor, _):
            return cbor.formatItem(context: context)
        case .knownValue(let predicate, _):
            return predicate.formatItem(context: context)
        case .wrapped(let envelope, _):
            return .list([.begin("{"), envelope.formatItem(context: context), .end("}")])
        case .assertion(let assertion):
            return assertion.formatItem(context: context)
        case .encrypted(_):
            return .item("ENCRYPTED")
        case .node(subject: let subject, assertions: let assertions, digest: _):
            var items: [EnvelopeFormatItem] = []

            let subjectItem = subject.formatItem(context: context)
            var elidedCount = 0
            var encryptedCount = 0
            var assertionsItems: [[EnvelopeFormatItem]] = []
            assertions.forEach {
                if $0.isElided {
                    elidedCount += 1
                } else if $0.isEncrypted {
                    encryptedCount += 1
                } else {
                    assertionsItems.append([$0.formatItem(context: context)])
                }
            }
            assertionsItems.sort { $0.lexicographicallyPrecedes($1) }
            if elidedCount > 1 {
                assertionsItems.append([.item("ELIDED (\(elidedCount))")])
            } else if elidedCount > 0 {
                assertionsItems.append([.item("ELIDED")])
            }
            if encryptedCount > 1 {
                assertionsItems.append([.item("ENCRYPTED (\(encryptedCount))")])
            } else if encryptedCount > 0 {
                assertionsItems.append([.item("ENCRYPTED")])
            }
            let joinedAssertionsItems = Array(assertionsItems.joined(separator: [.separator]))

            let needsBraces: Bool = subject.isSubjectAssertion
            
            if needsBraces {
                items.append(.begin("{"))
            }
            items.append(subjectItem)
            if needsBraces {
                items.append(.end("}"))
            }
            items.append(.begin("["))
            items.append(.list(joinedAssertionsItems))
            items.append(.end("]"))

            return .list(items)
        case .elided:
            return .item("ELIDED")
        }
    }
}

enum EnvelopeFormatItem {
    case begin(String)
    case end(String)
    case item(String)
    case separator
    case list([EnvelopeFormatItem])
}

extension EnvelopeFormatItem: ExpressibleByStringLiteral {
    init(stringLiteral value: StringLiteralType) {
        self = .item(value)
    }
}

extension EnvelopeFormatItem: CustomStringConvertible {
    var description: String {
        switch self {
        case .begin(let string):
            return ".begin(\(string))"
        case .end(let string):
            return ".end(\(string))"
        case .item(let string):
            return ".item(\(string))"
        case .separator:
            return ".separator"
        case .list(let list):
            return ".list(\(list))"
        }
    }
}

extension EnvelopeFormatItem {
    var flatten: [EnvelopeFormatItem] {
        if case let .list(items) = self {
            return items.map { $0.flatten }.flatMap { $0 }
        } else {
            return [self]
        }
    }
    
    func nicen(_ items: [EnvelopeFormatItem]) -> [EnvelopeFormatItem] {
        var input = items
        var result: [EnvelopeFormatItem] = []
        
        while !input.isEmpty {
            let current = input.removeFirst()
            if input.isEmpty {
                result.append(current)
                break
            }
            if case .end(let endString) = current {
                if case .begin(let beginString) = input.first! {
                    result.append(.end("\(endString) \(beginString)"))
                    result.append(.begin(""))
                    input.removeFirst()
                } else {
                    result.append(current)
                }
            } else {
                result.append(current)
            }
        }
        
        return result
    }
    
    func indent(_ level: Int) -> String {
        String(repeating: " ", count: level * 4)
    }
    
    private func addSpaceAtEndIfNeeded(_ s: String) -> String {
        guard !s.isEmpty else {
            return " "
        }
        if s.last! == " " {
            return s
        } else {
            return s + " "
        }
    }
    
    var format: String {
        var lines: [String] = []
        var level = 0
        var currentLine = ""
        let items = nicen(flatten)
        for item in items {
            switch item {
            case .begin(let string):
                if !string.isEmpty {
                    let c = currentLine.isEmpty ? string : addSpaceAtEndIfNeeded(currentLine) + string
                    lines.append(indent(level) + c + .newline)
                }
                level += 1
                currentLine = ""
            case .end(let string):
                if !currentLine.isEmpty {
                    lines.append(indent(level) + currentLine + .newline)
                    currentLine = ""
                }
                level -= 1
                lines.append(indent(level) + string + .newline)
            case .item(let string):
                currentLine += string
            case .separator:
                if !currentLine.isEmpty {
                    lines.append(indent(level) + currentLine + .newline)
                    currentLine = ""
                }
            case .list:
                lines.append("<list>")
            }
        }
        if !currentLine.isEmpty {
            lines.append(currentLine)
        }
        return lines.joined()
    }
}

extension EnvelopeFormatItem: Equatable {
    static func ==(lhs: EnvelopeFormatItem, rhs: EnvelopeFormatItem) -> Bool {
        if case let .begin(l) = lhs, case let .begin(r) = rhs, l == r { return true }
        if case let .end(l) = lhs, case let .end(r) = rhs, l == r { return true }
        if case let .item(l) = lhs, case let .item(r) = rhs, l == r { return true }
        if case .separator = lhs, case .separator = rhs { return true }
        if case let .list(l) = lhs, case let .list(r) = rhs, l == r { return true }
        return false
    }
}

extension EnvelopeFormatItem {
    var index: Int {
        switch self {
        case .begin:
            return 1
        case .end:
            return 2
        case .item:
            return 3
        case .separator:
            return 4
        case .list:
            return 5
        }
    }
}

extension EnvelopeFormatItem: Comparable {
    static func <(lhs: EnvelopeFormatItem, rhs: EnvelopeFormatItem) -> Bool {
        let lIndex = lhs.index
        let rIndex = rhs.index
        if lIndex < rIndex {
            return true
        } else if rIndex < lIndex {
            return false
        }
        if case let .begin(l) = lhs, case let .begin(r) = rhs, l < r { return true }
        if case let .end(l) = lhs, case let .end(r) = rhs, l < r { return true }
        if case let .item(l) = lhs, case let .item(r) = rhs, l < r { return true }
        if case .separator = lhs, case .separator = rhs { return false }
        if case let .list(l) = lhs, case let .list(r) = rhs, l.lexicographicallyPrecedes(r) { return true }
        return false
    }
}
