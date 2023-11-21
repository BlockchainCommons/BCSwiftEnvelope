import Foundation
import SecureComponents
import WolfBase
import Envelope

/// This is a mostly-duplicate of the `Seed` struct from BCSwiftFoundation, used here for demonstration and testing purposes only.
struct Seed {
    let data: Data
    var name: String
    var note: String
    var creationDate: Date?
    
    init?(data: Data, name: String = "", note: String = "", creationDate: Date? = nil) {
        self.data = data
        self.name = name
        self.note = note
        self.creationDate = creationDate
    }
}

extension Seed: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        data
    }
}

extension Seed {
    var envelope: Envelope {
        var e = Envelope(data)
            .addType(.Seed)
            .addAssertion(.date, creationDate)
        
        if !name.isEmpty {
            e = e.addAssertion(.hasName, name)
        }

        if !note.isEmpty {
            e = e.addAssertion(.note, note)
        }
        
        return e
    }
    
    init(_ envelope: Envelope) throws {
        try envelope.checkType(.Seed)
        if
            let subjectLeaf = envelope.leaf,
            case CBOR.tagged(.seedV1, let item) = subjectLeaf
        {
            self = try Self.init(untaggedCBOR: item)
            return
        }

        let data = try envelope.extractSubject(Data.self)
        let name = try envelope.extractOptionalObject(String.self, forPredicate: .hasName) ?? ""
        let note = try envelope.extractOptionalObject(String.self, forPredicate: .note) ?? ""
        let creationDate = try? envelope.extractObject(Date.self, forPredicate: .date)
        guard let result = Self.init(data: data, name: name, note: note, creationDate: creationDate) else {
            throw EnvelopeError.invalidFormat
        }
        self = result
    }
}

extension Seed: URCodable {
    static var cborTags = [Tag.seed, Tag.seedV1]
    
    var untaggedCBOR: CBOR {
        var map: Map = [1: data]
        if let creationDate {
            map[2] = creationDate
        }
        if !name.isEmpty {
            map[3] = name
        }
        if !note.isEmpty {
            map[4] = note
        }
        return map.cbor
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        guard
            let dataItem = map.get(1),
            case let CBOR.bytes(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw CBORError.invalidFormat
        }
        let data = bytes.data

        let creationDate: Date?
        if let dateItem = map.get(2) {
            guard let d = try? Date(cbor: dateItem) else {
                // CreationDate field doesn't contain a date.
                throw CBORError.invalidFormat
            }
            creationDate = d
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = map.get(3) {
            guard case let CBOR.text(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = map.get(4) {
            guard case let CBOR.text(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self = Seed(data: data, name: name, note: note, creationDate: creationDate)!
    }
}
