import Foundation

public extension Envelope {
    func addType(_ type: Envelope) -> Envelope {
        addAssertion(.isA, type)
    }
    
    func addType(_ type: KnownValue) -> Envelope {
        addType(Envelope(type))
    }
    
    func addType(if condition: Bool, _ type: Envelope) -> Envelope {
        guard condition else {
            return self
        }
        return addType(type)
    }
    
    func addType(if condition: Bool, _ type: KnownValue) -> Envelope {
        guard condition else {
            return self
        }
        return addType(type)
    }
    
    var types: [Envelope] {
        objects(forPredicate: .isA)
    }
    
    var type: Envelope {
        get throws {
            let t = types
            guard t.count == 1 else {
                throw EnvelopeError.ambiguousPredicate
            }
            return t.first!
        }
    }
    
    func hasType(_ type: Envelope) -> Bool {
        types.contains { $0.digest == type.digest }
    }
    
    func hasType(_ type: KnownValue) -> Bool {
        types.contains { $0.subject.digest == Envelope(type).digest }
    }
    
    func checkType(_ type: Envelope) throws {
        guard hasType(type) else {
            throw EnvelopeError.invalidFormat
        }
    }
    
    func checkType(_ type: KnownValue) throws {
        guard hasType(type) else {
            throw EnvelopeError.invalidFormat
        }
    }
}
