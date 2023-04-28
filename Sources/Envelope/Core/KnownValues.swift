import Foundation

public struct KnownValues {
    var knownValuesByRawValue: [UInt64: KnownValue]
    var knownValuesByAssignedName: [String: KnownValue]
    
    public init<T>(_ knownValues: T) where T: Sequence, T.Element == KnownValue {
        knownValuesByRawValue = [:]
        knownValuesByAssignedName = [:]
        for knownValue in knownValues {
            Self._insert(knownValue, knownValuesByRawValue: &knownValuesByRawValue, knownValuesByAssignedName: &knownValuesByAssignedName)
        }
    }
    
    public mutating func insert(_ knownValue: KnownValue) {
        Self._insert(knownValue, knownValuesByRawValue: &knownValuesByRawValue, knownValuesByAssignedName: &knownValuesByAssignedName)
    }
    
    public func assignedName(for knownValue: KnownValue) -> String? {
        knownValuesByRawValue[knownValue.value]?.assignedName
    }
    
    public func name(for knownValue: KnownValue) -> String {
        assignedName(for: knownValue) ?? knownValue.name
    }
    
    public func knownValue(named assignedName: String) -> KnownValue? {
        knownValuesByAssignedName[assignedName]
    }
    
    public static func knownValue(for rawValue: UInt64, knownValues: KnownValues? = nil) -> KnownValue {
        guard
            let knownValues,
            let namedKnownValue = knownValues.knownValuesByRawValue[rawValue]
        else {
            return KnownValue(rawValue)
        }
        return namedKnownValue
    }
    
    public static func knownValue(named assignedName: String, knownValues: KnownValues? = nil) -> KnownValue? {
        guard
            let knownValues,
            let knownValue = knownValues.knownValuesByAssignedName[assignedName]
        else {
            return nil
        }
        return knownValue
    }
    
    public static func name(for knownValue: KnownValue, knownValues: KnownValues? = nil) -> String {
        knownValues?.name(for: knownValue) ?? knownValue.name
    }

    static func _insert(_ knownValue: KnownValue, knownValuesByRawValue: inout [UInt64: KnownValue], knownValuesByAssignedName: inout [String: KnownValue]) {
        knownValuesByRawValue[knownValue.value] = knownValue
        if let name = knownValue.assignedName {
            knownValuesByAssignedName[name] = knownValue
        }
    }
}

extension KnownValues: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: KnownValue...) {
        self.init(elements)
    }
}
