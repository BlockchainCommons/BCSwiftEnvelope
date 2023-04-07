import Foundation

public struct KnownValues {
    var knownValuesByRawValue: [UInt64: KnownValue]
    
    public init<T>(_ knownValues: T) where T: Sequence, T.Element == KnownValue {
        knownValuesByRawValue = [:]
        for knownValue in knownValues {
            Self._insert(knownValue, knownValuesByRawValue: &knownValuesByRawValue)
        }
    }
    
    public mutating func insert(_ knownValue: KnownValue) {
        Self._insert(knownValue, knownValuesByRawValue: &knownValuesByRawValue)
    }
    
    public func assignedName(for knownValue: KnownValue) -> String? {
        knownValuesByRawValue[knownValue.value]?.assignedName
    }
    
    public func name(for knownValue: KnownValue) -> String {
        assignedName(for: knownValue) ?? knownValue.name
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
    
    public static func name(for knownValue: KnownValue, knownValues: KnownValues? = nil) -> String {
        knownValues?.name(for: knownValue) ?? knownValue.name
    }

    static func _insert(_ knownValue: KnownValue, knownValuesByRawValue: inout [UInt64: KnownValue]) {
        knownValuesByRawValue[knownValue.value] = knownValue
    }
}

extension KnownValues: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: KnownValue...) {
        self.init(elements)
    }
}
