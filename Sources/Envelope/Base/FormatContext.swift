import Foundation
import WolfBase
import SecureComponents

public struct FormatContext {
    public let tags: TagsStore
    public let knownValues: KnownValuesStore
    public let functions: FunctionsStore
    public let parameters: ParametersStore
    
    public init(tags: TagsStore = [], knownValues: KnownValuesStore = [], functions: FunctionsStore = [], parameters: ParametersStore = []) {
        self.tags = tags
        self.knownValues = knownValues
        self.functions = functions
        self.parameters = parameters
    }
}

extension FormatContext: TagsStoreProtocol {
    public func assignedName(for tag: Tag) -> String? {
        tags.assignedName(for: tag)
    }
    
    public func name(for tag: Tag) -> String {
        tags.name(for: tag)
    }

    public func tag(for value: UInt64) -> Tag? {
        tags.tag(for: value)
    }

    public func tag(for name: String) -> Tag? {
        tags.tag(for: name)
    }
}
