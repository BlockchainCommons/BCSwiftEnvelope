import Foundation
import Graph
import SecureComponents

/// Support for the tree text output format for ``Envelope``.

public extension Envelope {
    /// Returns the tree notation for this envelope.
    ///
    /// See <doc:OutputFormats> for more information.
    ///
    /// - Parameters:
    ///   - hideNodes: `true` if the semantic layout of the envelope is to be displayed,
    ///   `false` if the structural layout of the envelope is to be displayed.
    ///   - target: All elements in `target` will be highlighted with an asterisk.
    ///
    /// - Returns: The tree notation description.
    func treeFormat(hideNodes: Bool = false, highlighting target: Set<Digest> = []) -> String {
        var elements: [TreeElement] = []
        walk(hideNodes: hideNodes) { (envelope, level, incomingEdge, _) -> Int? in
            elements.append(TreeElement(level: level, envelope: envelope, incomingEdge: incomingEdge, showID: !hideNodes, isHighlighted: target.contains(envelope.digest)))
            return nil
        }
        return elements.map { $0.string }.joined(separator: "\n")
    }
}

struct TreeElement {
    let level: Int
    let envelope: Envelope
    let incomingEdge: Envelope.EdgeType
    let showID: Bool
    let isHighlighted: Bool

    init(level: Int, envelope: Envelope, incomingEdge: Envelope.EdgeType = .none, showID: Bool = true, isHighlighted: Bool = false) {
        self.level = level
        self.envelope = envelope
        self.incomingEdge = incomingEdge
        self.showID = showID
        self.isHighlighted = isHighlighted
    }
    
    var string: String {
        let line = [
            isHighlighted ? "*" : nil,
            showID ? envelope.shortID : nil,
            incomingEdge.label,
            envelope.summary(maxLength: 40)
        ]
            .compactMap { $0 }
            .joined(separator: " ")
        let indent = String(repeating: " ", count: level * 4)
        return indent + line
    }
}
