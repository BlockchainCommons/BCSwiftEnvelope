import Foundation
import Graph
import GraphMermaid
import WolfBase

public extension Envelope {
    /// Returns the [Mermaid](https://mermaid.js.org/#/) format notation for this envelope.
    ///
    /// - Parameters:
    ///   - hideNodes: `true` if the semantic layout of the envelope is to be displayed,
    ///   `false` if the structural layout of the envelope is to be displayed.
    ///   - layoutDirection: The direction of layout, either `.leftToRight` (default) or `.topToBottom`.
    ///   - theme: The color scheme of the image, either `.color` (default) or `.monochrome`.
    ///
    /// - Returns: Mermaid code.
    func mermaidFormat(hideNodes: Bool = false, layoutDirection: MermaidOptions.LayoutDirection? = nil, theme: MermaidOptions.Theme? = nil) -> String {
        graph(hideNodes: hideNodes, data: MermaidOptions(layoutDirection: layoutDirection, theme: theme, includeDigests: !hideNodes)).mermaidFormat
    }
    
    /// Options for [Mermaid](https://mermaid.js.org/#/) output.
    struct MermaidOptions {
        public let layoutDirection: LayoutDirection
        public let theme: Theme
        public let includeDigests: Bool

        public init(layoutDirection: LayoutDirection? = nil, theme: Theme? = nil, includeDigests: Bool = true) {
            self.layoutDirection = layoutDirection ?? .leftToRight
            self.theme = theme ?? .color
            self.includeDigests = includeDigests
        }

        public enum LayoutDirection {
            case leftToRight
            case topToBottom
        }
        
        public enum Theme {
            case color
            case monochrome
        }
    }
}

typealias MermaidEnvelopeGraph = Graph<Int, Int, Envelope, EnvelopeEdgeData, Envelope.MermaidOptions>

extension MermaidEnvelopeGraph: MermaidEncodable {
    public var mermaidGraphAttributes: GraphAttributes {
        let layoutDirection: LayoutDirection
        switch self.data.layoutDirection {
        case .leftToRight:
            layoutDirection = .leftToRight
        case .topToBottom:
            layoutDirection = .topToBottom
        }
        return GraphAttributes(layoutDirection: layoutDirection)
    }
    
    public func mermaidNodeAttributes(_ node: Int) -> NodeAttributes {
        let envelope = try! nodeData(node)
        var labelComponents: [String] = []
        if data.includeDigests {
            labelComponents.append(envelope.shortID)
        }
        labelComponents.append(envelope.summary(maxLength: 40).replacingOccurrences(of: "\"", with: "#quot;"))
        let label = labelComponents.joined(separator: "<br/>").flanked("\"")

        var attributes = NodeAttributes(label: label)
        attributes.strokeWidth = 3
        switch envelope {
        case .node(_, _, _):
            attributes.shape = .circle
            attributes.strokeColor = "red"
        case .leaf(_, _):
            attributes.shape = .rectangle
            attributes.strokeColor = "#55f"
        case .wrapped(_, _):
            attributes.shape = .trapezoid
            attributes.strokeColor = "red"
        case .knownValue(_, _):
            attributes.shape = .parallelogram
            attributes.strokeColor = "#55f"
        case .assertion(_):
            attributes.shape = .stadium
            attributes.strokeColor = "red"
        case .encrypted(_):
            attributes.shape = .asymmetric
            attributes.dashArray = [5, 5]
            attributes.strokeColor = "#55f"
        case .elided(_):
            attributes.shape = .hexagon
            attributes.dashArray = [5, 5]
            attributes.strokeColor = "#55f"
        }
        
        if data.theme == .monochrome {
            attributes.strokeColor = nil
            attributes.fillColor = nil
        }
        
        return attributes
    }
    
    public func mermaidEdgeAttributes(_ edge: Int) -> EdgeAttributes {
        let edgeAttributes = try! edgeData(edge)
        var attributes = EdgeAttributes()
        attributes.strokeWidth = 2
        attributes.label = edgeAttributes.type.label
        switch edgeAttributes.type {
        case .subject:
            attributes.strokeColor = "red"
        case .predicate:
            attributes.strokeColor = "green"
        case .object:
            attributes.strokeColor = "#55f"
        case .wrapped:
            attributes.strokeColor = "red"
        default:
            break
        }
        
        if data.theme == .monochrome {
            attributes.strokeColor = nil
        }
        
        return attributes
    }
}

struct EnvelopeEdgeData {
    let type: Envelope.EdgeType
}

extension Envelope {
    var shortID: String {
        self.digest.shortDescription
    }
    
    func summary(maxLength: Int = .max) -> String {
        switch self {
        case .node(_, _, _):
            return "NODE"
        case .leaf(let cbor, _):
            return cbor.envelopeSummary(maxLength: maxLength)
        case .wrapped(_, _):
            return "WRAPPED"
        case .knownValue(let knownValue, _):
            return knownValue.name
        case .assertion(_):
            return "ASSERTION"
        case .encrypted(_):
            return "ENCRYPTED"
        case .elided(_):
            return "ELIDED"
        }
    }
}

struct EnvelopeGraphBuilder<GraphData> {
    typealias GraphType = Graph<Int, Int, Envelope, EnvelopeEdgeData, GraphData>
    var graph: GraphType
    var _nextNodeID = 1
    var _nextEdgeID = 1

    init(data: GraphData) {
        self.graph = Graph(data: data)
    }

    var nextNodeID: Int {
        mutating get {
            defer {
                _nextNodeID += 1
            }
            return _nextNodeID
        }
    }
    
    var nextEdgeID: Int {
        mutating get {
            defer {
                _nextEdgeID += 1
            }
            return _nextEdgeID
        }
    }
    
    init(_ envelope: Envelope, hideNodes: Bool, data: GraphData) {
        self.init(data: data)
        envelope.walk(hideNodes: hideNodes) { (envelope, level, incomingEdge, parent) -> Int? in
            let node = nextNodeID
            try! graph.newNode(node, data: envelope)
            if let parent {
                try! graph.newEdge(nextEdgeID, tail: parent, head: node, data: .init(type: incomingEdge))
            }
            return node
        }
    }
}

extension Envelope {
    func graph<GraphData>(hideNodes: Bool, data: GraphData) -> Graph<Int, Int, Envelope, EnvelopeEdgeData, GraphData> {
        EnvelopeGraphBuilder(self, hideNodes: hideNodes, data: data).graph
    }
    
    func graph(hideNodes: Bool) -> Graph<Int, Int, Envelope, EnvelopeEdgeData, Void> {
        graph(hideNodes: hideNodes, data: ())
    }
}
