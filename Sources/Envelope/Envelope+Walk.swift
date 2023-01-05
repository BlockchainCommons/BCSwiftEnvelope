import Foundation

public extension Envelope {
    /// A user-provided function called for each envelope element during a call to ``walk(hideNodes:visit:)``.
    ///
    /// The `Parent` type is user-provided, and each call to the `Visitor` returns the
    /// parent object to be provided to all calls to children of the element.
    typealias Visitor<Parent> = (Envelope, Int, EdgeType, Parent?) -> Parent?
    
    /// The type of the element at the tail of an incoming edge.
    enum EdgeType {
        case none
        case subject
        case assertion
        case predicate
        case object
        case wrapped
        
        var label: String? {
            switch self {
            case .subject, .wrapped:
                return "subj"
            case .predicate:
                return "pred"
            case .object:
                return "obj"
            default:
                return nil
            }
        }
    }
    
    /// Perform a depth-first walk of the envelope's elements.
    ///
    /// The call is generic over the `Parent` type, which is user defined and used by callers
    /// who wish to compose other tree-like structures from an ``Envelope``. `Parent` may be `Void`.
    ///
    /// - Parameters:
    ///   - hideNodes: `true` if `.node` cases are to be skipped. Default: `false`
    ///   - visit: A ``Visitor`` function.
    func walk<Parent>(hideNodes: Bool = false, visit: Visitor<Parent>) {
        if hideNodes {
            walkTree { envelope, level, parent in
                visit(envelope, level, .none, parent)
            }
        } else {
            walkStructure(visit: visit)
        }
    }
}

extension Envelope {
    func walkStructure<Parent>(visit: Visitor<Parent>) {
        walkStructure(level: 0, incomingEdge: .none, parent: nil, visit: visit)
    }
    
    func walkStructure<Parent>(level: Int, incomingEdge: EdgeType, parent: Parent?, visit: Visitor<Parent>) {
        let parent = visit(self, level, incomingEdge, parent)
        let nextLevel = level + 1
        switch self {
        case .node(let subject, let assertions, _):
            subject.walkStructure(level: nextLevel, incomingEdge: .subject, parent: parent, visit: visit)
            for assertion in assertions {
                assertion.walkStructure(level: nextLevel, incomingEdge: .assertion, parent: parent, visit: visit)
            }
        case .wrapped(let envelope, _):
            envelope.walkStructure(level: nextLevel, incomingEdge: .wrapped, parent: parent, visit: visit)
        case .assertion(let assertion):
            assertion.predicate.walkStructure(level: nextLevel, incomingEdge: .predicate, parent: parent, visit: visit)
            assertion.object.walkStructure(level: nextLevel, incomingEdge: .object, parent: parent, visit: visit)
        default:
            break
        }
    }

    func walkTree<Parent>(visit: (Envelope, Int, Parent?) -> Parent?) {
        walkTree(level: 0, parent: nil, visit: visit)
    }
    
    @discardableResult
    func walkTree<Parent>(level: Int, parent: Parent?, visit: (Envelope, Int, Parent?) -> Parent?) -> Parent? {
        var parent = parent
        var subjectLevel = level
        if !isNode {
            parent = visit(self, level, parent)
            subjectLevel = level + 1
        }
        switch self {
        case .node(let subject, let assertions, _):
            let assertionParent = subject.walkTree(level: subjectLevel, parent: parent, visit: visit)
            let assertionLevel = subjectLevel + 1
            for assertion in assertions {
                assertion.walkTree(level: assertionLevel, parent: assertionParent, visit: visit)
            }
        case .wrapped(let envelope, _):
            envelope.walkTree(level: subjectLevel, parent: parent, visit: visit)
        case .assertion(let assertion):
            assertion.predicate.walkTree(level: subjectLevel, parent: parent, visit: visit)
            assertion.object.walkTree(level: subjectLevel, parent: parent, visit: visit)
        default:
            break
        }
        return parent
    }
}
