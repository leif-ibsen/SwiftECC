//
//  Point.swift
//  AEC
//
//  Created by Leif Ibsen on 23/10/2019.
//

import BigInt

public struct Point: CustomStringConvertible, Equatable {
    
    // MARK: Constants
    
    /// The point at infinity
    public static let INFINITY = Point()
    
    
    // MARK: - Initializers

    private init() {
        self.x = BInt.ZERO
        self.y = BInt.ZERO
        self.infinity = true
    }
    
    /// Creates a Point from its x- and y-coordinates
    ///
    /// - Parameters:
    ///   - x: The x coordinate
    ///   - y: The y coordinate
    public init(_ x: BInt, _ y: BInt) {
        self.x = x
        self.y = y
        self.infinity = false
    }

    
    // MARK: Stored Properties
    
    /// The x coordinate
    public let x: BInt
    /// The y coordinate
    public let y: BInt
    /// Is `true` if `self` is the point at infinity, else `false`
    public let infinity: Bool
    
    
    // MARK: Computed Properties
    
    /// Textual description of `self`
    public var description: String {
        return self.infinity ? "Point(infinity)" : "Point(\(self.x), \(self.y))"
    }

    
    // MARK: Instance Methods
    
    /// Tests equality of Points
    ///
    /// - Parameters:
    ///   - p1: First point
    ///   - p2: Second point
    /// - Returns: `true` if p1 = p2, else `false`
    public static func == (p1: Point, p2: Point) -> Bool {
        return p1.x == p2.x && p1.y == p2.y && p1.infinity == p2.infinity
    }
    
}
