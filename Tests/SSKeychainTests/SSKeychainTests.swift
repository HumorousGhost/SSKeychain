import XCTest
@testable import SSKeychain

final class SSKeychainTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(SSKeychain().text, "Hello, World!")
    }
}
