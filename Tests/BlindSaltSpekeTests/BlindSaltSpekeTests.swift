import XCTest
@testable import BlindSaltSpeke

final class BlindSaltSpekeTests: XCTestCase {
    /*
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(BlindSaltSpeke().text, "Hello, World!")
    }
    */
    
    let ARGON2i_BLOCKS: UInt32 = 100000
    let ARGON2i_ITERATIONS: UInt32 = 3
    
    func testDemo() throws {
        var server = BlindSaltSpeke.ServerSession(serverId: "matrix.example.com", clientId: "@bob:example.com", salt: .init(repeating: 0xff, count: 32))
        var client = try BlindSaltSpeke.ClientSession(clientId: "@bob:example.com", serverId: "matrix.example.com", password: "hunter2")
        
        // OPRF
        let blind = client.generateBlind()
        let blindSalt = try server.blindSalt(blind: blind)
        
        // Generate params
        let (P,V) = try client.generatePandV(blindSalt: blindSalt, phfBlocks: ARGON2i_BLOCKS, phfIterations: ARGON2i_ITERATIONS)
        
        let B = server.generateB(basePoint: P)
        
        let A = try client.generateA(blindSalt: blindSalt, phfBlocks: ARGON2i_BLOCKS, phfIterations: ARGON2i_ITERATIONS)
        
        client.deriveSharedKey(serverPubkey: B)
        server.deriveSharedKey(A: A, V: V)
        
        let serverVerifier = server.generateVerifier()
        
        assert(client.verifyServer(verifier: serverVerifier))
        
        let clientVerifier = client.generateVerifier()
        
        assert(server.verifyClient(verifier: clientVerifier))
        
    }
}
