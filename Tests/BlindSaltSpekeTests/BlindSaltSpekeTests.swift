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
    
    func testEnroll() throws {
        var server = BlindSaltSpeke.ServerSession(serverId: "matrix.example.com", clientId: "@bob:example.com", salt: .init(repeating: 0xff, count: 32))
        var client = try BlindSaltSpeke.ClientSession(clientId: "@bob:example.com", serverId: "matrix.example.com", password: "hunter2")
        
        // OPRF
        let blind = client.generateBlind()
        let blindSalt = try server.blindSalt(blind: blind)
        
        // Generate client's public params
        let (P,V) = try client.generatePandV(blindSalt: blindSalt, phfBlocks: ARGON2i_BLOCKS, phfIterations: ARGON2i_ITERATIONS)
        
        // Generate server's ephemeral pubkey
        let B = server.generateB(basePoint: P)
        
        // Generate client's ephemeral pubkey
        let A = try client.generateA(blindSalt: blindSalt, phfBlocks: ARGON2i_BLOCKS, phfIterations: ARGON2i_ITERATIONS)
        
        // Derive the shared key from each other's public keys
        client.deriveSharedKey(serverPubkey: B)
        server.deriveSharedKey(A: A, V: V)
        
        // Client proves its identity first
        let clientVerifier = client.generateVerifier()
        assert(server.verifyClient(verifier: clientVerifier))
        
        // Finally the server also proves its own identity
        let serverVerifier = server.generateVerifier()
        assert(client.verifyServer(verifier: serverVerifier))
    }
    
    func testLogin() throws {
        let storedP: [UInt8] = Array<UInt8>(hex: "2c51018f697699b0791f2d26caec53c922d21632c64c6cc9e0de8d48ffa77d2c").reversed()
        let storedV: [UInt8] = Array<UInt8>(hex: "253f91be3c4ee54486c8cf49677d14b7721cce9b4fe602a78b65a54fe286f0a7").reversed()
        
        var client = try BlindSaltSpeke.ClientSession(clientId: "@bob:example.com", serverId: "matrix.example.com", password: "hunter2")
        var server = BlindSaltSpeke.ServerSession(serverId: "matrix.example.com", clientId: "@bob:example.com", salt: .init(repeating: 0xff, count: 32))
        
        // Message 1
        // - Client sends clientId and blind
        let blind = client.generateBlind()
        
        // Message 2
        // - Server sends blindSalt and B
        let blindSalt = try server.blindSalt(blind: blind)
        let B = server.generateB(basePoint: storedP)
        
        // Message 3
        // - Client re-derives its own P and V, but doesn't expose them
        // - Client uses P to generate A
        // - Client uses A and V to derive the shared key
        // - Client uses shared key to generate its verifier
        let A = try client.generateA(blindSalt: blindSalt, phfBlocks: ARGON2i_BLOCKS, phfIterations: ARGON2i_ITERATIONS)
        client.deriveSharedKey(serverPubkey: B)
        let clientVerifier = client.generateVerifier()
        
        // Message 4
        // - Server uses A, B, and V to derive the shared key
        // - Server verifies the client
        // - Server generates its own verifier
        server.deriveSharedKey(A: A, V: storedV)
        assert(server.verifyClient(verifier: clientVerifier))
        let serverVerifier = server.generateVerifier()
        
        // Final check
        // - Client verifies the server
        assert(client.verifyServer(verifier: serverVerifier))
    }
}
