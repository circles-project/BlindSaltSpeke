import Cbsspeke

public struct BlindSaltSpeke {
    
    public struct BSSpekeError: Error {
        var msg: String
        
        init(msg: String) {
            self.msg = msg
        }
    }
    
    public class ServerSession {
        private var Cctx = Cbsspeke.bsspeke_server_ctx()
        private var salt: [UInt8]
        
        public init(serverId: String, clientId: String, salt: [UInt8]) {
            self.salt = salt
            Cbsspeke.bsspeke_server_init(&Cctx,
                                         serverId, serverId.utf8CString.count-1, // Subtract 1 because .count includes the trailing \0
                                         clientId, clientId.utf8CString.count-1) // Subtract 1 because .count includes the trailing \0
        }
        
        public func blindSalt(blind: [UInt8]) throws -> [UInt8] {
            var blindSalt: [UInt8] = .init(repeating: 0, count: 32)
            
            assert(blind.count == 32)
            
            let ptr = UnsafeMutablePointer(mutating: blindSalt)
            
            Cbsspeke.bsspeke_server_blind_salt(ptr,
                                               blind,
                                               salt, salt.count)
            
            return blindSalt
        }
        
        public func generateB(basePoint: [UInt8]) -> [UInt8] {
            assert(basePoint.count == 32)
            Cbsspeke.bsspeke_server_generate_B(basePoint, &Cctx)
            var B: [UInt8] = .init(repeating: 0, count: 32)
            let ptr = UnsafeMutablePointer(mutating: B)
            Cbsspeke.bsspeke_server_get_B(ptr, &Cctx)
            return B
        }
        
        public func deriveSharedKey(A: [UInt8],
                                    V: [UInt8]) {
            assert(A.count == 32)
            assert(V.count == 32)
            Cbsspeke.bsspeke_server_derive_shared_key(A, V, &Cctx)
        }
        
        public func generateVerifier() -> [UInt8] {
            var verifier: [UInt8] = .init(repeating: 0, count: 32)
            var ptr = UnsafeMutablePointer(mutating: verifier)
            Cbsspeke.bsspeke_server_generate_verifier(ptr, &Cctx)
            return verifier
        }
        
        public func verifyClient(verifier: [UInt8]) -> Bool {
            assert(verifier.count == 32)
            
            let rc: Int32 = Cbsspeke.bsspeke_server_verify_client(verifier, &Cctx)
            
            return rc == 0
        }
    }
    
    public class ClientSession {
        private var Cctx = Cbsspeke.bsspeke_client_ctx()
        
        public init(clientId: String, serverId: String, password: String) throws {
            let rc: Int32
            rc = Cbsspeke.bsspeke_client_init(&Cctx,
                                              clientId, clientId.utf8CString.count,
                                              serverId, serverId.utf8CString.count,
                                              password, password.utf8CString.count)
            if rc != 0 {
                throw BSSpekeError(msg: "Failed to initialize client (rc = \(rc)")
            }
        }
        
        public func generateBlind() -> [UInt8] {
            var blind: [UInt8] = .init(repeating: 0, count: 32)
            Cbsspeke.bsspeke_client_generate_blind(UnsafeMutablePointer(mutating: blind), &Cctx)
            return blind
        }
        
        public func generatePandV(blindSalt: [UInt8], phfBlocks: UInt32, phfIterations: UInt32) throws -> ([UInt8], [UInt8]) {
            var P: [UInt8] = .init(repeating: 0, count: 32)
            var V: [UInt8] = .init(repeating: 0, count: 32)
            
            let ptrP = UnsafeMutablePointer(mutating: P)
            let ptrV = UnsafeMutablePointer(mutating: V)
            
            assert(blindSalt.count == 32)
            
            let rc = Cbsspeke.bsspeke_client_generate_P_and_V(ptrP, ptrV, blindSalt, phfBlocks, phfIterations, &Cctx)
            
            if rc != 0 {
                throw BSSpekeError(msg: "Failed to generate permanent public key")
            }
            
            return (P,V)
        }
        
        public func generateA(blindSalt: [UInt8], phfBlocks: UInt32, phfIterations: UInt32) throws -> [UInt8] {
            
            assert(blindSalt.count == 32)
            
            let rc = Cbsspeke.bsspeke_client_generate_A(blindSalt, phfBlocks, phfIterations, &Cctx)
            
            if rc != 0 {
                throw BSSpekeError(msg: "Failed to generate client ephemeral pubkey A")
            }
            
            var A: [UInt8] = .init(repeating: 0, count: 32)
            let ptr = UnsafeMutablePointer(mutating: A)
            Cbsspeke.bsspeke_client_get_A(ptr, &Cctx)
            return A
        }
        
        public func deriveSharedKey(serverPubkey: [UInt8]) {
            assert(serverPubkey.count == 32)
            
            Cbsspeke.bsspeke_client_derive_shared_key(serverPubkey, &Cctx)
        }
        
        public func generateVerifier() -> [UInt8] {
            var verifier: [UInt8] = .init(repeating: 0, count: 32)
            let ptr = UnsafeMutablePointer(mutating: verifier)
            Cbsspeke.bsspeke_client_generate_verifier(ptr, &Cctx)
            
            return verifier
        }
        
        public func verifyServer(verifier: [UInt8]) -> Bool {
            assert(verifier.count == 32)
            
            let rc = Cbsspeke.bsspeke_client_verify_server(verifier, &Cctx)
            
            return rc == 0
        }
    }
}
