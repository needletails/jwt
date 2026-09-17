#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging
import Vapor

extension Request.JWT {
    public var firebaseAuth: FirebaseAuth {
        .init(_jwt: self)
    }

    public struct FirebaseAuth: Sendable {
        public let _jwt: Request.JWT

        public func verify(
            applicationIdentifier: String? = nil
        ) async throws -> FirebaseAuthIdentityToken {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                Logger.current.error("Request is missing JWT bearer header.")
                throw Abort(.unauthorized)
            }
            return try await self.verify(token, applicationIdentifier: applicationIdentifier)
        }

        public func verify(
            _ message: String,
            applicationIdentifier: String? = nil
        ) async throws -> FirebaseAuthIdentityToken {
            try await self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
        }

        public func verify(
            _ message: some DataProtocol & Sendable,
            applicationIdentifier: String? = nil
        ) async throws -> FirebaseAuthIdentityToken {
            let keys = try await self._jwt._request.application.jwt.firebaseAuth.keys(on: self._jwt._request)
            let token = try await keys.verify(message, as: FirebaseAuthIdentityToken.self)
            if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.firebaseAuth.applicationIdentifier {
                try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
                guard token.audience.value.first == applicationIdentifier else {
                    throw JWTError.claimVerificationFailure(
                        failedClaim: token.audience,
                        reason: "Audience claim does not match expected value"
                    )
                }
                guard token.issuer.value == "https://securetoken.google.com/\(applicationIdentifier)" else {
                    throw JWTError.claimVerificationFailure(
                        failedClaim: token.issuer,
                        reason: "Issuer claim does not match expected value"
                    )
                }
            }
            return token
        }
    }
}

extension Application.JWT {
    public var firebaseAuth: FirebaseAuth {
        .init(_jwt: self)
    }

    public struct FirebaseAuth: Sendable {
        public let _jwt: Application.JWT

        public func keys(on request: Request) async throws -> JWTKeyCollection {
            try await JWTKeyCollection().add(jwks: self.jwks.get())
        }

        public var jwks: EndpointCache<JWKS> {
            self._jwt.storage.firebaseAuth.jwks
        }

        public var jwksEndpoint: URI {
            get {
                self._jwt.storage.firebaseAuth.jwksEndpoint
            }
            nonmutating set {
                self._jwt.storage.firebaseAuth.setEndpoint(newValue, client: self._jwt._application.client)
            }
        }

        public var applicationIdentifier: String? {
            get {
                self._jwt.storage.firebaseAuth.applicationIdentifier
            }
            nonmutating set {
                self._jwt.storage.firebaseAuth.applicationIdentifier = newValue
            }
        }
    }
}
