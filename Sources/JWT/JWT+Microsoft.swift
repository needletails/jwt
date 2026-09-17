#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging
import Vapor

extension Request.JWT {
    public var microsoft: Microsoft {
        .init(_jwt: self)
    }

    public struct Microsoft {
        public let _jwt: Request.JWT

        public func verify(
            applicationIdentifier: String? = nil
        ) async throws -> MicrosoftIdentityToken {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                Logger.current.error("Request is missing JWT bearer header.")
                throw Abort(.unauthorized)
            }
            return try await self.verify(token, applicationIdentifier: applicationIdentifier)
        }

        public func verify(
            _ message: String,
            applicationIdentifier: String? = nil
        ) async throws -> MicrosoftIdentityToken {
            try await self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
        }

        public func verify(
            _ message: some DataProtocol & Sendable,
            applicationIdentifier: String? = nil
        ) async throws -> MicrosoftIdentityToken {
            let keys = try await self._jwt._request.application.jwt.microsoft.keys(on: self._jwt._request)
            let token = try await keys.verify(message, as: MicrosoftIdentityToken.self)
            if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.microsoft.applicationIdentifier {
                try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
            }
            return token
        }
    }
}

extension Application.JWT {
    public var microsoft: Microsoft {
        .init(_jwt: self)
    }

    public struct Microsoft {
        public let _jwt: Application.JWT

        public func keys(on request: Request) async throws -> JWTKeyCollection {
            try await JWTKeyCollection().add(jwks: self.jwks.get())
        }

        public var jwks: EndpointCache<JWKS> {
            self._jwt.storage.microsoft.jwks
        }

        public var jwksEndpoint: URI {
            get {
                self._jwt.storage.microsoft.jwksEndpoint
            }
            nonmutating set {
                self._jwt.storage.microsoft.setEndpoint(newValue, client: self._jwt._application.client)
            }
        }

        public var applicationIdentifier: String? {
            get {
                self._jwt.storage.microsoft.applicationIdentifier
            }
            nonmutating set {
                self._jwt.storage.microsoft.applicationIdentifier = newValue
            }
        }
    }
}
