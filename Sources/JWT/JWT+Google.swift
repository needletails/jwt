#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging
import Vapor

extension Request.JWT {
    public var google: Google {
        .init(_jwt: self)
    }

    public struct Google: Sendable {
        public let _jwt: Request.JWT

        public func verify(
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) async throws -> GoogleIdentityToken {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                Logger.current.error("Request is missing JWT bearer header.")
                throw Abort(.unauthorized)
            }
            return try await self.verify(
                token,
                applicationIdentifier: applicationIdentifier,
                gSuiteDomainName: gSuiteDomainName
            )
        }

        public func verify(
            _ message: String,
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) async throws -> GoogleIdentityToken {
            try await self.verify(
                [UInt8](message.utf8),
                applicationIdentifier: applicationIdentifier,
                gSuiteDomainName: gSuiteDomainName
            )
        }

        public func verify(
            _ message: some DataProtocol & Sendable,
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) async throws -> GoogleIdentityToken {
            let keys = try await self._jwt._request.application.jwt.google.keys(on: self._jwt._request)
            let token = try await keys.verify(message, as: GoogleIdentityToken.self)
            if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.google.applicationIdentifier {
                try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
            }
            if let gSuiteDomainName = gSuiteDomainName ?? self._jwt._request.application.jwt.google.gSuiteDomainName {
                guard let hd = token.hostedDomain, hd.value == gSuiteDomainName else {
                    throw JWTError.claimVerificationFailure(
                        failedClaim: token.hostedDomain,
                        reason: "Hosted domain claim does not match gSuite domain name"
                    )
                }
            }
            return token
        }
    }
}

extension Application.JWT {
    public var google: Google {
        .init(_jwt: self)
    }

    public struct Google: Sendable {
        public let _jwt: Application.JWT

        public func keys(on request: Request) async throws -> JWTKeyCollection {
            try await JWTKeyCollection().add(jwks: self.jwks.get())
        }

        public var jwks: EndpointCache<JWKS> {
            self._jwt.storage.google.jwks
        }

        public var jwksEndpoint: URI {
            get {
                self._jwt.storage.google.jwksEndpoint
            }
            nonmutating set {
                self._jwt.storage.google.setEndpoint(newValue, client: self._jwt._application.client)
            }
        }

        public var applicationIdentifier: String? {
            get {
                self._jwt.storage.google.applicationIdentifier
            }
            nonmutating set {
                self._jwt.storage.google.applicationIdentifier = newValue
            }
        }

        public var gSuiteDomainName: String? {
            get {
                self._jwt.storage.google.gSuiteDomainName
            }
            nonmutating set {
                self._jwt.storage.google.gSuiteDomainName = newValue
            }
        }
    }
}
