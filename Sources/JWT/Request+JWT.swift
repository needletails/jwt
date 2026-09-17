#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging
import Vapor

/// Binds ``Request/application`` for the duration of `operation`.
///
/// Prefer `Application.testing` so JWT middleware binds automatically on HTTP.
/// Use this for unit tests that invoke handlers or middleware without going through the responder.
public func withJWTApplication<T>(
    _ application: Application,
    isolation: isolated (any Actor)? = #isolation,
    _ operation: () async throws -> T
) async rethrows -> T {
    try await JWTApplicationContext.$application.withValue(application) {
        try await operation()
    }
}

extension Request {
    /// Application bound for this request by JWT's context middleware.
    ///
    /// Vapor 5 removed `Request.application`; accessing ``Application/jwt`` during configuration
    /// installs the middleware that restores it for request handlers.
    public var application: Application {
        guard let application = JWTApplicationContext.application else {
            fatalError(
                """
                Request.application is unavailable outside a JWT-bound request context. \
                Access Application.jwt during configuration (before the app starts) so the \
                context middleware is installed.
                """
            )
        }
        return application
    }

    public var jwt: JWT {
        .init(_request: self)
    }

    public struct JWT: Sendable {
        public let _request: Request

        @discardableResult
        public func verify<Payload>(as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            guard let token = self._request.headers.bearerAuthorization?.token else {
                Logger.current.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return try await self.verify(token, as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: String, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            try await self.verify([UInt8](message.utf8), as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: some DataProtocol & Sendable, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            try await self._request.application.jwt.keys.verify(message, as: Payload.self)
        }

        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil, header: JWTHeader = .init()) async throws -> String
        where Payload: JWTPayload {
            try await self._request.application.jwt.keys.sign(jwt, kid: kid, header: header)
        }
    }
}
