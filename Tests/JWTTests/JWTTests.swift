import Foundation
import HTTPTypes
import JWT
import JWTKit
import Testing
import Vapor
import VaporTesting

@Suite("JWTTests")
struct JWTTests {
    @Test("Shared keys identity")
    func sharedKeysIdentity() async throws {
        try await withApp { app in
            await app.jwt.keys.add(
                hmac: "a-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256
            )

            let payload = TestUser(name: "shared")
            let token = try await app.jwt.keys.sign(payload)

            app.get("me") { req async throws -> String in
                try await req.jwt.verify(as: TestUser.self).name
            }

            try await app.testing { client in
                let res = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(res.status == .ok)
                #expect(try await res.body.requireString() == "shared")
            }
        }
    }

    @Test("Test Docs")
    func docs() async throws {
        struct TestPayload: JWTPayload {
            enum CodingKeys: String, CodingKey {
                case subject = "sub"
                case expiration = "exp"
                case isAdmin = "admin"
            }

            var subject: SubjectClaim
            var expiration: ExpirationClaim
            var isAdmin: Bool

            func verify(using _: some JWTAlgorithm) async throws {
                try self.expiration.verifyNotExpired()
            }
        }

        try await withApp { app in
            await app.jwt.keys.add(
                hmac: "a-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256
            )
            await app.jwt.keys.add(
                hmac: "another-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256,
                kid: "a"
            )
            await app.jwt.keys.add(
                hmac: "a-third-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256,
                kid: "b"
            )

            app.jwt.apple.applicationIdentifier = "..."
            app.get("apple") { req async throws -> HTTPResponse.Status in
                _ = try await req.jwt.apple.verify()
                return .ok
            }

            app.jwt.google.applicationIdentifier = "..."
            app.jwt.google.gSuiteDomainName = "..."
            app.get("google") { req async throws -> HTTPResponse.Status in
                _ = try await req.jwt.google.verify()
                return .ok
            }

            app.jwt.microsoft.applicationIdentifier = "..."
            app.get("microsoft") { req async throws -> HTTPResponse.Status in
                _ = try await req.jwt.microsoft.verify()
                return .ok
            }

            app.jwt.firebaseAuth.applicationIdentifier = "..."
            app.get("firebase") { req async throws -> HTTPResponse.Status in
                _ = try await req.jwt.firebaseAuth.verify()
                return .ok
            }

            app.get("me") { req async throws -> HTTPResponse.Status in
                try await req.jwt.verify(as: TestPayload.self)
                return .ok
            }

            app.post("login") { req async throws -> [String: String] in
                let payload = TestPayload(
                    subject: "vapor",
                    expiration: .init(value: .distantFuture),
                    isAdmin: true
                )
                return try await [
                    "token": req.jwt.sign(payload, kid: "a")
                ]
            }

            let secure = app.grouped(TestUser.authenticator(), TestUser.guardMiddleware())
            secure.get("auth") { req -> TestUser in
                if let user = req.auth.get(TestUser.self) {
                    return user
                } else {
                    Issue.record("Shouldn't get here if the guard middleware is working.")
                    throw Abort(.internalServerError)
                }
            }

            let token =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.023MpwVrTea_vZ7uzgZGN1dB-XK88BSC0oyLnQDbxSI"

            try await app.testing { client in
                let me = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(me.status == .ok)

                let login = try await client.post("login")
                #expect(login.status == .ok)
                let body = try await login.content.decode([String: String].self)
                _ = try #require(body["token"])
            }
        }
    }

    @Test("Test Manual Authentication")
    func manualAuthentication() async throws {
        try await withApp { app in
            await app.jwt.keys.add(ecdsa: ES512PrivateKey())

            app.post("login") { req async throws -> LoginResponse in
                let credentials = try await req.content.decode(LoginCredentials.self)
                return try await LoginResponse(
                    token: req.jwt.sign(TestUser(name: credentials.name))
                )
            }

            app.get("me") { req async throws -> String in
                try await req.jwt.verify(as: TestUser.self).name
            }

            try await app.testing { client in
                let login = try await client.post("login", content: LoginCredentials(name: "foo"))
                #expect(login.status == .ok)
                let loginBody = try await login.content.decode(LoginResponse.self)
                let token = loginBody.token

                let me = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(me.status == .ok)
                #expect(try await me.body.requireString() == "foo")

                let fakeToken = try await JWTKeyCollection()
                    .add(ecdsa: ES512PrivateKey())
                    .sign(TestUser(name: "bob"))
                let fake = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(fakeToken)"]
                )
                #expect(fake.status == .unauthorized)
            }
        }
    }

    @Test("Test Middleware Authentication")
    func middlewareAuthentication() async throws {
        try await withApp { app in
            await app.jwt.keys.add(ecdsa: ES512PrivateKey())

            app.post("login") { req async throws -> LoginResponse in
                let credentials = try await req.content.decode(LoginCredentials.self)
                return try await LoginResponse(
                    token: req.jwt.sign(TestUser(name: credentials.name))
                )
            }

            let secure = app.grouped(UserAuthenticator(), TestUser.guardMiddleware())
            secure.get("me") { req -> TestUser in
                if let user = req.auth.get(TestUser.self) {
                    return user
                } else {
                    Issue.record("Shouldn't get here if the guard middleware is working.")
                    throw Abort(.internalServerError)
                }
            }

            try await app.testing { client in
                let login = try await client.post("login", content: LoginCredentials(name: "foo"))
                #expect(login.status == .ok)
                let token = try await login.content.decode(LoginResponse.self).token

                let me = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(me.status == .ok)
                let user = try await me.content.decode(TestUser.self)
                #expect(user.name == "foo")

                let wrongNameToken = try await app.jwt.keys.sign(TestUser(name: "bob"))
                let wrongName = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(wrongNameToken)"]
                )
                #expect(wrongName.status == .unauthorized)

                let fakeToken = try await JWTKeyCollection()
                    .add(ecdsa: ES512PrivateKey())
                    .sign(TestUser(name: "bob"))
                let fake = try await client.get(
                    "me",
                    headers: [.authorization: "Bearer \(fakeToken)"]
                )
                #expect(fake.status == .unauthorized)
            }
        }
    }

    @Test("Test Apple Authentication with Mock JWKS")
    func testAppleWithMockJWKS() async throws {
        let mockJWKS = """
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-apple-key",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "y_FtQ_cOcx6ZgyaqU54CESfkpttXuNnEZ07nYXXo8ylIiUFpB0r0Fecgv_tIhF1LFCWBHUsqyoSRQz0_iBRnYyIsG-yF_q1K3ll5Q_2GAS9_28jBuJGKDuKIj6dgPlr33si6bjeePTl4ZO6OZFxGYyn4x035pwGwjKGFuQRKYh0AtxwHiWeRIsAJ_B2Z-VGOpcSXH-x_YUfN8Q9FuyGUzcsVLuGizbooRSMSSoD_y_8veWOnXWbMsh0KKTON_-yTmAcLn2tOzFmsYgHQXatW0f2XjrdmmWl4VfiekFKFDvGenxum9nEJrzIJOMm6qHnIiyCNA3xbMqmr7oqeIUa-fQ",
                        "e": "AQAB"
                    }
                ]
            }
            """

        let rsaPrivateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDL8W1D9w5zHpmD
            JqpTngIRJ+Sm21e42cRnTudhdejzKUiJQWkHSvQV5yC/+0iEXUsUJYEdSyrKhJFD
            PT+IFGdjIiwb7IX+rUreWXlD/YYBL3/byMG4kYoO4oiPp2A+WvfeyLpuN549OXhk
            7o5kXEZjKfjHTfmnAbCMoYW5BEpiHQC3HAeJZ5EiwAn8HZn5UY6lxJcf7H9hR83x
            D0W7IZTNyxUu4aLNuihFIxJKgP/L/y95Y6ddZsyyHQopM43/7JOYBwufa07MWaxi
            AdBdq1bR/ZeOt2aZaXhV+J6QUoUO8Z6fG6b2cQmvMgk4ybqoeciLII0DfFsyqavu
            ip4hRr59AgMBAAECggEAUIw994XwMw922hG/W98gOd5jtHMVJnD73UGQqTGEm+VG
            PM+Ux8iWtr/ec3Svo3elW4OkhwlVET9ikAf0u64zVzf769ty4K9YzpDQEEZlUrqL
            6SZVPKxetppKDVKx9G7BT0BAQZ+947h7EIIXwxOeyTOeijkFzSwhqqlwwy4qoqzV
            FTQS20QHE62hxzwuS5HBqw8ds183qAg9NbzR0Cp4za9qTiBB6C8KEcLqeatO+q+d
            VCDsJcAMZOvW14N6BozKgbQ/WXZQ/3kNUPBndZLzzqaILFNmB1Zf2DVVJ9gU7+EK
            xOac60StIfG81NllCTBrmRVq8yitNqwmutHMlxrIkQKBgQDvp39MkEHtNunFGkI5
            R8IB5BZjtx5OdRBKkmPasmNU8U0XoQAJUKY/9piIpCtRi87tMXv8WWmlbULi66pu
            4BnMIisw78xlIWRZTSizFrkFcEoVgEnbZBtSrOg/J5PAcjLEGCQoAdmMXAekR2/m
            htv7FPijHPNUjyIFLaxwjl9izwKBgQDZ2mQeKNRHjIb5ZBzB0ZCvUy2y4+kaLrhZ
            +CWMN1flL4dd1KuZKvCEfHY9kWOjqw6XneN4yT0aPmbBft4fihiiNW0Sm8i+fSpy
            g0klw2HJl49wnwctBpRgTdMKGo9n14OGeu0xKOAy7I4j1tKrUXiRWnP9R583Ti7c
            w7YHgdHM8wKBgEV147SaPzF08A6bzMPzY2zO4hpmsdcFoQIsKdryR04QXkrR9EO+
            52C0pYM9Kf0Jq6Ed7ZS3iaJT58YDjjNyqqd648/cQP6yzfYAIiK+HERSRnay5zU6
            b5zn1qyvWOi3cLVbVedumdJPvjtEJU/ImKvOaT5FntVMYwzjLw60hTsLAoGAZJnt
            UeAY51GFovUQMpDL96q5l7qXknewuhtVe4KzHCrun+3tsDWcDBJNp/DTymjbvDg1
            KzoC9XOLkB8+A+KJrZ5uWAGImi7Cw07NIJsxNR7AJonJjolTS4Wkxy2su49SNW/e
            yKzPm7SRjwtNDb/5pWXX2kaQx8Fa8qeOD7lrYPECgYAwQ6o0vYmr+L1tOZZgMVv9
            Jusa8beVUH5hyduJjmxbYOtFTkggAozdx7rs4BgyRsmDlV48cEmcVf/7IH4gMJLb
            O+bbERwCYUChe+piANhnwfwDHzbRd8mmQus54P06X7bWu6Rmi7gbQGVN/Z6VhbIm
            D2cOo0w4bk/3yb01xz1MEw==
            -----END PRIVATE KEY-----
            """

        try await withApp { app in
            app.get("mock-apple-jwks") { _ in
                Response(
                    status: .ok,
                    headers: [.contentType: "application/json"],
                    body: .init(string: mockJWKS)
                )
            }

            app.get("apple-verify") { req async throws -> String in
                let token = try await req.jwt.apple.verify()
                return token.subject.value
            }

            app.get("apple-verify-custom") { req async throws -> String in
                let token = try await req.jwt.apple.verify(applicationIdentifier: "com.custom.app")
                return token.subject.value
            }

            // Touch JWT before the app starts so the request-context middleware is installed.
            app.jwt.apple.applicationIdentifier = "com.example.app"

            let privateKey = try Insecure.RSA.PrivateKey(pem: rsaPrivateKeyPEM)
            let signingKeys = await JWTKeyCollection().add(
                rsa: privateKey,
                digestAlgorithm: .sha256,
                kid: "test-apple-key"
            )

            let validPayload = AppleIdentityToken(
                issuer: "https://appleid.apple.com",
                audience: "com.example.app",
                expires: .init(value: Date().addingTimeInterval(3600)),
                issuedAt: .init(value: Date()),
                subject: "001234.abcdef1234567890.1234",
                email: "test@privaterelay.appleid.com",
                emailVerified: true
            )
            let validToken = try await signingKeys.sign(validPayload, kid: "test-apple-key")

            try await app.testing(.running) { client in
                let port = try #require(client.port)
                app.jwt.apple.jwksEndpoint = "http://127.0.0.1:\(port)/mock-apple-jwks"

                let verifyResponse = try await client.get(
                    "apple-verify",
                    headers: [.authorization: "Bearer \(validToken)"]
                )
                #expect(verifyResponse.status == .ok)
                #expect(try await verifyResponse.body.requireString() == "001234.abcdef1234567890.1234")

                let wrongAudiencePayload = AppleIdentityToken(
                    issuer: "https://appleid.apple.com",
                    audience: "com.wrong.app",
                    expires: .init(value: Date().addingTimeInterval(3600)),
                    issuedAt: .init(value: Date()),
                    subject: "001234.abcdef1234567890.1234"
                )
                let wrongAudienceToken = try await signingKeys.sign(wrongAudiencePayload, kid: "test-apple-key")
                let wrongAudienceResponse = try await client.get(
                    "apple-verify",
                    headers: [.authorization: "Bearer \(wrongAudienceToken)"]
                )
                #expect(wrongAudienceResponse.status == .unauthorized)

                let expiredPayload = AppleIdentityToken(
                    issuer: "https://appleid.apple.com",
                    audience: "com.example.app",
                    expires: .init(value: Date().addingTimeInterval(-3600)),
                    issuedAt: .init(value: Date().addingTimeInterval(-7200)),
                    subject: "001234.abcdef1234567890.1234"
                )
                let expiredToken = try await signingKeys.sign(expiredPayload, kid: "test-apple-key")
                let expiredTokenResponse = try await client.get(
                    "apple-verify",
                    headers: [.authorization: "Bearer \(expiredToken)"]
                )
                #expect(expiredTokenResponse.status == .unauthorized)

                let wrongIssuerPayload = AppleIdentityToken(
                    issuer: "https://notapple.com",
                    audience: "com.example.app",
                    expires: .init(value: Date().addingTimeInterval(3600)),
                    issuedAt: .init(value: Date()),
                    subject: "001234.abcdef1234567890.1234"
                )
                let wrongIssuerToken = try await signingKeys.sign(wrongIssuerPayload, kid: "test-apple-key")
                let wrongIssuerResponse = try await client.get(
                    "apple-verify",
                    headers: [.authorization: "Bearer \(wrongIssuerToken)"]
                )
                #expect(wrongIssuerResponse.status == .unauthorized)

                let missingAuthHeaderResponse = try await client.get("apple-verify")
                #expect(missingAuthHeaderResponse.status == .unauthorized)

                let customAudiencePayload = AppleIdentityToken(
                    issuer: "https://appleid.apple.com",
                    audience: "com.custom.app",
                    expires: .init(value: Date().addingTimeInterval(3600)),
                    issuedAt: .init(value: Date()),
                    subject: "custom-user-id"
                )
                let customToken = try await signingKeys.sign(customAudiencePayload, kid: "test-apple-key")
                let customKidResponse = try await client.get(
                    "apple-verify-custom",
                    headers: [.authorization: "Bearer \(customToken)"]
                )
                #expect(customKidResponse.status == .ok)
                #expect(try await customKidResponse.body.requireString() == "custom-user-id")
            }
        }
    }

    @Test("Test Microsoft Endpoint Switch")
    func testMicrosoftEndpointSwitch() async throws {
        try await withApp { app in
            await app.jwt.keys.add(
                hmac: "a-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256
            )

            let testUser = TestUser(name: "foo")
            let token = try await app.jwt.keys.sign(testUser)

            app.jwt.microsoft.applicationIdentifier = ""
            app.get("microsoft") { req async throws in
                let token = try await req.jwt.microsoft.verify()
                return token.name ?? "none"
            }

            try await app.testing { client in
                let unauthorized = try await client.get(
                    "microsoft",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(unauthorized.status == .unauthorized)

                app.jwt.microsoft.jwksEndpoint =
                    "https://login.microsoftonline.com/common/discovery/v2.0/keys"
                let stillUnauthorized = try await client.get(
                    "microsoft",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(stillUnauthorized.status == .unauthorized)

                app.jwt.microsoft.jwksEndpoint =
                    "https://login.microsoftonline.com/nonexistent/endpoint"
                let serverError = try await client.get(
                    "microsoft",
                    headers: [.authorization: "Bearer \(token)"]
                )
                #expect(serverError.status == .internalServerError)
            }
        }
    }
}
