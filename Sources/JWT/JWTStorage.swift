import JWTKit
import Synchronization
import Vapor

/// Binds ``Application`` for the duration of a request.
///
/// Vapor 5's ``Request`` no longer carries `application`; JWT restores that link via middleware
/// so `req.jwt` and `req.application.jwt` keep working.
enum JWTApplicationContext {
    @TaskLocal static var application: Application?
}

struct JWTApplicationContextMiddleware: Middleware {
    let application: Application

    func respond(to request: Request, chainingTo next: any Responder) async throws -> Response {
        try await JWTApplicationContext.$application.withValue(self.application) {
            try await next.respond(to: request)
        }
    }
}

/// Per-`Application` JWT state. Replaces Vapor 4 `StorageKey` / `app.storage`.
final class JWTApplicationStorage: Sendable {
    private let keysBox: Mutex<JWTKeyCollection>
    let apple: JWKSProviderStorage
    let google: GoogleProviderStorage
    let microsoft: JWKSProviderStorage
    let firebaseAuth: JWKSProviderStorage
    private let didRegisterCleanup: Mutex<Bool>
    private let didRegisterMiddleware: Mutex<Bool>

    var keys: JWTKeyCollection {
        get { self.keysBox.withLock { $0 } }
        set { self.keysBox.withLock { $0 = newValue } }
    }

    init(client: any Client) {
        self.keysBox = .init(JWTKeyCollection())
        self.apple = JWKSProviderStorage(
            defaultEndpoint: "https://appleid.apple.com/auth/keys",
            client: client
        )
        self.google = GoogleProviderStorage(client: client)
        self.microsoft = JWKSProviderStorage(
            defaultEndpoint: "https://login.microsoftonline.com/common/discovery/keys",
            client: client
        )
        self.firebaseAuth = JWKSProviderStorage(
            defaultEndpoint:
                "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
            client: client
        )
        self.didRegisterCleanup = .init(false)
        self.didRegisterMiddleware = .init(false)
    }

    func registerCleanupIfNeeded(on application: Application, id: ObjectIdentifier) {
        let shouldRegister = self.didRegisterCleanup.withLock { registered -> Bool in
            if registered { return false }
            registered = true
            return true
        }
        guard shouldRegister else { return }
        application.addLifecycleHandler(JWTStorageCleanup(id: id))
    }

    func registerContextMiddlewareIfNeeded(on application: Application) {
        let shouldRegister = self.didRegisterMiddleware.withLock { registered -> Bool in
            if registered { return false }
            registered = true
            return true
        }
        guard shouldRegister else { return }
        var middlewares = application.middleware
        middlewares.use(JWTApplicationContextMiddleware(application: application), at: .beginning)
        application.middleware = middlewares
    }
}

final class JWKSProviderStorage: Sendable {
    struct State: Sendable {
        var jwks: EndpointCache<JWKS>
        var jwksEndpoint: URI
        var applicationIdentifier: String?
    }

    private let state: Mutex<State>

    init(defaultEndpoint: URI, client: any Client) {
        self.state = .init(
            .init(
                jwks: EndpointCache(uri: defaultEndpoint, client: client),
                jwksEndpoint: defaultEndpoint,
                applicationIdentifier: nil
            )
        )
    }

    var jwks: EndpointCache<JWKS> {
        get { self.state.withLock { $0.jwks } }
        set { self.state.withLock { $0.jwks = newValue } }
    }

    var jwksEndpoint: URI {
        get { self.state.withLock { $0.jwksEndpoint } }
        set { self.state.withLock { $0.jwksEndpoint = newValue } }
    }

    var applicationIdentifier: String? {
        get { self.state.withLock { $0.applicationIdentifier } }
        set { self.state.withLock { $0.applicationIdentifier = newValue } }
    }

    func setEndpoint(_ endpoint: URI, client: any Client) {
        self.state.withLock { state in
            state.jwksEndpoint = endpoint
            state.jwks = EndpointCache(uri: endpoint, client: client)
        }
    }
}

final class GoogleProviderStorage: Sendable {
    struct State: Sendable {
        var jwks: EndpointCache<JWKS>
        var jwksEndpoint: URI
        var applicationIdentifier: String?
        var gSuiteDomainName: String?
    }

    private let state: Mutex<State>

    init(client: any Client) {
        let endpoint: URI = "https://www.googleapis.com/oauth2/v3/certs"
        self.state = .init(
            .init(
                jwks: EndpointCache(uri: endpoint, client: client),
                jwksEndpoint: endpoint,
                applicationIdentifier: nil,
                gSuiteDomainName: nil
            )
        )
    }

    var jwks: EndpointCache<JWKS> {
        get { self.state.withLock { $0.jwks } }
        set { self.state.withLock { $0.jwks = newValue } }
    }

    var jwksEndpoint: URI {
        get { self.state.withLock { $0.jwksEndpoint } }
        set { self.state.withLock { $0.jwksEndpoint = newValue } }
    }

    var applicationIdentifier: String? {
        get { self.state.withLock { $0.applicationIdentifier } }
        set { self.state.withLock { $0.applicationIdentifier = newValue } }
    }

    var gSuiteDomainName: String? {
        get { self.state.withLock { $0.gSuiteDomainName } }
        set { self.state.withLock { $0.gSuiteDomainName = newValue } }
    }

    func setEndpoint(_ endpoint: URI, client: any Client) {
        self.state.withLock { state in
            state.jwksEndpoint = endpoint
            state.jwks = EndpointCache(uri: endpoint, client: client)
        }
    }
}

private let jwtApplicationStorage = Mutex<[ObjectIdentifier: JWTApplicationStorage]>([:])

func jwtStorage(for application: Application) -> JWTApplicationStorage {
    let id = ObjectIdentifier(application)
    let (storage, isNew) = jwtApplicationStorage.withLock { map -> (JWTApplicationStorage, Bool) in
        if let existing = map[id] {
            return (existing, false)
        }
        let created = JWTApplicationStorage(client: application.client)
        map[id] = created
        return (created, true)
    }
    if isNew {
        storage.registerCleanupIfNeeded(on: application, id: id)
        storage.registerContextMiddlewareIfNeeded(on: application)
    }
    return storage
}

private struct JWTStorageCleanup: LifecycleHandler {
    let id: ObjectIdentifier

    func shutdown(_ application: Application) async {
        _ = jwtApplicationStorage.withLock { $0.removeValue(forKey: self.id) }
    }
}
