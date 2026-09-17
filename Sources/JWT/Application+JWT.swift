import JWTKit
import Vapor

extension Application {
    public var jwt: JWT {
        .init(_application: self)
    }

    public struct JWT: Sendable {
        public let _application: Application

        public var keys: JWTKeyCollection {
            get { jwtStorage(for: self._application).keys }
            nonmutating set { jwtStorage(for: self._application).keys = newValue }
        }

        var storage: JWTApplicationStorage {
            jwtStorage(for: self._application)
        }
    }
}
