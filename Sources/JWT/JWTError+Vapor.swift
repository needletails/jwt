import HTTPTypes
import JWTKit
import Vapor

extension JWTError: @retroactive AbortError {
    public var status: HTTPResponse.Status {
        .unauthorized
    }

    @_implements(AbortError, reason) public var abortErrorReason: String {
        self.reason ?? self.description
    }
}
