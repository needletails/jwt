import Vapor
import VaporTesting

func withApp(_ body: @escaping (Application) async throws -> Void) async throws {
    try await VaporTesting.withApp(body)
}
