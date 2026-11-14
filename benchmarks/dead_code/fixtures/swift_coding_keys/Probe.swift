import Foundation

public struct Payload: Codable {
    let displayName: String

    private enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
    }

    private enum RetiredKeys: String, CodingKey {
        case displayName = "name"
    }
}

public struct Plain {
    let displayName: String

    private enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
    }
}
