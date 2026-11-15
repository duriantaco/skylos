public struct Banner {
    private var title: String? { nil }
    private var subtitle: String? { nil }
    private var footer: String? { nil }
    private var cached: String? { nil }

    public func render(_ value: String?) -> String {
        guard let title else { return "" }
        if let subtitle {
            return title + subtitle
        }
        if let footer = value {
            return title + footer
        }
        let cached: String? = value
        if let cached {
            return title + cached
        }
        return title
    }
}
