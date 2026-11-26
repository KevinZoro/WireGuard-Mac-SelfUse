import Foundation

struct WebsiteRules: Sendable {
    static let port: UInt16 = 18765

    let domains: [String]

    init(_ input: String) throws {
        guard input.utf8.count <= 16_384 else {
            throw UserError("直连列表最多支持 100 个域名。")
        }
        let entries = input.split { $0.isWhitespace || $0 == "," || $0 == "，" }
        var normalized = Set<String>()
        for entry in entries {
            guard let domain = Self.hostname(String(entry)) else {
                throw UserError("请输入网站域名，例如 example.com。每行一个。")
            }
            normalized.insert(domain)
        }
        guard !normalized.isEmpty && normalized.count <= 100 else {
            throw UserError("请输入 1 到 100 个要直连的域名。")
        }
        domains = normalized.sorted()
    }

    static func hostname(_ input: String) -> String? {
        let value = input.lowercased()
        let host = value.hasSuffix(".") ? String(value.dropLast()) : value
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard host.utf8.count <= 253, labels.count >= 2,
              let tld = labels.last,
              tld.utf8.contains(where: { (97...122).contains($0) }),
              labels.allSatisfy({ label in
                  (1...63).contains(label.utf8.count)
                      && label.first != "-" && label.last != "-"
                      && label.utf8.allSatisfy {
                          (97...122).contains($0) || (48...57).contains($0) || $0 == 45
                      }
              }) else { return nil }
        return host
    }
}
