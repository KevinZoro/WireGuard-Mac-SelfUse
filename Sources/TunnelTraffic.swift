import Darwin

struct TunnelTraffic: Sendable {
    let received: UInt64
    let sent: UInt64

    static func read(tunIPv4Address: String) -> Self? {
        var target = in_addr()
        guard inet_pton(AF_INET, tunIPv4Address, &target) == 1 else { return nil }
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let interfaces else { return nil }
        defer { freeifaddrs(interfaces) }

        var entry: UnsafeMutablePointer<ifaddrs>? = interfaces
        while let interface = entry?.pointee {
            entry = interface.ifa_next
            guard let address = interface.ifa_addr,
                  address.pointee.sa_family == AF_INET,
                  let name = interface.ifa_name,
                  String(cString: name).hasPrefix("utun") else { continue }
            let ipv4 = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                $0.pointee.sin_addr.s_addr
            }
            guard ipv4 == target.s_addr else { continue }
            let index = if_nametoindex(name)
            guard index != 0 else { return nil }

            var query = [CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA, Int32(index), IFDATA_GENERAL]
            var stats = ifmibdata()
            var size = MemoryLayout.size(ofValue: stats)
            guard sysctl(&query, UInt32(query.count), &stats, &size, nil, 0) == 0 else { return nil }
            return Self(received: stats.ifmd_data.ifi_ibytes, sent: stats.ifmd_data.ifi_obytes)
        }
        return nil
    }
}
