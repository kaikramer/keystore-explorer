// PAC file that calls every single one of the helper functions (at least indirectly)
function FindProxyForURL(url, host) {

    if (shExpMatch(host, "*.example.com")) return "SOCKS4 example.com:1001";

    if (isPlainHostName(host)) return "SOCKS4 example.com:1002";

    if (localHostOrDomainIs(host, "www.example.com")) return "SOCKS4 example.com:1003";

    if (!isResolvable(host)) return "SOCKS4 example.com:1004";

    if (dnsDomainLevels(host) == 4) return "SOCKS4 example.com:1005";

    if (myIpAddress() == "1.2.3.4") return "SOCKS4 example.com:1006";

    if (isInNet(host, "12.0.0.0", "255.255.248.0")) return "SOCKS4 example.com:1007";

    if (dnsDomainIs(host, "example.com")) return "SOCKS4 example.com:1008";

    if (weekdayRange("MON", "WED")) return "SOCKS4 example.com:1009";

    if (dateRange("JAN", "JUN")) return "SOCKS4 example.com:1010";

    if (timeRange(8, 20)) return "SOCKS4 example.com:1011";

    return "PROXY proxy.example.com:8080; DIRECT";
}
