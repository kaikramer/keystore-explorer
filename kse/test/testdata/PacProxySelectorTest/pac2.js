function FindProxyForURL(url, host) {

    if (dnsDomainIs(host, "intranet.example.com") ||
        shExpMatch(host, "(*.example.com|example.com)"))
        return "DIRECT";

    if (url.substring(0, 4) == "ftp:" ||
        shExpMatch(url, "http://example.com/folder/*"))
        return "DIRECT";

    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
        return "DIRECT";

    if (isInNet(myIpAddress(), "10.10.5.0", "255.255.255.0"))
        return "PROXY 1.2.3.4:8080";

    return "PROXY 4.5.6.7:8080; PROXY 7.8.9.10:8080";
}