function FindProxyForURL(url, host) {

    /* Normalize the URL for pattern matching */
    url = url.toLowerCase();
    host = host.toLowerCase();

    /* Don't proxy local hostnames */
    if (isPlainHostName(host)) {
        return 'DIRECT';
    }

    /* Don't proxy local domains */
    if (dnsDomainIs(host, ".example1.com") ||
        (host == "example1.com") ||
        dnsDomainIs(host, ".example2.com") ||
        (host == "example2.com") ||
        dnsDomainIs(host, ".example3.com") ||
        (host == "example3.com")) {
        return 'DIRECT';
    }

    /* Don't proxy Windows Update */
    if ((host == "download.microsoft.com") ||
        (host == "ntservicepack.microsoft.com") ||
        (host == "cdm.microsoft.com") ||
        (host == "wustat.windows.com") ||
        (host == "windowsupdate.microsoft.com") ||
        (dnsDomainIs(host, ".windowsupdate.microsoft.com")) ||
        (host == "update.microsoft.com") ||
        (dnsDomainIs(host, ".update.microsoft.com")) ||
        (dnsDomainIs(host, ".windowsupdate.com"))) {
        return 'DIRECT';
    }

    if (isResolvable(host)) {
        var hostIP = dnsResolve(host);

        /* Don't proxy non-routable addresses (RFC 3330) */
        if (isInNet(hostIP, '0.0.0.0', '255.0.0.0') ||
            isInNet(hostIP, '10.0.0.0', '255.0.0.0') ||
            isInNet(hostIP, '127.0.0.0', '255.0.0.0') ||
            isInNet(hostIP, '169.254.0.0', '255.255.0.0') ||
            isInNet(hostIP, '172.16.0.0', '255.240.0.0') ||
            isInNet(hostIP, '192.0.2.0', '255.255.255.0') ||
            isInNet(hostIP, '192.88.99.0', '255.255.255.0') ||
            isInNet(hostIP, '192.168.0.0', '255.255.0.0') ||
            isInNet(hostIP, '198.18.0.0', '255.254.0.0') ||
            isInNet(hostIP, '224.0.0.0', '240.0.0.0') ||
            isInNet(hostIP, '240.0.0.0', '240.0.0.0')) {
            return 'DIRECT';
        }

        /* Don't proxy local addresses.*/
        if (false) {
            return 'DIRECT';
        }
    }

    if (url.substring(0, 5) == 'http:' ||
        url.substring(0, 6) == 'https:' ||
        url.substring(0, 4) == 'ftp:') {
        return 'PROXY wcg1.example.com:8080';
    }

    return 'DIRECT';
}
