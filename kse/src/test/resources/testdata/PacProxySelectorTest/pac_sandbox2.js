function FindProxyForURL(url, host) {

    var file = Java.type('java.io.File');
    file.createTempFile("sandboxtest", ".txt")

    return 'DIRECT';
}
