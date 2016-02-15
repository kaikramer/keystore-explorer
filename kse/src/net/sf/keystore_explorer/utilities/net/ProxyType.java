package net.sf.keystore_explorer.utilities.net;

public enum ProxyType {
	NONE,
	SYSTEM,
	MANUAL,
	PAC;

	public static ProxyType resolve(String proxyTypeStr) {
		for (ProxyType proxyType : values()) {
			if (proxyType.name().equals(proxyTypeStr)) {
				return proxyType;
			}
		}
		return null;
	}
}
