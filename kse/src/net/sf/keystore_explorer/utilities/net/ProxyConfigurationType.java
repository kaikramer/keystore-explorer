package net.sf.keystore_explorer.utilities.net;

public enum ProxyConfigurationType {
	NONE,
	SYSTEM,
	MANUAL,
	PAC;

	public static ProxyConfigurationType resolve(String proxyTypeStr) {
		for (ProxyConfigurationType proxyType : values()) {
			if (proxyType.name().equals(proxyTypeStr)) {
				return proxyType;
			}
		}
		return null;
	}
}
