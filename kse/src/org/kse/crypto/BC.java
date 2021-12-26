package org.kse.crypto;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Singleton for JCE BC provider. When an explicit provider is wanted,
 * but {@link java.security.NoSuchProviderException} should be avoided.
 * <p>
 * Usage example:
 * </p>
 * <pre>
 * Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", BC.getInstance());
 * </pre>
 */
public class BC {
	private static final Provider BC = new BouncyCastleProvider();

	public static Provider getInstance() {
		return BC;
	}
}
