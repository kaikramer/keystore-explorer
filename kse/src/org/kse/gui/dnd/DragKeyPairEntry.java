/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.kse.gui.dnd;

import java.awt.Toolkit;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.x509.X509CertUtil;

/**
 * Encapsulates a draggable key pair entry. Product of drag is:
 * <ol>
 * <li>A PKCS #12 KeyStore containing the key pair if drag is to a file.</li>
 * <li>A concatenation of encrypted PEM'd PKCS #8 (private key) and PKCS #7
 * (certificate chain) if drag is to a string.</li>
 * </ol>
 *
 */
public class DragKeyPairEntry extends DragEntry {
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dnd/resources");

	private static final String EXTENSION = "p12";

	private byte[] contentBytes;
	private String contentStr;
	private ImageIcon image;

	/**
	 * Construct DragKeyPairEntry.
	 *
	 * @param name
	 *            Entry name
	 * @param privateKey
	 *            Private key
	 * @param password
	 *            Private key password
	 * @param certificateChain
	 *            Certificate chain
	 * @throws CryptoException
	 *             If there was a problem creating the content
	 */
	public DragKeyPairEntry(String name, PrivateKey privateKey, Password password, Certificate[] certificateChain)
			throws CryptoException {
		super(name);

		try {
			// Binary content is PKCS #12 protected by password
			KeyStore p12 = KeyStoreUtil.create(KeyStoreType.PKCS12);
			p12.setKeyEntry(name, privateKey, new char[] {}, certificateChain);

			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				p12.store(baos, password.toCharArray());
				contentBytes = baos.toByteArray();
			}

			/*
			 * String content is PKCS #8 PEM (private key) protected by PBE
			 * (SHA-1 and 128 bit RC4) concatenated with PCKS #7 PEM
			 * (certificate chain)
			 */
			StringBuffer sbContent = new StringBuffer();
			String pkcs8 = Pkcs8Util.getEncryptedPem(privateKey, Pkcs8PbeType.SHA1_128BIT_RC4, password);
			String pkcs7 = X509CertUtil.getCertsEncodedPkcs7Pem(X509CertUtil.convertCertificates(certificateChain));

			// Output notes delimiting the different parts
			sbContent.append(res.getString("DragKeyPairEntry.StringFlavor.PrivateKeyPart.text"));
			sbContent.append("\n\n");
			sbContent.append(pkcs8);
			sbContent.append('\n');
			sbContent.append(res.getString("DragKeyPairEntry.StringFlavor.CertificateChainPart.text"));
			sbContent.append("\n\n");
			sbContent.append(pkcs7);

			contentStr = sbContent.toString();

			// Get drag image
			image = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
					getClass().getResource(res.getString("DragKeyPairEntry.Drag.image"))));
		} catch (IOException ex) {
			throw new CryptoException(res.getString("NoGetKeyPairEntryContent.exception.message"), ex);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(res.getString("NoGetKeyPairEntryContent.exception.message"), ex);
		}
	}

	/**
	 * Get entry image - to display while dragging.
	 *
	 * @return Entry image
	 */
	@Override
	public ImageIcon getImage() {
		return image;
	}

	/**
	 * Get entry file extension. Used to generate file name.
	 *
	 * @return File extension
	 */
	@Override
	public String getExtension() {
		return EXTENSION;
	}

	/**
	 * Get entry content as binary. Used to generate dragged file name.
	 *
	 * @return Content
	 */
	@Override
	public byte[] getContent() {
		return contentBytes;
	}

	/**
	 * Get entry content as a string.
	 *
	 * @return Content
	 */
	@Override
	public String getContentString() {
		return contentStr;
	}
}
