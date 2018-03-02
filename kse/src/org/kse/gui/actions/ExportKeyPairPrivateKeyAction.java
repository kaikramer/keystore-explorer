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
package org.kse.gui.actions;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPbeType;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyOpenSsl;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyPkcs8;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyPvk;
import org.kse.gui.dialogs.importexport.DExportPrivateKeyType;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to export the selected key pair entry's private key.
 *
 */
public class ExportKeyPairPrivateKeyAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ExportKeyPairPrivateKeyAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("ExportKeyPairPrivateKeyAction.statusbar"));
		putValue(NAME, res.getString("ExportKeyPairPrivateKeyAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ExportKeyPairPrivateKeyAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ExportKeyPairPrivateKeyAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			String alias = kseFrame.getSelectedEntryAlias();

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return;
			}

			KeyStore keyStore = currentState.getKeyStore();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

			DExportPrivateKeyType dExportPrivateKeyType = new DExportPrivateKeyType(frame);
			dExportPrivateKeyType.setLocationRelativeTo(frame);
			dExportPrivateKeyType.setVisible(true);

			if (!dExportPrivateKeyType.exportTypeSelected()) {
				return;
			}

			if (dExportPrivateKeyType.exportPkcs8()) {
				exportAsPkcs8(privateKey, alias);
			} else if (dExportPrivateKeyType.exportPvk()) {
				exportAsPvk(privateKey, alias);
			} else {
				exportAsOpenSsl(privateKey, alias);
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void exportAsPkcs8(PrivateKey privateKey, String alias) throws CryptoException, IOException {
		File exportFile = null;

		try {
			DExportPrivateKeyPkcs8 dExportPrivateKeyPkcs8 = new DExportPrivateKeyPkcs8(frame, alias,
					applicationSettings.getPasswordQualityConfig());
			dExportPrivateKeyPkcs8.setLocationRelativeTo(frame);
			dExportPrivateKeyPkcs8.setVisible(true);

			if (!dExportPrivateKeyPkcs8.exportSelected()) {
				return;
			}

			exportFile = dExportPrivateKeyPkcs8.getExportFile();
			boolean pemEncode = dExportPrivateKeyPkcs8.pemEncode();
			boolean encrypt = dExportPrivateKeyPkcs8.encrypt();

			Pkcs8PbeType pbeAlgorithm = null;
			Password exportPassword = null;

			if (encrypt) {
				pbeAlgorithm = dExportPrivateKeyPkcs8.getPbeAlgorithm();
				exportPassword = dExportPrivateKeyPkcs8.getExportPassword();
			}

			byte[] encoded = getPkcs8EncodedPrivateKey(privateKey, pemEncode, pbeAlgorithm, exportPassword);

			exportEncodedPrivateKey(encoded, exportFile);

			JOptionPane.showMessageDialog(frame,
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPkcs8Successful.message"),
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPkcs8.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
					exportFile);
			JOptionPane.showMessageDialog(frame, message,
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPkcs8.Title"),
					JOptionPane.WARNING_MESSAGE);
		}
	}

	private void exportAsPvk(PrivateKey privateKey, String alias) throws CryptoException, IOException {
		File exportFile = null;

		try {
			DExportPrivateKeyPvk dExportPrivateKeyPvk = new DExportPrivateKeyPvk(frame, alias, privateKey,
					applicationSettings.getPasswordQualityConfig());
			dExportPrivateKeyPvk.setLocationRelativeTo(frame);
			dExportPrivateKeyPvk.setVisible(true);

			if (!dExportPrivateKeyPvk.exportSelected()) {
				return;
			}

			exportFile = dExportPrivateKeyPvk.getExportFile();
			int keyType = dExportPrivateKeyPvk.getKeyType();
			boolean encrypt = dExportPrivateKeyPvk.encrypt();

			boolean strongEncryption = false;
			Password exportPassword = null;

			if (encrypt) {
				strongEncryption = dExportPrivateKeyPvk.useStrongEncryption();
				exportPassword = dExportPrivateKeyPvk.getExportPassword();
			}

			byte[] encoded = getPvkEncodedPrivateKey(privateKey, keyType, exportPassword, strongEncryption);

			exportEncodedPrivateKey(encoded, exportFile);

			JOptionPane.showMessageDialog(frame,
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvkSuccessful.message"),
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvk.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
					exportFile);
			JOptionPane.showMessageDialog(frame, message,
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyPvk.Title"),
					JOptionPane.WARNING_MESSAGE);
		}
	}

	private void exportAsOpenSsl(PrivateKey privateKey, String alias) throws CryptoException, IOException {
		File exportFile = null;

		try {
			DExportPrivateKeyOpenSsl dExportPrivateKeyOpenSsl = new DExportPrivateKeyOpenSsl(frame, alias,
					applicationSettings.getPasswordQualityConfig());
			dExportPrivateKeyOpenSsl.setLocationRelativeTo(frame);
			dExportPrivateKeyOpenSsl.setVisible(true);

			if (!dExportPrivateKeyOpenSsl.exportSelected()) {
				return;
			}

			exportFile = dExportPrivateKeyOpenSsl.getExportFile();
			boolean pemEncode = dExportPrivateKeyOpenSsl.pemEncode();
			boolean encrypt = dExportPrivateKeyOpenSsl.encrypt();

			OpenSslPbeType pbeAlgorithm = null;
			Password exportPassword = null;

			if (encrypt) {
				pbeAlgorithm = dExportPrivateKeyOpenSsl.getPbeAlgorithm();
				exportPassword = dExportPrivateKeyOpenSsl.getExportPassword();
			}

			byte[] encoded = getOpenSslEncodedPrivateKey(privateKey, pemEncode, pbeAlgorithm, exportPassword);

			exportEncodedPrivateKey(encoded, exportFile);

			JOptionPane.showMessageDialog(frame,
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSslSuccessful.message"),
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSsl.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (FileNotFoundException ex) {
			String message = MessageFormat.format(res.getString("ExportKeyPairPrivateKeyAction.NoWriteFile.message"),
					exportFile);
			JOptionPane.showMessageDialog(frame, message,
					res.getString("ExportKeyPairPrivateKeyAction.ExportPrivateKeyOpenSsl.Title"),
					JOptionPane.WARNING_MESSAGE);
		}
	}

	private byte[] getPkcs8EncodedPrivateKey(PrivateKey privateKey, boolean pemEncode, Pkcs8PbeType pbeAlgorithm,
			Password password) throws CryptoException, IOException {
		byte[] encoded = null;

		if (pemEncode) {
			if ((pbeAlgorithm != null) && (password != null)) {
				encoded = Pkcs8Util.getEncryptedPem(privateKey, pbeAlgorithm, password).getBytes();
			} else {
				encoded = Pkcs8Util.getPem(privateKey).getBytes();
			}
		} else {
			if ((pbeAlgorithm != null) && (password != null)) {
				encoded = Pkcs8Util.getEncrypted(privateKey, pbeAlgorithm, password);
			} else {
				encoded = Pkcs8Util.get(privateKey);
			}
		}

		return encoded;
	}

	private byte[] getPvkEncodedPrivateKey(PrivateKey privateKey, int keyType, Password password,
			boolean strongEncryption) throws CryptoException, IOException {
		byte[] encoded = null;

		if (password != null) {
			if (privateKey instanceof RSAPrivateCrtKey) {
				encoded = MsPvkUtil.getEncrypted((RSAPrivateCrtKey) privateKey, keyType, password, strongEncryption);
			} else {
				encoded = MsPvkUtil.getEncrypted((DSAPrivateKey) privateKey, password, strongEncryption);
			}
		} else {
			if (privateKey instanceof RSAPrivateCrtKey) {
				encoded = MsPvkUtil.get((RSAPrivateCrtKey) privateKey, keyType);
			} else {
				encoded = MsPvkUtil.get((DSAPrivateKey) privateKey);
			}
		}

		return encoded;
	}

	private byte[] getOpenSslEncodedPrivateKey(PrivateKey privateKey, boolean pemEncoded, OpenSslPbeType pbeAlgorithm,
			Password password) throws CryptoException, IOException {
		byte[] encoded = null;

		if (pemEncoded) {
			if ((pbeAlgorithm != null) && (password != null)) {
				encoded = OpenSslPvkUtil.getEncrypted(privateKey, pbeAlgorithm, password).getBytes();
			} else {
				encoded = OpenSslPvkUtil.getPem(privateKey).getBytes();
			}
		} else {
			encoded = OpenSslPvkUtil.get(privateKey);
		}

		return encoded;
	}

	private void exportEncodedPrivateKey(byte[] encoded, File exportFile) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(exportFile)) {
			fos.write(encoded);
			fos.flush();
		}
	}
}
