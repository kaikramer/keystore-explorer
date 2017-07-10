/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package net.sf.keystore_explorer.gui.actions;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.keystore.KeyStoreType;
import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.dialogs.DGetAlias;
import net.sf.keystore_explorer.gui.dialogs.importexport.DImportKeyPairOpenSsl;
import net.sf.keystore_explorer.gui.dialogs.importexport.DImportKeyPairPkcs12;
import net.sf.keystore_explorer.gui.dialogs.importexport.DImportKeyPairPkcs8;
import net.sf.keystore_explorer.gui.dialogs.importexport.DImportKeyPairPvk;
import net.sf.keystore_explorer.gui.dialogs.importexport.DImportKeyPairType;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.password.DGetNewPassword;
import net.sf.keystore_explorer.utilities.history.HistoryAction;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to import a key pair.
 *
 */
public class ImportKeyPairAction extends KeyStoreExplorerAction implements HistoryAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public ImportKeyPairAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("ImportKeyPairAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("ImportKeyPairAction.statusbar"));
		putValue(NAME, res.getString("ImportKeyPairAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("ImportKeyPairAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("ImportKeyPairAction.image")))));
	}

	@Override
	public String getHistoryDescription() {
		return (String) getValue(NAME);
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		DImportKeyPairType dImportKeyPairType = new DImportKeyPairType(frame);
		dImportKeyPairType.setLocationRelativeTo(frame);
		dImportKeyPairType.setVisible(true);

		if (!dImportKeyPairType.importTypeSelected()) {
			return;
		}

		if (dImportKeyPairType.importPkcs12()) {
			importKeyPairPkcs12();
		} else if (dImportKeyPairType.importPkcs8()) {
			importKeyPairPkcs8();
		} else if (dImportKeyPairType.importPvk()) {
			importKeyPairPvk();
		} else {
			importKeyPairOpenSsl();
		}
	}

	private void importKeyPairPkcs12() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			DImportKeyPairPkcs12 dImportKeyPairPkcs12 = new DImportKeyPairPkcs12(frame);
			dImportKeyPairPkcs12.setLocationRelativeTo(frame);
			dImportKeyPairPkcs12.setVisible(true);

			PrivateKey privKey = dImportKeyPairPkcs12.getPrivateKey();
			X509Certificate[] certs = dImportKeyPairPkcs12.getCertificateChain();

			if ((privKey == null) || (certs == null)) {
				return;
			}

			X509Certificate[] x509Certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));

			DGetAlias dGetAlias = new DGetAlias(frame, res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"),
					X509CertUtil.getCertificateAlias(x509Certs[0]));
			dGetAlias.setLocationRelativeTo(frame);
			dGetAlias.setVisible(true);
			String alias = dGetAlias.getAlias();

			if (alias == null) {
				return;
			}

			if (keyStore.containsAlias(alias)) {
				String message = MessageFormat.format(res.getString("ImportKeyPairAction.OverWriteEntry.message"),
						alias);

				int selected = JOptionPane.showConfirmDialog(frame, message,
						res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}

			Password password = new Password((char[])null);
			KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

			if (type.hasEntryPasswords()) {
				DGetNewPassword dGetNewPassword = new DGetNewPassword(frame,
						res.getString("ImportKeyPairAction.NewKeyPairEntryPassword.Title"),
						applicationSettings.getPasswordQualityConfig());
				dGetNewPassword.setLocationRelativeTo(frame);
				dGetNewPassword.setVisible(true);
				password = dGetNewPassword.getPassword();

				if (password == null) {
					return;
				}
			}

			if (keyStore.containsAlias(alias)) {
				keyStore.deleteEntry(alias);
				newState.removeEntryPassword(alias);
			}

			keyStore.setKeyEntry(alias, privKey, password.toCharArray(), x509Certs);
			newState.setEntryPassword(alias, password);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame, res.getString("ImportKeyPairAction.KeyPairImportSuccessful.message"),
					res.getString("ImportKeyPairAction.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void importKeyPairPkcs8() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			DImportKeyPairPkcs8 dImportKeyPairPkcs8 = new DImportKeyPairPkcs8(frame);
			dImportKeyPairPkcs8.setLocationRelativeTo(frame);
			dImportKeyPairPkcs8.setVisible(true);

			PrivateKey privateKey = dImportKeyPairPkcs8.getPrivateKey();
			Certificate[] certs = dImportKeyPairPkcs8.getCertificateChain();

			if ((privateKey == null) || (certs == null)) {
				return;
			}

			X509Certificate[] x509Certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));

			DGetAlias dGetAlias = new DGetAlias(frame, res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"),
					X509CertUtil.getCertificateAlias(x509Certs[0]));

			dGetAlias.setLocationRelativeTo(frame);
			dGetAlias.setVisible(true);
			String alias = dGetAlias.getAlias();

			if (alias == null) {
				return;
			}

			if (keyStore.containsAlias(alias)) {
				String message = MessageFormat.format(res.getString("ImportKeyPairAction.OverWriteEntry.message"),
						alias);

				int selected = JOptionPane.showConfirmDialog(frame, message,
						res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}

			Password password = new Password((char[])null);
			KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

			if (type.hasEntryPasswords()) {
				DGetNewPassword dGetNewPassword = new DGetNewPassword(frame,
						res.getString("ImportKeyPairAction.NewKeyPairEntryPassword.Title"),
						applicationSettings.getPasswordQualityConfig());
				dGetNewPassword.setLocationRelativeTo(frame);
				dGetNewPassword.setVisible(true);
				password = dGetNewPassword.getPassword();

				if (password == null) {
					return;
				}
			}

			if (keyStore.containsAlias(alias)) {
				keyStore.deleteEntry(alias);
				newState.removeEntryPassword(alias);
			}

			keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), x509Certs);
			newState.setEntryPassword(alias, password);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame, res.getString("ImportKeyPairAction.KeyPairImportSuccessful.message"),
					res.getString("ImportKeyPairAction.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void importKeyPairPvk() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			DImportKeyPairPvk dImportKeyPairPvk = new DImportKeyPairPvk(frame);
			dImportKeyPairPvk.setLocationRelativeTo(frame);
			dImportKeyPairPvk.setVisible(true);

			PrivateKey privateKey = dImportKeyPairPvk.getPrivateKey();
			Certificate[] certs = dImportKeyPairPvk.getCertificateChain();

			if ((privateKey == null) || (certs == null)) {
				return;
			}

			X509Certificate[] x509Certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));

			DGetAlias dGetAlias = new DGetAlias(frame, res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"),
					X509CertUtil.getCertificateAlias(x509Certs[0]));

			dGetAlias.setLocationRelativeTo(frame);
			dGetAlias.setVisible(true);
			String alias = dGetAlias.getAlias();

			if (alias == null) {
				return;
			}

			if (keyStore.containsAlias(alias)) {
				String message = MessageFormat.format(res.getString("ImportKeyPairAction.OverWriteEntry.message"),
						alias);

				int selected = JOptionPane.showConfirmDialog(frame, message,
						res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}

			Password password = new Password((char[])null);
			KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

			if (type.hasEntryPasswords()) {
				DGetNewPassword dGetNewPassword = new DGetNewPassword(frame,
						res.getString("ImportKeyPairAction.NewKeyPairEntryPassword.Title"),
						applicationSettings.getPasswordQualityConfig());
				dGetNewPassword.setLocationRelativeTo(frame);
				dGetNewPassword.setVisible(true);
				password = dGetNewPassword.getPassword();

				if (password == null) {
					return;
				}
			}

			if (keyStore.containsAlias(alias)) {
				keyStore.deleteEntry(alias);
				newState.removeEntryPassword(alias);
			}

			keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), x509Certs);
			newState.setEntryPassword(alias, password);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame, res.getString("ImportKeyPairAction.KeyPairImportSuccessful.message"),
					res.getString("ImportKeyPairAction.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void importKeyPairOpenSsl() {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();

			DImportKeyPairOpenSsl dImportKeyPairOpenSsl = new DImportKeyPairOpenSsl(frame);
			dImportKeyPairOpenSsl.setLocationRelativeTo(frame);
			dImportKeyPairOpenSsl.setVisible(true);

			PrivateKey privateKey = dImportKeyPairOpenSsl.getPrivateKey();
			Certificate[] certs = dImportKeyPairOpenSsl.getCertificateChain();

			if ((privateKey == null) || (certs == null)) {
				return;
			}

			X509Certificate[] x509Certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));

			DGetAlias dGetAlias = new DGetAlias(frame, res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"),
					X509CertUtil.getCertificateAlias(x509Certs[0]));

			dGetAlias.setLocationRelativeTo(frame);
			dGetAlias.setVisible(true);
			String alias = dGetAlias.getAlias();

			if (alias == null) {
				return;
			}

			if (keyStore.containsAlias(alias)) {
				String message = MessageFormat.format(res.getString("ImportKeyPairAction.OverWriteEntry.message"),
						alias);

				int selected = JOptionPane.showConfirmDialog(frame, message,
						res.getString("ImportKeyPairAction.NewKeyPairEntryAlias.Title"), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}

			Password password = new Password((char[])null);
			KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

			if (type.hasEntryPasswords()) {
				DGetNewPassword dGetNewPassword = new DGetNewPassword(frame,
						res.getString("ImportKeyPairAction.NewKeyPairEntryPassword.Title"),
						applicationSettings.getPasswordQualityConfig());
				dGetNewPassword.setLocationRelativeTo(frame);
				dGetNewPassword.setVisible(true);
				password = dGetNewPassword.getPassword();

				if (password == null) {
					return;
				}
			}

			if (keyStore.containsAlias(alias)) {
				keyStore.deleteEntry(alias);
				newState.removeEntryPassword(alias);
			}

			keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), x509Certs);
			newState.setEntryPassword(alias, password);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame, res.getString("ImportKeyPairAction.KeyPairImportSuccessful.message"),
					res.getString("ImportKeyPairAction.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
