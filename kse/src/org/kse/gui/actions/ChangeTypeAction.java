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

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.text.MessageFormat;
import java.util.Enumeration;

import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;


/**
 * Action to change the active KeyStore's type.
 *
 */
public class ChangeTypeAction extends KeyStoreExplorerAction implements HistoryAction {
	private static final long serialVersionUID = 1L;
	private KeyStoreType newType;
	private boolean warnNoChangeKey;
	private boolean warnNoECC;

	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 * @param newType
	 *            New KeyStore type
	 */
	public ChangeTypeAction(KseFrame kseFrame, KeyStoreType newType) {
		super(kseFrame);

		this.newType = newType;

		putValue(LONG_DESCRIPTION,
				MessageFormat.format(res.getString("ChangeTypeAction.statusbar"), newType.friendly()));
		putValue(NAME, newType.friendly());
		putValue(SHORT_DESCRIPTION, newType.friendly());
	}

	@Override
	public String getHistoryDescription() {
		return MessageFormat.format(res.getString("ChangeTypeAction.History.text"), newType.friendly());
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		KeyStoreType currentType = KeyStoreType.resolveJce(kseFrame.getActiveKeyStoreHistory().getCurrentState()
				.getKeyStore().getType());

		if (currentType == newType) {
			return;
		}

		boolean changeResult = changeKeyStoreType(newType);

		if (!changeResult) {
			// Change type failed or cancelled - revert radio button menu item for KeyStore type
			kseFrame.updateControls(false);
		}
	}

	private boolean changeKeyStoreType(KeyStoreType newKeyStoreType) {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStoreState currentState = history.getCurrentState();

			KeyStore currentKeyStore = currentState.getKeyStore();
			String currentType = currentState.getKeyStore().getType();

			KeyStore newKeyStore = KeyStoreUtil.create(newKeyStoreType);

			// Only warn the user once
			resetWarnings();

			// Copy all entries to the new KeyStore: Trusted certs, key pairs and secret keys
			for (Enumeration<String> aliases = currentKeyStore.aliases(); aliases.hasMoreElements();) {
				String alias = aliases.nextElement();

				if (KeyStoreUtil.isTrustedCertificateEntry(alias, currentKeyStore)) {
					Certificate trustedCertificate = currentKeyStore.getCertificate(alias);
					newKeyStore.setCertificateEntry(alias, trustedCertificate);
				} else if (KeyStoreUtil.isKeyPairEntry(alias, currentKeyStore)) {
					if (!copyKeyPairEntry(newKeyStoreType, currentState, currentKeyStore, currentType,
							newKeyStore, alias)) {
						return false;
					}
				} else if (KeyStoreUtil.isKeyEntry(alias, currentKeyStore)) {
					if (!copySecretKeyEntry(newKeyStoreType, currentState, currentKeyStore, newKeyStore, alias)) {
						return false;
					}
				}
			}

			KeyStoreState newState = currentState.createBasisForNextState(this);
			newState.setKeyStore(newKeyStore);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane.showMessageDialog(frame,
					res.getString("ChangeTypeAction.ChangeKeyStoreTypeSuccessful.message"),
					res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"), JOptionPane.INFORMATION_MESSAGE);
			return true;
		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return false;
		}
	}

	private void resetWarnings() {
		// Only warn the user once about key entries not being carried over by the change
		warnNoChangeKey = false;

		// Only warn the user once about key entries not being carried over by the change
		warnNoECC = false;
	}

	private boolean copyKeyPairEntry(KeyStoreType newKeyStoreType, KeyStoreState currentState,
			KeyStore currentKeyStore, String currentType, KeyStore newKeyStore, String alias) throws KeyStoreException,
	CryptoException, NoSuchAlgorithmException, UnrecoverableKeyException {

		Certificate[] certificateChain = currentKeyStore.getCertificateChain(alias);
		certificateChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certificateChain));

		Password password = getEntryPassword(alias, currentState);
		if (password == null) {
			return false;
		}

		Key privateKey = currentKeyStore.getKey(alias, password.toCharArray());

		currentState.setEntryPassword(alias, password);

		// EC key pair? => might not be supported in target key store type
		if (KeyStoreUtil.isECKeyPair(alias, currentKeyStore)) {

			String namedCurve = EccUtil.getNamedCurve(currentKeyStore.getKey(alias, password.toCharArray()));

			// EC or curve not supported?
			if (!newKeyStoreType.supportsECC() || !newKeyStoreType.supportsNamedCurve(namedCurve)) {

				// show warning and abort change or just skip depending on user choice
				return showWarnNoECC();
			}
		}

		newKeyStore.setKeyEntry(alias, privateKey, password.toCharArray(), certificateChain);
		return true;
	}


	private boolean copySecretKeyEntry(KeyStoreType newKeyStoreType, KeyStoreState currentState,
			KeyStore currentKeyStore, KeyStore newKeyStore, String alias) throws KeyStoreException,
	NoSuchAlgorithmException, UnrecoverableKeyException {

		if (newKeyStoreType.supportsKeyEntries()) {

			Password password = getEntryPassword(alias, currentState);

			if (password == null) {
				return false;
			}

			Key secretKey = currentKeyStore.getKey(alias, password.toCharArray());

			currentState.setEntryPassword(alias, password);

			newKeyStore.setKeyEntry(alias, secretKey, password.toCharArray(), null);
		} else {
			// show warning and let user decide whether to abort (return false) or just skip the entry (true)
			return showWarnNoChangeKey();
		}

		return true;
	}

	private boolean showWarnNoECC() {
		if (!warnNoECC) {
			warnNoECC = true;
			int selected = JOptionPane.showConfirmDialog(frame, res.getString("ChangeTypeAction.WarnNoECC.message"),
					res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"), JOptionPane.YES_NO_OPTION);

			if (selected != JOptionPane.YES_OPTION) {
				// user wants to abort
				return false;
			}
		}
		// do not add this entry to new key store
		return true;
	}

	private boolean showWarnNoChangeKey() {
		if (!warnNoChangeKey) {
			warnNoChangeKey = true;
			int selected = JOptionPane.showConfirmDialog(frame,
					res.getString("ChangeTypeAction.WarnNoChangeKey.message"),
					res.getString("ChangeTypeAction.ChangeKeyStoreType.Title"), JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return false;
			}
		}
		return true;
	}
}
