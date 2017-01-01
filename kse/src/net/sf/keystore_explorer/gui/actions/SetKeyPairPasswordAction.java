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

import static java.awt.Dialog.ModalityType.DOCUMENT_MODAL;

import java.awt.Toolkit;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;
import net.sf.keystore_explorer.gui.password.DChangePassword;
import net.sf.keystore_explorer.utilities.history.HistoryAction;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to set the selected key pair entry's password.
 *
 */
public class SetKeyPairPasswordAction extends KeyStoreExplorerAction implements HistoryAction {
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public SetKeyPairPasswordAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("SetKeyPairPasswordAction.statusbar"));
		putValue(NAME, res.getString("SetKeyPairPasswordAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SetKeyPairPasswordAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SetKeyPairPasswordAction.image")))));
	}

	@Override
	public String getHistoryDescription() {
		return res.getString("SetKeyPairPasswordAction.History.text");
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		String alias = null;

		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();

			KeyStoreState currentState = history.getCurrentState();
			KeyStoreState newState = currentState.createBasisForNextState(this);

			KeyStore keyStore = newState.getKeyStore();
			alias = kseFrame.getSelectedEntryAlias();

			Password oldPassword = newState.getEntryPassword(alias);

			DChangePassword dChangePassword = new DChangePassword(frame, DOCUMENT_MODAL,
					res.getString("SetKeyPairPasswordAction.SetKeyPairPassword.Title"), oldPassword,
					applicationSettings.getPasswordQualityConfig());
			dChangePassword.setLocationRelativeTo(frame);
			dChangePassword.setVisible(true);

			if (oldPassword == null) {
				oldPassword = dChangePassword.getOldPassword();
			}
			Password newPassword = dChangePassword.getNewPassword();

			if ((oldPassword == null) || (newPassword == null)) {
				return;
			}

			// Change the password by recreating the entry
			Certificate[] certs = keyStore.getCertificateChain(alias);
			certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));

			Key privateKey = keyStore.getKey(alias, oldPassword.toCharArray());

			keyStore.deleteEntry(alias);
			newState.removeEntryPassword(alias);

			keyStore.setKeyEntry(alias, privateKey, newPassword.toCharArray(), certs);

			if (currentState.getEntryPassword(alias) == null) {
				currentState.setEntryPassword(alias, oldPassword);
			}

			newState.setEntryPassword(alias, newPassword);

			currentState.append(newState);

			kseFrame.updateControls(true);

			JOptionPane
			.showMessageDialog(frame,
					res.getString("SetKeyPairPasswordAction.SetKeyPairPasswordSuccessful.message"),
					res.getString("SetKeyPairPasswordAction.SetKeyPairPassword.Title"),
					JOptionPane.INFORMATION_MESSAGE);
		} catch (GeneralSecurityException ex) {
			String problemStr = MessageFormat.format(
					res.getString("SetKeyPairPasswordAction.NoSetPasswordKeyPairEntry.Problem"), alias);

			String[] causes = new String[] {
					res.getString("SetKeyPairPasswordAction.PasswordIncorrectKeyPairEntry.Cause"),
					res.getString("SetKeyPairPasswordAction.NotSupportedAlgorithmKeyPairEntry.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(frame,
					res.getString("SetKeyPairPasswordAction.ProblemSettingPasswordKeyPairEntry.Title"),
					problem);
			dProblem.setLocationRelativeTo(frame);
			dProblem.setVisible(true);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}
}
