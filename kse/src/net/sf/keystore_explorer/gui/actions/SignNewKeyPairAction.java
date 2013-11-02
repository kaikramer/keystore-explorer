package net.sf.keystore_explorer.gui.actions;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.crypto.x509.X509CertUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;
import net.sf.keystore_explorer.utilities.history.KeyStoreState;

/**
 * Action to sign a newly generated key pair (i.e. generate a certificate) using the selected key pair entry as issuing
 * CA.
 * 
 */
public class SignNewKeyPairAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = 6130302168441299361L;

	public SignNewKeyPairAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(LONG_DESCRIPTION, res.getString("SignNewKeyPairAction.statusbar"));
		putValue(NAME, res.getString("SignNewKeyPairAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SignNewKeyPairAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("SignNewKeyPairAction.image")))));
	}

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
			Certificate[] certs = keyStore.getCertificateChain(alias);

			X509Certificate[] signingChain = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));
			X509Certificate signingCert = signingChain[0];

			GenerateKeyPairAction generateKeyPairAction = new GenerateKeyPairAction(kseFrame);
			String newAlias = generateKeyPairAction.generateKeyPair(signingCert, privateKey);
			
			// TODO add issuer to chain

		} catch (Exception ex) {
			DError.displayError(frame, ex);
			return;
		}
	}

}
