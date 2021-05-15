package org.kse.gui.actions;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import org.kse.crypto.CryptoException;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DVerifyCertificate;
import org.kse.gui.dialogs.importexport.DExportCertificates;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

public class VerifyCertificateAction extends KeyStoreExplorerAction{

	private static final long serialVersionUID = 1L;
	private X509Certificate certFromConstructor;

	public VerifyCertificateAction(KseFrame kseFrame) {
		super(kseFrame);
	}

	public VerifyCertificateAction(KseFrame kseFrame, X509Certificate cert) {
		super(kseFrame);
		this.certFromConstructor = cert;
	}
	
	@Override
	protected void doAction() {
		try
		{
			DVerifyCertificate dVerifyCertificate = null;
			X509Certificate cert = null;
			if (certFromConstructor == null) {
				String alias = kseFrame.getSelectedEntryAlias();
				dVerifyCertificate = new DVerifyCertificate(frame, alias);
				cert = getCertificate(alias);
			} else {
				cert = certFromConstructor;
				dVerifyCertificate = new DVerifyCertificate(frame, X509CertUtil.getCertificateAlias(cert));
			}
	
			dVerifyCertificate.setLocationRelativeTo(frame);
			dVerifyCertificate.setVisible(true);
		}
		catch(Exception ex)
		{
			DError.displayError(frame, ex);
		}
	}

	private X509Certificate getCertificate(String alias) throws CryptoException {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStore keyStore = history.getCurrentState().getKeyStore();

			return X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} catch (KeyStoreException ex) {
			String message = MessageFormat.format(
					res.getString("ExportTrustedCertificateAction.NoAccessEntry.message"), alias);
			throw new CryptoException(message, ex);
		}
	}
}
