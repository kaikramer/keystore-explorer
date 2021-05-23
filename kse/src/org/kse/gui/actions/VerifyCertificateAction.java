package org.kse.gui.actions;

import java.awt.Toolkit;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.crypto.CryptoException;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DVerifyCertificate;
import org.kse.gui.dialogs.DVerifyCertificate.VerifyOptions;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

public class VerifyCertificateAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = 1L;
	private X509Certificate certificateEval;
	private X509Certificate[] chain;

	public VerifyCertificateAction(KseFrame kseFrame) {
		super(kseFrame);
		putValue(LONG_DESCRIPTION, res.getString("VerifyCertificateAction.statusbar"));
		putValue(NAME, res.getString("VerifyCertificateAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("VerifyCertificateAction.tooltip"));
		putValue(SMALL_ICON, new ImageIcon(
				Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/verifycert.png"))));
	}

	public VerifyCertificateAction(KseFrame kseFrame, X509Certificate cert, X509Certificate[] chain) {
		super(kseFrame);
		this.certificateEval = cert;
		this.chain = chain;
	}

	@Override
	protected void doAction() {

		try {
			String alias = "";
			if (certificateEval == null) {
				alias = kseFrame.getSelectedEntryAlias();
				certificateEval = getCertificate(alias);
				chain = getCertificateChain(alias);
			} else {
				alias = X509CertUtil.getCertificateAlias(certificateEval);
			}
			// if the certificate is expired it should not be evaluated
			Date now = new Date(System.currentTimeMillis());
			if (certificateEval.getNotAfter().before(now)) {
				JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.certExpired.message"),
						res.getString("VerifyCertificateAction.Verify.Title") + " " + alias,
						JOptionPane.WARNING_MESSAGE);
			} else {
				DVerifyCertificate dVerifyCertificate = new DVerifyCertificate(frame, alias, kseFrame);
				dVerifyCertificate.setLocationRelativeTo(frame);
				dVerifyCertificate.setVisible(true);
				if (dVerifyCertificate.isVerifySelected()) {

					VerifyOptions verifyOptions = dVerifyCertificate.getVerifyOption();
					KeyStoreHistory keyStoreHistory = dVerifyCertificate.getKeyStore();
					if (verifyOptions == VerifyOptions.CRL) {
						verifyStatusCrl(keyStoreHistory, alias);
					} else if (verifyOptions == VerifyOptions.OCSP) {
						verifyStatusOCSP(keyStoreHistory, alias);
					} else {						
						verifyChain(keyStoreHistory, alias);
					}
				}
			}
		} catch (CertPathValidatorException cex) {
			JOptionPane.showMessageDialog(frame, cex.getMessage(),
					res.getString("VerifyCertificateAction.Verify.Title"), JOptionPane.WARNING_MESSAGE);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		} finally {
			certificateEval = null;
		}
	}

	private void verifyChain(KeyStoreHistory keyStoreHistory, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {
		if (verify("false", "false", false, keyStoreHistory)) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.ChainSuccessful.message"),
					res.getString("VerifyCertificateAction.Verify.Title") + " " + alias,
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void verifyStatusOCSP(KeyStoreHistory keyStoreHistory, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {
		if (verify("false", "true", true, keyStoreHistory)) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.OcspSuccessful.message"),
					res.getString("VerifyCertificateAction.Verify.Title") + " " + alias,
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void verifyStatusCrl(KeyStoreHistory keyStoreHistory, String alias)
			throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {
		if (verify("true", "false", true, keyStoreHistory)) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.CrlSuccessful.message"),
					res.getString("VerifyCertificateAction.Verify.Title") + " " + alias,
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private boolean verify(String crl, String ocsp, boolean revocationEnabled, KeyStoreHistory keyStoreHistory)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {

		KeyStore trustStore = getKeyStore(keyStoreHistory);

		if (trustStore == null) {
			return false;
		}
		if (trustStore.size() == 0) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.trustStoreEmpty.message"),
					res.getString("VerifyCertificateAction.Verify.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		System.setProperty("com.sun.net.ssl.checkRevocation", crl);
		System.setProperty("com.sun.security.enableCRLDP", crl);
		Security.setProperty("ocsp.enable", ocsp);

		List<X509Certificate> listCertificates = new ArrayList<>();
		if (revocationEnabled) {
			listCertificates.add(certificateEval);
		} else {
			if (chain != null) {
				for (int i = chain.length - 1; i >= 0; i--) {
					X509Certificate cert = chain[i];
					listCertificates.add(0, cert);
					if (cert.equals(certificateEval)) {
						break;
					}
				}
			}
		}

		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		CertificateFactory factory = CertificateFactory.getInstance("X509");
		CertPath certPath = factory.generateCertPath(listCertificates);
		PKIXParameters params = new PKIXParameters(trustStore);
		Date now = new Date(System.currentTimeMillis());
		params.setDate(now);
		params.setRevocationEnabled(revocationEnabled);
		validator.validate(certPath, params);
		return true;
	}

	private boolean isCA(X509Certificate cert) {
		int basicConstraints = cert.getBasicConstraints();
		if (basicConstraints != -1) {
			boolean[] keyUsage = cert.getKeyUsage();
			if (keyUsage != null && keyUsage[5]) {
				return true;
			}
		}
		return false;
	}

	private KeyStore getKeyStore(KeyStoreHistory keyStoreHistory)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		KeyStore trustStore = null;
		trustStore = KeyStore.getInstance("JCEKS");
		trustStore.load(null, null);
		if (keyStoreHistory != null) {

			KeyStore tempTrustStore = keyStoreHistory.getCurrentState().getKeyStore();
			Enumeration<String> enumeration = tempTrustStore.aliases();
			while (enumeration.hasMoreElements()) {
				String alias = enumeration.nextElement();
				X509Certificate cert = (X509Certificate) tempTrustStore.getCertificate(alias);
				if (isCA(cert)) {
					trustStore.setCertificateEntry(alias, cert);
				}
			}
		}
		if (trustStore.size() == 0) {
			if (chain != null) {
				for (int i = 0; i < chain.length; i++) {
					X509Certificate cert = chain[i];
					if (isCA(cert)) {
						String entry = "entry" + i;
						trustStore.setCertificateEntry(entry, cert);
					}
				}
			}			
		}
		return trustStore;
	}

	private X509Certificate getCertificate(String alias) throws CryptoException {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStore keyStore = history.getCurrentState().getKeyStore();

			return X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
		} catch (KeyStoreException ex) {
			String message = MessageFormat.format(res.getString("VerifyCertificateAction.NoAccessEntry.message"),
					alias);
			throw new CryptoException(message, ex);
		}
	}

	private X509Certificate[] getCertificateChain(String alias) throws CryptoException {
		try {
			KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
			KeyStore keyStore = history.getCurrentState().getKeyStore();
			X509Certificate[] certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias));
			return certs;
		} catch (KeyStoreException ex) {
			String message = MessageFormat.format(res.getString("VerifyCertificateAction.NoAccessEntry.message"),
					alias);
			throw new CryptoException(message, ex);
		}
	}

}
