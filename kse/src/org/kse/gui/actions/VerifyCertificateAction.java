package org.kse.gui.actions;

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
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
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.kse.ApplicationSettings;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keystore.KeyStoreLoadException;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DVerifyCertificate;
import org.kse.gui.dialogs.DVerifyCertificate.VerifyOptions;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetPassword;
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

		ApplicationSettings applicationSettings = ApplicationSettings.getInstance();

		File caCertificatesFile = applicationSettings.getCaCertificatesFile();

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
						res.getString("VerifyCertificateAction.Verify.Title") + " " + alias, JOptionPane.WARNING_MESSAGE);
			} else {
				DVerifyCertificate dVerifyCertificate = new DVerifyCertificate(frame, alias, caCertificatesFile.toString());
				dVerifyCertificate.setLocationRelativeTo(frame);
				dVerifyCertificate.setVisible(true);
				if (dVerifyCertificate.isVerifySelected()) {

					VerifyOptions verifyOptions = dVerifyCertificate.getVerifyOption();
					if (verifyOptions == VerifyOptions.CRL) {
						verifyStatusCrl(alias);
					} else if (verifyOptions == VerifyOptions.OCSP) {
						verifyStatusOCSP(alias);
					} else {
						verifyChain(dVerifyCertificate.getCaCertificateFile(), alias);
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

	private void verifyChain(String caCertificateFile, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {
		if (verify("false", "false", false, caCertificateFile)) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.ChainSuccessful.message"),
					res.getString("VerifyCertificateAction.Verify.Title") + " " +  alias, JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void verifyStatusOCSP(String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {
		if (verify("false", "true", true, "")) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.OcspSuccessful.message"),
					res.getString("VerifyCertificateAction.Verify.Title") + " " + alias, JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void verifyStatusCrl(String alias)
			throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {
		if (verify("true", "false", true, "")) {
			JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.CrlSuccessful.message"),
					res.getString("VerifyCertificateAction.Verify.Title") + " " + alias, JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private boolean verify(String crl, String ocsp, boolean revocationEnabled, String caCertificateFile)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, CryptoException {

		KeyStore trustStore = createOrOpenKeyStore(caCertificateFile);

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

	private KeyStore createOrOpenKeyStore(String caCertificateFile)
			throws CryptoException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore trustStore = null;
		if (!caCertificateFile.isEmpty()) {
			File keyStoreFile = new File(caCertificateFile);
			trustStore = openKeyStore(keyStoreFile, trustStore);
		} else {
			trustStore = KeyStore.getInstance("JCEKS");
			trustStore.load(null, null);
			if (chain != null) {
				for (int i = 0; i < chain.length; i++) {
					X509Certificate cert = chain[i];
					int basicConstraints = cert.getBasicConstraints();
					if (basicConstraints != -1) {
						boolean[] keyUsage = cert.getKeyUsage();
						if (keyUsage != null && keyUsage[5]) {
							// CA certificate
							String entry = "entry" + i;
							trustStore.setCertificateEntry(entry, cert);
						}
					}
				}
			}
		}
		return trustStore;
	}

	private KeyStore openKeyStore(File keyStoreFile, KeyStore trustStore)
			throws CryptoException, FileNotFoundException {

		if (!keyStoreFile.exists()) {
			throw new FileNotFoundException(res.getString("VerifyCertificateAction.FileNotFoundException.message"));
		}

		while (true) {
			try {
				Password password = getPassword(keyStoreFile);
				if (password == null || password.isNulled()) {
					return null;
				}
				return KeyStoreUtil.load(keyStoreFile, password);
			} catch (KeyStoreLoadException klex) {
				int tryAgainChoice = showErrorMessage(keyStoreFile, klex);
				if (tryAgainChoice == JOptionPane.NO_OPTION) {
					return null;
				}
			}
		}
	}

	private Password getPassword(File file) {
		DGetPassword dGetPassword = new DGetPassword(frame,
				MessageFormat.format(res.getString("VerifyCertificateAction.EnterPassword.Title"), file.getName()));
		dGetPassword.setLocationRelativeTo(frame);
		dGetPassword.setVisible(true);
		return dGetPassword.getPassword();
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

	private int showErrorMessage(File keyStoreFile, KeyStoreLoadException klex) {
		String problemStr = MessageFormat.format(res.getString("OpenAction.NoOpenKeyStore.Problem"),
				klex.getKeyStoreType().friendly(), keyStoreFile.getName());

		String[] causes = new String[] { res.getString("OpenAction.PasswordIncorrectKeyStore.Cause"),
				res.getString("OpenAction.CorruptedKeyStore.Cause") };

		Problem problem = new Problem(problemStr, causes, klex);

		DProblem dProblem = new DProblem(frame, res.getString("OpenAction.ProblemOpeningKeyStore.Title"), problem);
		dProblem.setLocationRelativeTo(frame);
		dProblem.setVisible(true);

		return JOptionPane.showConfirmDialog(frame, res.getString("OpenAction.TryAgain.message"),
				res.getString("OpenAction.TryAgain.Title"), JOptionPane.YES_NO_OPTION);
	}
}
