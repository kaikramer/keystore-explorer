package org.kse.gui.actions;

import java.awt.Toolkit;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.swing.ImageIcon;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

public class SignCrlAction extends KeyStoreExplorerAction {

	private static final long serialVersionUID = 1L;
	public static final long THIRTY_DAYS = 1000L * 60 * 60 * 24 * 30;

	public SignCrlAction(KseFrame kseFrame) {
		super(kseFrame);
		putValue(LONG_DESCRIPTION, res.getString("SignCrlAction.statusbar"));
		putValue(NAME, res.getString("SignCrlAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("SignCrlAction.tooltip"));
		putValue(SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/signcrl.png"))));
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
			Provider provider = history.getExplicitProvider();

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			X509Certificate[] certs = X509CertUtil
					.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias)));
			KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

			String pathFile = history.getPath();
			File file = new File(pathFile);
			String path = file.getParentFile().getAbsolutePath();
			String newPath = path + File.separator + convertSignatureName(alias);  
			signCrl(new BigInteger("1"), new Date(), new Date(System.currentTimeMillis() + THIRTY_DAYS), certs[0],
					privateKey, newPath, "SHA256withRSA", null);

		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private void signCrl(BigInteger number, Date effectiveDate, Date nextUpdate, X509Certificate caCert,
			PrivateKey caPrivateKey, String signatureName, String signatureAlgorithm,
			List<X509Certificate> listRevokedCertificate)
			throws NoSuchAlgorithmException, OperatorCreationException, CRLException, IOException {

		X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), effectiveDate);
		crlGen.setNextUpdate(nextUpdate);

		if (listRevokedCertificate != null) {
			for (X509Certificate cert : listRevokedCertificate) {
				crlGen.addCRLEntry(cert.getSerialNumber(), new Date(), CRLReason.privilegeWithdrawn);
			}
		}
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

		crlGen.addExtension(Extension.authorityKeyIdentifier, false,
				extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

		crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(number));

		X509CRLHolder crl = crlGen
				.build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(caPrivateKey));
		X509CRL x509CRL = new JcaX509CRLConverter().setProvider("BC").getCRL(crl);
		byte[] data = x509CRL.getEncoded();
		if (data != null) {
			InputStream in = new ByteArrayInputStream(data);
			int length;
			byte[] buffer = new byte[1024];
			try (FileOutputStream fileOutputStream = new FileOutputStream(signatureName + ".crl")) {
				while ((length = in.read(buffer)) != -1) {
					fileOutputStream.write(buffer, 0, length);
				}
			}
		}
	}

	private String convertSignatureName(String signatureName) {
		/*
		 * Convert the supplied signature name to make it valid for use with signing,
		 * i.e. any characters that are not 'a-z', 'A-Z', '0-9', '_' or '-' are
		 * converted to '_'
		 */
		StringBuilder sb = new StringBuilder(signatureName.length());

		for (int i = 0; i < signatureName.length(); i++) {
			char c = signatureName.charAt(i);

			if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_') {
				c = '_';
			}
			sb.append(c);
		}

		return sb.toString();
	}
}
