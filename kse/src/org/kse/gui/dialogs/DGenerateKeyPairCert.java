/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui.dialogs;

import static org.kse.crypto.x509.X509CertificateVersion.VERSION1;
import static org.kse.crypto.x509.X509CertificateVersion.VERSION3;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertificateGenerator;
import org.kse.crypto.x509.X509ExtensionSet;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.crypto.JValidityPeriod;
import org.kse.gui.datetime.JDateTime;
import org.kse.gui.dialogs.extensions.DAddExtensions;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to generate a certificate based on a supplied key pair and
 * signature algorithm for inclusion in a KeyStore.
 *
 */
public class DGenerateKeyPairCert extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlVersion;
	private JRadioButton jrbVersion1;
	private JRadioButton jrbVersion3;
	private JLabel jlSigAlg;
	private JComboBox<SignatureType> jcbSignatureAlgorithm;
	private JLabel jlValidityStart;
	private JDateTime jdtValidityStart;
	private JLabel jlValidityEnd;
	private JDateTime jdtValidityEnd;
	private JLabel jlValidityPeriod;
	private JValidityPeriod jvpValidityPeriod;
	private JLabel jlSerialNumber;
	private JTextField jtfSerialNumber;
	private JLabel jlName;
	private JDistinguishedName jdnName;
	private JButton jbAddExtensions;
	private JButton jbOK;
	private JButton jbCancel;

	private KeyPair keyPair;
	private KeyPairType keyPairType;
	private X509Certificate certificate;
	private X509ExtensionSet extensions = new X509ExtensionSet();

	private X509Certificate issuerCert;
	private PrivateKey issuerPrivateKey;

	private Provider provider;

	/**
	 * Creates a new DGenerateKeyPairCert dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog's title
	 * @param keyPair
	 *            The key pair to generate the certificate from
	 * @param keyPairType
	 *            The key pair type
	 * @param issuerPrivateKey
	 * 	          The signing key pair (issuer CA)
	 * @throws CryptoException
	 *             A problem was encountered with the supplied key pair
	 */
	public DGenerateKeyPairCert(JFrame parent, String title, KeyPair keyPair, KeyPairType keyPairType,
			X509Certificate issuerCert, PrivateKey issuerPrivateKey, Provider provider) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.keyPair = keyPair;
		this.keyPairType = keyPairType;
		this.issuerCert = issuerCert;
		this.issuerPrivateKey = issuerPrivateKey;
		this.provider = provider;
		initComponents(title);
	}

	private void initComponents(String title) throws CryptoException {

		jlVersion = new JLabel(res.getString("DGenerateKeyPairCert.jlVersion.text"));

		jrbVersion1 = new JRadioButton(res.getString("DGenerateKeyPairCert.jrbVersion1.text"));
		jrbVersion1.setToolTipText(res.getString("DGenerateKeyPairCert.jrbVersion1.tooltip"));

		jrbVersion3 = new JRadioButton(res.getString("DGenerateKeyPairCert.jrbVersion3.text"));
		jrbVersion3.setToolTipText(res.getString("DGenerateKeyPairCert.jrbVersion3.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbVersion1);
		buttonGroup.add(jrbVersion3);
		jrbVersion3.setSelected(true);

		jlSigAlg = new JLabel(res.getString("DGenerateKeyPairCert.jlSigAlg.text"));

		jcbSignatureAlgorithm = new JComboBox<>();
		jcbSignatureAlgorithm.setToolTipText(res.getString("DGenerateKeyPairCert.jcbSignatureAlgorithm.tooltip"));
		jcbSignatureAlgorithm.setMaximumRowCount(10);

		// populate signature algorithm selector
		if (issuerPrivateKey != null) {
			KeyPairType issuerKeyPairType = KeyPairType.resolveJce(issuerPrivateKey.getAlgorithm());
			DialogHelper.populateSigAlgs(issuerKeyPairType, issuerPrivateKey, jcbSignatureAlgorithm);
		} else {
			// self-signed
			DialogHelper.populateSigAlgs(keyPairType, keyPair.getPrivate(), jcbSignatureAlgorithm);
		}

		Date now = new Date();

		jlValidityStart = new JLabel(res.getString("DGenerateKeyPairCert.jlValidityStart.text"));

		jdtValidityStart = new JDateTime(res.getString("DGenerateKeyPairCert.jdtValidityStart.text"), false);
		jdtValidityStart.setDateTime(now);
		jdtValidityStart.setToolTipText(res.getString("DGenerateKeyPairCert.jdtValidityStart.tooltip"));

		jlValidityPeriod = new JLabel(res.getString("DGenerateKeyPairCert.jlValidityPeriod.text"));

		jvpValidityPeriod = new JValidityPeriod(JValidityPeriod.YEARS);
		jvpValidityPeriod.setToolTipText(res.getString("DGenerateKeyPairCert.jvpValidityPeriod.tooltip"));

		jlValidityEnd = new JLabel(res.getString("DGenerateKeyPairCert.jlValidityEnd.text"));

		jdtValidityEnd = new JDateTime(res.getString("DGenerateKeyPairCert.jdtValidityEnd.text"), false);
		jdtValidityEnd.setDateTime(new Date(now.getTime() + TimeUnit.DAYS.toMillis(365)));
		jdtValidityEnd.setToolTipText(res.getString("DGenerateKeyPairCert.jdtValidityEnd.tooltip"));

		jlSerialNumber = new JLabel(res.getString("DGenerateKeyPairCert.jlSerialNumber.text"));

		jtfSerialNumber = new JTextField("" + generateSerialNumber(), 20);
		jtfSerialNumber.setToolTipText(res.getString("DGenerateKeyPairCert.jtfSerialNumber.tooltip"));

		jlName = new JLabel(res.getString("DGenerateKeyPairCert.jlName.text"));

		jdnName = new JDistinguishedName(res.getString("DGenerateKeyPairCert.jdnName.title"), 30, true);
		jdnName.setToolTipText(res.getString("DGenerateKeyPairCert.jdnName.tooltip"));

		jbAddExtensions = new JButton(res.getString("DGenerateKeyPairCert.jbAddExtensions.text"));
		jbAddExtensions.setMnemonic(res.getString("DGenerateKeyPairCert.jbAddExtensions.mnemonic").charAt(0));
		jbAddExtensions.setToolTipText(res.getString("DGenerateKeyPairCert.jbAddExtensions.tooltip"));

		jbCancel = new JButton(res.getString("DGenerateKeyPairCert.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jbOK = new JButton(res.getString("DGenerateKeyPairCert.jbOK.text"));

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		pane.add(jlVersion, "");
		pane.add(jrbVersion1, "split 2");
		pane.add(jrbVersion3, "wrap");
		pane.add(jlSigAlg, "");
		pane.add(jcbSignatureAlgorithm, "wrap");
		pane.add(jlValidityStart, "");
		pane.add(jdtValidityStart, "wrap");
		pane.add(jlValidityPeriod, "");
		pane.add(jvpValidityPeriod, "wrap");
		pane.add(jlValidityEnd, "");
		pane.add(jdtValidityEnd, "wrap");
		pane.add(jlSerialNumber, "");
		pane.add(jtfSerialNumber, "wrap");
		pane.add(jlName, "");
		pane.add(jdnName, "wrap");
		pane.add(jbAddExtensions, "spanx");
		pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
		pane.add(jbCancel, "spanx, split 2, tag cancel");
		pane.add(jbOK, "tag ok");


		jvpValidityPeriod.addApplyActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Date startDate = jdtValidityStart.getDateTime();
				if(startDate == null) {
					startDate = new Date();
					jdtValidityStart.setDateTime(startDate);
				}
				Date validityEnd = jvpValidityPeriod.getValidityEnd(startDate);
				jdtValidityEnd.setDateTime(validityEnd);

			}
		});

		jbAddExtensions.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DGenerateKeyPairCert.this);
					addExtensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DGenerateKeyPairCert.this);
				}
			}
		});

		jrbVersion3.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent evt) {
				jbAddExtensions.setEnabled(jrbVersion3.isSelected());
			}
		});

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setTitle(title);
		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void addExtensionsPressed() {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PublicKey caPublicKey = null;
		X500Name caIssuerName = null;
		BigInteger caSerialNumber = null;
		if (issuerCert != null) {
			caIssuerName = X500NameUtils.x500PrincipalToX500Name(issuerCert.getIssuerX500Principal());
			caPublicKey = issuerCert.getPublicKey();
			caSerialNumber = issuerCert.getSerialNumber();
		} else {
			caIssuerName = jdnName.getDistinguishedName(); // May be null
			caPublicKey = keyPair.getPublic();

			String serialNumberStr = jtfSerialNumber.getText().trim();
			if (serialNumberStr.length() != 0) {
				try {
					caSerialNumber = parseDecOrHex(serialNumberStr);
				} catch (NumberFormatException ex) {
					// Don't set serial number
				}
			}
		}

		DAddExtensions dAddExtensions = new DAddExtensions(this, extensions, caPublicKey, caIssuerName, caSerialNumber,
				subjectPublicKey);
		dAddExtensions.setLocationRelativeTo(this);
		dAddExtensions.setVisible(true);

		if (dAddExtensions.getExtensions() != null) {
			extensions = dAddExtensions.getExtensions();
		}
	}

	/**
	 * Parses a string initially as a decimal value, or as a hexadecimal value if that failed but the string is a
	 * valid hex value. To avoid ambiguity, hex parsing can be forced by prefixing the input with '0x'.
	 *
	 * @param input The String to parse
	 * @return a BigInteger representation of the input.
	 */
	private BigInteger parseDecOrHex(String input) {
		try {
			return new BigInteger(input);
		} catch (NumberFormatException nfe) {
			if (input.startsWith("0x")) {
				return new BigInteger(input.substring(2), 16);
			}
			else if (input.matches("^\\p{XDigit}+$")) {
				return new BigInteger(input, 16);
			}
			else {
				throw nfe;
			}
		}
	}

	private boolean generateCertificate() {
		Date validityStart = jdtValidityStart.getDateTime();
		Date validityEnd = jdtValidityEnd.getDateTime();

		String serialNumberStr = jtfSerialNumber.getText().trim();
		if (serialNumberStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DGenerateKeyPairCert.ValReqSerialNumber.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		BigInteger serialNumber;
		try {
			serialNumber = parseDecOrHex(serialNumberStr);
			if (serialNumber.compareTo(BigInteger.ONE) < 0) {
				JOptionPane.showMessageDialog(this, res.getString("DGenerateKeyPairCert.SerialNumberNonZero.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return false;
			}
		} catch (NumberFormatException ex) {
			JOptionPane.showMessageDialog(this, res.getString("DGenerateKeyPairCert.SerialNumberNotInteger.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}

		X500Name x500Name = jdnName.getDistinguishedName();

		if (x500Name == null || x500Name.toString().isEmpty()) {
			JOptionPane.showMessageDialog(this, res.getString("DGenerateKeyPairCert.NameValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return false;
		}

		try {
			SignatureType signatureType = ((SignatureType) jcbSignatureAlgorithm.getSelectedItem());

			X509CertificateGenerator generator;

			if (jrbVersion1.isSelected()) {
				generator = new X509CertificateGenerator(VERSION1);
			} else {
				generator = new X509CertificateGenerator(VERSION3);
			}

			// self-signed or signed by other key pair?
			if (issuerPrivateKey == null) {
				certificate = generator.generateSelfSigned(x500Name, validityStart, validityEnd, keyPair.getPublic(),
						keyPair.getPrivate(), signatureType, serialNumber, extensions, provider);
			} else {
				certificate = generator.generate(x500Name,
						X500NameUtils.x500PrincipalToX500Name(issuerCert.getSubjectX500Principal()),
						validityStart, validityEnd, keyPair.getPublic(), issuerPrivateKey, signatureType, serialNumber,
						extensions, provider);
			}
		} catch (CryptoException e) {
			DError.displayError(this, e);
			closeDialog();
		}

		return true;
	}

	private long generateSerialNumber() {
		return System.currentTimeMillis() / 1000;
	}

	/**
	 * Get the generated certificate.
	 *
	 * @return The generated certificate or null if the user cancelled the
	 *         dialog
	 */
	public X509Certificate getCertificate() {
		return certificate;
	}

	private void okPressed() {
		if (generateCertificate()) {
			closeDialog();
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	// for quick testing
	public static void main(String[] args) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyGen.initialize(1024);
		KeyPair keyPair = keyGen.genKeyPair();

		DGenerateKeyPairCert dialog = new DGenerateKeyPairCert(new javax.swing.JFrame(), "test", keyPair,
				KeyPairType.RSA, null, null, new BouncyCastleProvider());
		DialogViewer.run(dialog);
	}
}
