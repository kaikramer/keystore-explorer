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
package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.TreeSet;

import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.Password;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.StringUtils;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;

/**
 * Displays the properties of a supplied KeyStore.
 *
 */
public class DProperties extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String NEWLINE = "\n";

	private JPanel jpButtons;
	private JButton jbCopy;
	private JButton jbOK;
	private JPanel jpProperties;
	private JTree jtrProperties;
	private JScrollPane jspProperties;
	private KeyStoreHistory history;
	private KeyStoreState currentState;
	private IndentSequence INDENT = new IndentSequence(IndentChar.SPACE, 4);

	/**
	 * Creates a new DProperties dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param history
	 *            KeyStore history
	 * @throws CryptoException
	 *             If a problem occurred while getting the properties
	 */
	public DProperties(JFrame parent, KeyStoreHistory history) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.history = history;
		this.currentState = history.getCurrentState();
		initComponents();
	}

	private void initComponents() throws CryptoException {
		jbCopy = new JButton(res.getString("DProperties.jbCopy.text"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DProperties.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(res.getString("DProperties.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DProperties.this);
					copyPressed();
				} finally {
					CursorUtil.setCursorFree(DProperties.this);
				}
			}
		});

		jbOK = new JButton(res.getString("DProperties.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy, true);

		jpProperties = new JPanel(new BorderLayout());
		jpProperties.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtrProperties = new JTree(createPropertiesNodes());
		jtrProperties.setRowHeight(Math.max(18, jtrProperties.getRowHeight()));
		jtrProperties.setShowsRootHandles(true);
		jtrProperties.setRootVisible(false);
		jtrProperties.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		jtrProperties.setCellRenderer(new PropertiesTreeCellRend());

		TreeNode topNode = (TreeNode) jtrProperties.getModel().getRoot();
		expandTwoLevels(new TreePath(topNode));

		jspProperties = PlatformUtil.createScrollPane(jtrProperties, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspProperties.setPreferredSize(new Dimension(400, 250));
		jpProperties.add(jspProperties, BorderLayout.CENTER);

		getContentPane().add(jpProperties, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(MessageFormat.format(res.getString("DProperties.Title"), history.getName()));
		setResizable(true);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				jbOK.requestFocus();
			}
		});
	}

	private DefaultMutableTreeNode createPropertiesNodes() throws CryptoException {
		KeyStore keyStore = currentState.getKeyStore();

		String root = MessageFormat.format(res.getString("DProperties.properties.Root"), history.getName());
		DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode(root);

		String file = history.getPath();
		DefaultMutableTreeNode fileNode = new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.File"), file));
		rootNode.add(fileNode);

		String type = keyStore.getType();
		DefaultMutableTreeNode typeNode = new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Type"), type));
		rootNode.add(typeNode);

		String provider = keyStore.getProvider().getName();
		DefaultMutableTreeNode providerNode = new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Provider"), provider));
		rootNode.add(providerNode);

		createKeysNodes(rootNode);

		createKeyPairsNodes(rootNode);

		createTrustedCertificatesNodes(rootNode);

		return rootNode;
	}

	private TreeSet<String> getAliasesInAlphaOrder() throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			TreeSet<String> aliases = new TreeSet<String>();

			Enumeration<String> enumAliases = keyStore.aliases();

			while (enumAliases.hasMoreElements()) {
				String alias = enumAliases.nextElement();

				if (KeyStoreUtil.isSupportedEntryType(alias, keyStore)) {
					aliases.add(alias);
				}
			}
			return aliases;
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createTrustedCertificatesNodes(DefaultMutableTreeNode parentNode) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			TreeSet<String> aliases = getAliasesInAlphaOrder();

			DefaultMutableTreeNode trustCertsNode = new DefaultMutableTreeNode(
					res.getString("DProperties.properties.TrustedCertificates"));
			parentNode.add(trustCertsNode);

			boolean trustCertsPresent = false;

			for (String alias : aliases) {
				if (KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
					createTrustedCertificateNodes(trustCertsNode, alias);

					trustCertsPresent = true;
				}
			}

			if (!trustCertsPresent) {
				DefaultMutableTreeNode emptyTrustCertsNode = new DefaultMutableTreeNode(
						res.getString("DProperties.properties.None"));
				trustCertsNode.add(emptyTrustCertsNode);
			}
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createTrustedCertificateNodes(DefaultMutableTreeNode parentNode, String alias) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			DefaultMutableTreeNode trustedCertificateNode = new DefaultMutableTreeNode(alias);
			parentNode.add(trustedCertificateNode);

			createLastModifiedNode(trustedCertificateNode, alias);

			X509Certificate trustedCertificate = X509CertUtil.convertCertificate(keyStore.getCertificate(alias));

			populateCertificateNode(trustedCertificateNode, trustedCertificate);
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void populateCertificateNode(DefaultMutableTreeNode certificateNode, X509Certificate certificate)
			throws CryptoException {
		try {
			String version = MessageFormat.format(res.getString("DProperties.properties.Version"),
					"" + certificate.getVersion());
			certificateNode.add(new DefaultMutableTreeNode(version));

			String subject = MessageFormat.format(res.getString("DProperties.properties.Subject"),
					X500NameUtils.x500PrincipalToX500Name(certificate.getSubjectX500Principal()));
			certificateNode.add(new DefaultMutableTreeNode(subject));

			String issuer = MessageFormat.format(res.getString("DProperties.properties.Issuer"),
					X500NameUtils.x500PrincipalToX500Name(certificate.getIssuerX500Principal()));
			certificateNode.add(new DefaultMutableTreeNode(issuer));

			String serialNumber = MessageFormat.format(res.getString("DProperties.properties.SerialNumber"),
					new BigInteger(certificate.getSerialNumber().toByteArray()).toString(16).toUpperCase());
			certificateNode.add(new DefaultMutableTreeNode(serialNumber));

			Date validFromDate = certificate.getNotBefore();
			String validFrom = MessageFormat.format(res.getString("DProperties.properties.ValidFrom"),
					StringUtils.formatDate(validFromDate));
			certificateNode.add(new DefaultMutableTreeNode(validFrom));

			Date validUntilDate = certificate.getNotAfter();
			String validUntil = MessageFormat.format(res.getString("DProperties.properties.ValidUntil"),
					StringUtils.formatDate(validUntilDate));
			certificateNode.add(new DefaultMutableTreeNode(validUntil));

			createPublicKeyNodes(certificateNode, certificate);

			String signatureAlgorithm = MessageFormat.format(
					res.getString("DProperties.properties.SignatureAlgorithm"),
					X509CertUtil.getCertificateSignatureAlgorithm(certificate));
			certificateNode.add(new DefaultMutableTreeNode(signatureAlgorithm));

			byte[] cert = certificate.getEncoded();

			String md5 = MessageFormat.format(res.getString("DProperties.properties.Md5Fingerprint"),
					DigestUtil.getFriendlyMessageDigest(cert, DigestType.MD5));
			certificateNode.add(new DefaultMutableTreeNode(md5));

			String sha1 = MessageFormat.format(res.getString("DProperties.properties.Sha1Fingerprint"),
					DigestUtil.getFriendlyMessageDigest(cert, DigestType.SHA1));
			certificateNode.add(new DefaultMutableTreeNode(sha1));
		} catch (CertificateEncodingException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createPublicKeyNodes(DefaultMutableTreeNode parentNode, X509Certificate certificate)
			throws CryptoException {
		createPublicKeyNodes(parentNode, certificate.getPublicKey());
	}

	private void createPublicKeyNodes(DefaultMutableTreeNode parentNode, PublicKey publicKey) throws CryptoException {
		DefaultMutableTreeNode publicKeyNode = new DefaultMutableTreeNode(
				res.getString("DProperties.properties.PublicKey"));
		parentNode.add(publicKeyNode);

		KeyInfo keyInfo = KeyPairUtil.getKeyInfo(publicKey);
		String keyAlg = keyInfo.getAlgorithm();

		publicKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Algorithm"), keyAlg)));

		Integer keySize = keyInfo.getSize();

		if (keySize != null) {
			publicKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
					res.getString("DProperties.properties.KeySize"), "" + keyInfo.getSize())));
		} else {
			publicKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
					res.getString("DProperties.properties.KeySize"), "?")));
		}

		String keyFormat = publicKey.getFormat();

		publicKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Format"), keyFormat)));

		String keyEncoded = "0x" + new BigInteger(1, publicKey.getEncoded()).toString(16).toUpperCase();

		publicKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Encoded"), keyEncoded)));

		if (publicKey instanceof RSAPublicKey) {
			RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

			String publicExponent = MessageFormat.format(
					res.getString("DProperties.properties.public.rsa.PublicExponent"), "0x"
							+ rsaPublicKey.getPublicExponent().toString(16).toUpperCase());
			publicKeyNode.add(new DefaultMutableTreeNode(publicExponent));

			String modulus = MessageFormat.format(res.getString("DProperties.properties.public.rsa.Modulus"), "0x"
					+ rsaPublicKey.getModulus().toString(16).toUpperCase());
			publicKeyNode.add(new DefaultMutableTreeNode(modulus));

		} else if (publicKey instanceof DSAPublicKey) {
			DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;

			DSAParams dsaParams = dsaPublicKey.getParams();

			String primeModulusP = MessageFormat.format(
					res.getString("DProperties.properties.public.dsa.PrimeModulusP"),
					"0x" + dsaParams.getP().toString(16).toUpperCase());
			publicKeyNode.add(new DefaultMutableTreeNode(primeModulusP));

			String primeQ = MessageFormat.format(res.getString("DProperties.properties.public.dsa.PrimeQ"), "0x"
					+ dsaParams.getQ().toString(16).toUpperCase());
			publicKeyNode.add(new DefaultMutableTreeNode(primeQ));

			String generatorG = MessageFormat.format(res.getString("DProperties.properties.public.dsa.GeneratorG"),
					"0x" + dsaParams.getG().toString(16).toUpperCase());
			publicKeyNode.add(new DefaultMutableTreeNode(generatorG));

			String publicKeyY = MessageFormat.format(res.getString("DProperties.properties.public.dsa.PublicKeyY"),
					"0x" + dsaPublicKey.getY().toString(16).toUpperCase());
			publicKeyNode.add(new DefaultMutableTreeNode(publicKeyY));
		}
	}

	private void createKeyPairsNodes(DefaultMutableTreeNode parentNode) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			TreeSet<String> aliases = getAliasesInAlphaOrder();

			DefaultMutableTreeNode keyPairsNode = new DefaultMutableTreeNode(
					res.getString("DProperties.properties.KeyPairs"));
			parentNode.add(keyPairsNode);

			boolean keyPairsPresent = false;

			for (String alias : aliases) {
				if (KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
					createKeyPairNodes(keyPairsNode, alias);

					keyPairsPresent = true;
				}
			}

			if (!keyPairsPresent) {
				DefaultMutableTreeNode emptyKeyPairNode = new DefaultMutableTreeNode(
						res.getString("DProperties.properties.None"));
				keyPairsNode.add(emptyKeyPairNode);
			}
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createKeyPairNodes(DefaultMutableTreeNode parentNode, String alias) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			DefaultMutableTreeNode keyPairNode = new DefaultMutableTreeNode(alias);
			parentNode.add(keyPairNode);

			createLastModifiedNode(keyPairNode, alias);

			createPrivateKeyNodes(keyPairNode, alias);

			X509Certificate[] certificates = X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias));

			DefaultMutableTreeNode certificatesNode = new DefaultMutableTreeNode(
					res.getString("DProperties.properties.Certificates"));
			keyPairNode.add(certificatesNode);

			for (int i = 0; i < certificates.length; i++) {
				X509Certificate certificate = certificates[i];

				DefaultMutableTreeNode certificateNode = new DefaultMutableTreeNode(
						X509CertUtil.getShortName(certificate));
				certificatesNode.add(certificateNode);

				populateCertificateNode(certificateNode, certificate);
			}
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createPrivateKeyNodes(DefaultMutableTreeNode parentNode, String alias) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			Password password = getEntryPassword(alias);

			if (password == null) {
				DefaultMutableTreeNode privateKeyNode = new DefaultMutableTreeNode(
						res.getString("DProperties.properties.PrivateKey"));
				parentNode.add(privateKeyNode);

				DefaultMutableTreeNode lockedNode = new DefaultMutableTreeNode(
						res.getString("DProperties.properties.Locked"));
				privateKeyNode.add(lockedNode);

				return;
			}

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

			createPrivateKeyNodes(parentNode, privateKey);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		} catch (UnrecoverableKeyException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createPrivateKeyNodes(DefaultMutableTreeNode parentNode, PrivateKey privateKey) throws CryptoException {
		DefaultMutableTreeNode privateKeyNode = new DefaultMutableTreeNode(
				res.getString("DProperties.properties.PrivateKey"));
		parentNode.add(privateKeyNode);
		currentState.getKeyStore();

		KeyInfo keyInfo = KeyPairUtil.getKeyInfo(privateKey);
		String keyAlg = keyInfo.getAlgorithm();

		privateKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Algorithm"), keyAlg)));

		Integer keySize = keyInfo.getSize();

		if (keySize != null) {
			privateKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
					res.getString("DProperties.properties.KeySize"), "" + keyInfo.getSize())));
		} else {
			privateKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
					res.getString("DProperties.properties.KeySize"), "?")));
		}

		String keyFormat = privateKey.getFormat();

		privateKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Format"), keyFormat)));

		String keyEncoded;
		byte[] encodedKey = privateKey.getEncoded();
		if (encodedKey != null) {
			keyEncoded = "0x" + new BigInteger(1, privateKey.getEncoded()).toString(16).toUpperCase();
		} else {
			keyEncoded = "*****";
		}

		privateKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Encoded"), keyEncoded)));

		if (privateKey instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;

			String publicExponent = MessageFormat.format(
					res.getString("DProperties.properties.private.rsa.PublicExponent"), "0x"
							+ rsaPrivateKey.getPublicExponent().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(publicExponent));

			String modulus = MessageFormat.format(res.getString("DProperties.properties.private.rsa.Modulus"), "0x"
					+ rsaPrivateKey.getModulus().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(modulus));

			String primeP = MessageFormat.format(res.getString("DProperties.properties.private.rsa.PrimeP"), "0x"
					+ rsaPrivateKey.getPrimeP().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(primeP));

			String primeQ = MessageFormat.format(res.getString("DProperties.properties.private.rsa.PrimeQ"), "0x"
					+ rsaPrivateKey.getPrimeQ().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(primeQ));

			String primeExponentP = MessageFormat.format(
					res.getString("DProperties.properties.private.rsa.PrimeExponentP"), "0x"
							+ rsaPrivateKey.getPrimeExponentP().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(primeExponentP));

			String primeExponentQ = MessageFormat.format(
					res.getString("DProperties.properties.private.rsa.PrimeExponentQ"), "0x"
							+ rsaPrivateKey.getPrimeExponentQ().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(primeExponentQ));

			String crtCoefficient = MessageFormat.format(
					res.getString("DProperties.properties.private.rsa.CrtCoefficient"), "0x"
							+ rsaPrivateKey.getCrtCoefficient().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(crtCoefficient));

			String privateExponent = MessageFormat.format(
					res.getString("DProperties.properties.private.rsa.PrivateExponent"), "0x"
							+ rsaPrivateKey.getPrivateExponent().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(privateExponent));

		} else if (privateKey instanceof DSAPrivateKey) {
			DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privateKey;

			DSAParams dsaParams = dsaPrivateKey.getParams();

			String primeModulusP = MessageFormat.format(
					res.getString("DProperties.properties.private.dsa.PrimeModulusP"), "0x"
							+ dsaParams.getP().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(primeModulusP));

			String primeQ = MessageFormat.format(res.getString("DProperties.properties.private.dsa.PrimeQ"), "0x"
					+ dsaParams.getQ().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(primeQ));

			String generatorG = MessageFormat.format(res.getString("DProperties.properties.private.dsa.GeneratorG"),
					"0x" + dsaParams.getG().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(generatorG));

			String secretExponentX = MessageFormat.format(
					res.getString("DProperties.properties.private.dsa.SecretExponentX"), "0x"
							+ dsaPrivateKey.getX().toString(16).toUpperCase());
			privateKeyNode.add(new DefaultMutableTreeNode(secretExponentX));
		}

	}

	private Password getEntryPassword(String alias) {
		Password password = currentState.getEntryPassword(alias);

		return password;
	}

	private void createKeysNodes(DefaultMutableTreeNode parentNode) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			TreeSet<String> aliases = getAliasesInAlphaOrder();

			DefaultMutableTreeNode keysNode = new DefaultMutableTreeNode(res.getString("DProperties.properties.Keys"));
			parentNode.add(keysNode);

			boolean keysPresent = false;

			for (String alias : aliases) {
				if (KeyStoreUtil.isKeyEntry(alias, keyStore)) {
					createKeyNodes(keysNode, alias);

					keysPresent = true;
				}
			}

			if (!keysPresent) {
				DefaultMutableTreeNode emptyKeyNode = new DefaultMutableTreeNode(
						res.getString("DProperties.properties.None"));
				keysNode.add(emptyKeyNode);
			}
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createKeyNodes(DefaultMutableTreeNode parentNode, String alias) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			DefaultMutableTreeNode keyNode = new DefaultMutableTreeNode(alias);
			parentNode.add(keyNode);

			createLastModifiedNode(keyNode, alias);

			Password password = getEntryPassword(alias);

			if (password == null) {
				DefaultMutableTreeNode lockedNode = new DefaultMutableTreeNode(
						res.getString("DProperties.properties.Locked"));
				keyNode.add(lockedNode);

				return;
			}

			Key key = keyStore.getKey(alias, password.toCharArray());

			if (key instanceof PublicKey) {
				createPublicKeyNodes(keyNode, (PublicKey) key);
			} else if (key instanceof PrivateKey) {
				createPrivateKeyNodes(keyNode, (PrivateKey) key);
			} else if (key instanceof SecretKey) {
				createSecretKeyNodes(keyNode, (SecretKey) key);
			}
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		} catch (KeyStoreException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		} catch (UnrecoverableKeyException ex) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), ex);
		}
	}

	private void createSecretKeyNodes(DefaultMutableTreeNode parentNode, SecretKey secretKey) {
		DefaultMutableTreeNode secretKeyNode = new DefaultMutableTreeNode(
				res.getString("DProperties.properties.SecretKey"));
		parentNode.add(secretKeyNode);

		KeyInfo keyInfo = SecretKeyUtil.getKeyInfo(secretKey);
		String keyAlg = keyInfo.getAlgorithm();

		// Try and get friendly algorithm name for secret key
		SecretKeyType secretKeyType = SecretKeyType.resolveJce(keyAlg);

		if (secretKeyType != null) {
			keyAlg = secretKeyType.friendly();
		}

		secretKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Algorithm"), keyAlg)));

		Integer keySize = keyInfo.getSize();

		if (keySize != null) {
			secretKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
					res.getString("DProperties.properties.KeySize"), "" + keyInfo.getSize())));
		} else {
			secretKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
					res.getString("DProperties.properties.KeySize"), "?")));
		}

		String keyFormat = secretKey.getFormat();

		secretKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Format"), keyFormat)));

		String keyEncoded = "0x" + new BigInteger(1, secretKey.getEncoded()).toString(16).toUpperCase();

		secretKeyNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				res.getString("DProperties.properties.Encoded"), keyEncoded)));
	}

	private void createLastModifiedNode(DefaultMutableTreeNode parentNode, String alias) throws CryptoException {
		try {
			KeyStore keyStore = currentState.getKeyStore();

			if (KeyStoreType.resolveJce(keyStore.getType()) != KeyStoreType.PKCS12) {
				String lastModified = MessageFormat.format(res.getString("DProperties.properties.LastModified"),
						StringUtils.formatDate(keyStore.getCreationDate(alias)));
				parentNode.add(new DefaultMutableTreeNode(lastModified));
			}
		} catch (ProviderException e) {
			// some keystore types do not provide creation dates for their entries => simply create no node
		} catch (KeyStoreException e) {
			throw new CryptoException(res.getString("DProperties.NoGetProperties.exception.message"), e);
		}
	}

	private void copyPressed() {
		String properties = getNodeContents((TreeNode) jtrProperties.getModel().getRoot(), 0);

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(properties);
		clipboard.setContents(copy, copy);
	}

	private void expandTwoLevels(TreePath treePath) {
		if (treePath.getPathCount() > 2) {
			return;
		}

		TreeNode node = (TreeNode) treePath.getLastPathComponent();

		if (node.getChildCount() >= 0) {
			for (Enumeration<?> enumChildren = node.children(); enumChildren.hasMoreElements();) {
				TreeNode subNode = (TreeNode) enumChildren.nextElement();
				TreePath path = treePath.pathByAddingChild(subNode);
				expandTwoLevels(path);
			}
		}

		jtrProperties.expandPath(treePath);
	}

	private String getNodeContents(TreeNode node, int level) {
		StringBuffer strBuff = new StringBuffer();

		strBuff.append(INDENT.toString(level));

		strBuff.append(node.toString().trim());
		strBuff.append(NEWLINE);

		for (int i = 0; i < node.getChildCount(); i++) {
			strBuff.append(getNodeContents(node.getChildAt(i), level + 1));
		}

		return strBuff.toString();
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
