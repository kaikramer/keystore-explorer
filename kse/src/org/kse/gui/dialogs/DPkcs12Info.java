/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.encryptedData;
import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.envelopedData;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes128_CBC;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes192_CBC;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.certBag;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.keyBag;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs8ShroudedKeyBag;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_friendlyName;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_localKeyId;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.x509Certificate;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.ResourceBundle;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.kse.crypto.BC;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * Displays the properties of a supplied KeyStore.
 *
 */
public class DPkcs12Info extends JEscDialog {
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

	private CertificateFactory certificateFactory;

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
	public DPkcs12Info(JFrame parent, KeyStoreHistory history) throws CryptoException {
		super(parent, ModalityType.DOCUMENT_MODAL);
		this.history = history;
		this.currentState = history.getCurrentState();

		initCertificateFactory();

		initComponents();
	}

	private void initCertificateFactory() throws CryptoException {
		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new CryptoException(e);
		}
	}

	private void initComponents() {
		jbCopy = new JButton(res.getString("DProperties.jbCopy.text"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DProperties.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(res.getString("DProperties.jbCopy.tooltip"));
		jbCopy.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DPkcs12Info.this);
				copyPressed();
			} finally {
				CursorUtil.setCursorFree(DPkcs12Info.this);
			}
		});

		jbOK = new JButton(res.getString("DProperties.jbOK.text"));
		jbOK.addActionListener(evt -> okPressed());

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy);

		jpProperties = new JPanel(new BorderLayout());
		jpProperties.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtrProperties = new JTree(createPropertiesNodes());
		jtrProperties.setRowHeight(Math.max(18, jtrProperties.getRowHeight()));
		jtrProperties.setShowsRootHandles(true);
		jtrProperties.setRootVisible(false);
		jtrProperties.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		jtrProperties.setCellRenderer(new Pkcs12InfoTreeCellRend());

		TreeNode topNode = (TreeNode) jtrProperties.getModel().getRoot();
		expandTwoLevels(new TreePath(topNode));

		jspProperties = PlatformUtil.createScrollPane(jtrProperties, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspProperties.setPreferredSize(new Dimension(500, 400));
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

		SwingUtilities.invokeLater(() -> jbOK.requestFocus());
	}

	private DefaultMutableTreeNode createPropertiesNodes() {
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

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			char[] password = currentState.getPassword().toCharArray();
			keyStore.store(baos, password);
			parseP12(rootNode, baos.toByteArray(), password);
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
			e.printStackTrace();
		}

		return rootNode;
	}

	private void parseP12(DefaultMutableTreeNode parentNode, byte[] p12Data, char[] password)
			throws IOException {

		Pfx pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(p12Data));

		// add the mac code
		if (pfx.getMacData() != null) {
			createMacNode(pfx, parentNode);
		}

		ContentInfo authSafe = pfx.getAuthSafe();

		if (authSafe.getContentType().equals(data)) {

			ASN1OctetString octetString = ASN1OctetString.getInstance(pfx.getAuthSafe().getContent());
			ContentInfo[] safeContents = AuthenticatedSafe.getInstance(octetString.getOctets()).getContentInfo();

			for (ContentInfo safeContent : safeContents) {

				if (safeContent.getContentType().equals(data)) {

					DefaultMutableTreeNode dataNode = new DefaultMutableTreeNode("PKCS#7 Data");
					parentNode.add(dataNode);

					ASN1InputStream dIn = new ASN1InputStream(((ASN1OctetString) safeContent.getContent()).getOctets());
					ASN1Sequence seq = (ASN1Sequence) dIn.readObject();

					for (ASN1Encodable asn1Encodable : seq) {
						SafeBag b = SafeBag.getInstance(asn1Encodable);

						processBagNode(password, dataNode, b);
					}
				} else if (safeContent.getContentType().equals(encryptedData)) {

					DefaultMutableTreeNode dataNode = new DefaultMutableTreeNode("PKCS#7 Encrypted Data");
					parentNode.add(dataNode);

					// decrypt data
					EncryptedData d = EncryptedData.getInstance(safeContent.getContent());
					byte[] octets = decryptData(d.getEncryptionAlgorithm(), password,
							d.getContent().getOctets(), dataNode);
					ASN1Sequence seq = ASN1Sequence.getInstance(octets);

					for (ASN1Encodable asn1Encodable : seq) {
						SafeBag b = SafeBag.getInstance(asn1Encodable);

						processBagNode(password, dataNode, b);
					}
				} else if (safeContent.getContentType().equals(envelopedData)) {

					parentNode.add(new DefaultMutableTreeNode("Public Key encryption not supported"));
				} else {

					parentNode.add(new DefaultMutableTreeNode("Unknown OID: " + safeContent.getContentType().getId()));
				}
			}
		}
	}

	private void processBagNode(char[] password, DefaultMutableTreeNode dataNode, SafeBag safeBag) {
		DefaultMutableTreeNode bagNode;
		if (safeBag.getBagId().equals(certBag)) {
			bagNode = new DefaultMutableTreeNode("Certificate Bag");
			processCertBag(safeBag, bagNode);
		} else if (safeBag.getBagId().equals(pkcs8ShroudedKeyBag)) {
			bagNode = new DefaultMutableTreeNode("PKCS#8 Shrouded Key Bag");
			processPkcs8Bag(password, safeBag, bagNode);
		} else if (safeBag.getBagId().equals(keyBag)) {
			bagNode = new DefaultMutableTreeNode("Key Bag");
			processKeyBag(safeBag, bagNode);
		} else {
			bagNode = new DefaultMutableTreeNode("Unknown OID: " + safeBag.getBagId().getId());
		}

		dataNode.add(bagNode);
	}

	private void processKeyBag(SafeBag safeBag, DefaultMutableTreeNode parentNode) {
		PrivateKeyInfo kInfo = PrivateKeyInfo.getInstance(safeBag.getBagValue());
		ASN1ObjectIdentifier algorithm = kInfo.getPrivateKeyAlgorithm().getAlgorithm();

		// TODO

		parentNode.add(new DefaultMutableTreeNode(ObjectIdUtil.toString(safeBag.getBagId())));

		processBagAttributes(safeBag, parentNode);
	}

	private void processCertBag(SafeBag safeBag, DefaultMutableTreeNode parentNode) {

		CertBag cb = CertBag.getInstance(safeBag.getBagValue());
		if (!cb.getCertId().equals(x509Certificate)) {
			throw new RuntimeException("Unsupported certificate type: " + cb.getCertId());
		}

		X509Certificate cert;
		try {
			ByteArrayInputStream cIn = new ByteArrayInputStream(((ASN1OctetString) cb.getCertValue()).getOctets());
			cert = (X509Certificate) certificateFactory.generateCertificate(cIn);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		String subjectDN = cert.getSubjectX500Principal().getName("RFC2253");
		String issuerDN = cert.getIssuerX500Principal().getName("RFC2253");
		String sn = cert.getSerialNumber().toString(16);
		String notBefore = cert.getNotBefore().toString();
		String notAfter = cert.getNotAfter().toString();

		parentNode.add(new DefaultMutableTreeNode("SubjectDN: " + subjectDN));
		parentNode.add(new DefaultMutableTreeNode("IssuerDN: " + issuerDN));
		parentNode.add(new DefaultMutableTreeNode("SN: " + sn));
		parentNode.add(new DefaultMutableTreeNode("Validity: " + notBefore + " - " + notAfter));

		processBagAttributes(safeBag, parentNode);

	}

	private void processPkcs8Bag(char[] password, SafeBag safeBag, DefaultMutableTreeNode parentNode) {

		EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue());

		AlgorithmIdentifier encryptionAlgorithm = eIn.getEncryptionAlgorithm();

		addAlgorithmInfoNodes(parentNode, encryptionAlgorithm);

		// TODO do we actually need the key?
		//unwrapKey(eIn.getEncryptionAlgorithm(), eIn.getEncryptedData(), password, false);
		//decryptData(eIn.getEncryptionAlgorithm(), password, eIn.getEncryptedData(), parentNode);

		processBagAttributes(safeBag, parentNode);
	}

	private void addAlgorithmInfoNodes(DefaultMutableTreeNode parentNode, AlgorithmIdentifier encryptionAlgorithm) {

		ASN1ObjectIdentifier algOid = encryptionAlgorithm.getAlgorithm();

		String algorithm = ObjectIdUtil.toString(encryptionAlgorithm.getAlgorithm());
		parentNode.add(new DefaultMutableTreeNode("Algorithm: " + algorithm));

		if (algOid.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
			String iterationCount = getIterationCount(encryptionAlgorithm.getParameters());
			PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(encryptionAlgorithm.getParameters());

			parentNode.add(new DefaultMutableTreeNode("IV: " + new String(Hex.encode(pbeParams.getIV()))));
			parentNode.add(new DefaultMutableTreeNode("Iterations: " + iterationCount));
		} else if (algOid.equals(PKCSObjectIdentifiers.id_PBES2)) {
			// no parameters here...
		}
	}

	private String getIterationCount(ASN1Encodable parameters) {
		if (parameters == null) {
			return "";
		}

		ASN1Sequence seq = ASN1Sequence.getInstance(parameters);
		try {
			ASN1Integer iterations = ASN1Integer.getInstance(seq.getObjectAt(1));
			BigInteger itCount = iterations.getValue();
			return itCount.toString();
		} catch (Exception e) {
			return "";
		}
	}

//	private PrivateKey unwrapKey(AlgorithmIdentifier algId, byte[] data, char[] password, boolean wrongPKCS12Zero)
//			throws CryptoException {
//		String algorithm = algId.getAlgorithm().getId();
//		PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
//
//		PBEKeySpec pbeSpec = new PBEKeySpec(password);
//		PrivateKey out;
//
//		try {
//			SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
//			PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
//			SecretKey k = keyFact.generateSecret(pbeSpec);
//			Cipher cipher = Cipher.getInstance(algorithm);
//			cipher.init(Cipher.UNWRAP_MODE, k, defParams);
//
//			// assuming RSA key!
//			out = (PrivateKey) cipher.unwrap(data, "RSA", Cipher.PRIVATE_KEY);
//		} catch (Exception e) {
//			throw new CryptoException("exception unwrapping private key - " + e);
//		}
//
//		return out;
//	}

	private void processBagAttributes(SafeBag b, DefaultMutableTreeNode parentNode) {

		DefaultMutableTreeNode attributesNode = new DefaultMutableTreeNode("Bag Attributes");
		parentNode.add(attributesNode);

		if (b.getBagAttributes() != null) {
			Enumeration e = b.getBagAttributes().getObjects();

			while (e.hasMoreElements()) {
				ASN1Sequence sq = (ASN1Sequence) e.nextElement();
				ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq.getObjectAt(0);
				ASN1Set attrSet = (ASN1Set) sq.getObjectAt(1);
				ASN1Primitive attr = null;

				if (attrSet.size() > 0) {
					attr = (ASN1Primitive) attrSet.getObjectAt(0);
				}

				if (aOid.equals(pkcs_9_at_friendlyName)) {
					String alias = ((DERBMPString) attr).getString();
					attributesNode.add(new DefaultMutableTreeNode("friendlyName: " + alias));
				} else if (aOid.equals(pkcs_9_at_localKeyId)) {
					ASN1OctetString localId = (ASN1OctetString) attr;
					String localIdString = new String(Hex.encode(localId.getOctets()));
					attributesNode.add(new DefaultMutableTreeNode("localId: " + localIdString));
				} else {
					attributesNode.add(new DefaultMutableTreeNode(aOid.getId()));
				}
			}
		}
	}

	private boolean isMacValid(Pfx pfx, PKCS12MacCalculatorBuilderProvider macCalcProviderBuilder, char[] password)
			throws IOException {

		MacData macData = pfx.getMacData();

		PKCS12MacCalculatorBuilder pkcs12MacCalculatorBuilder = macCalcProviderBuilder.get(
				new AlgorithmIdentifier(macData.getMac().getAlgorithmId().getAlgorithm(),
				new PKCS12PBEParams(macData.getSalt(), macData.getIterationCount().intValue())));

		byte[] data = ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets();
		MacCalculator macCalculator;
		try {
			macCalculator = pkcs12MacCalculatorBuilder.build(password);

			OutputStream out = macCalculator.getOutputStream();
			out.write(data);
			out.close();
		} catch (Exception e) {
			throw new IOException(e);
		}

		AlgorithmIdentifier algId = macCalculator.getAlgorithmIdentifier();
		DigestInfo dInfo = new DigestInfo(pkcs12MacCalculatorBuilder.getDigestAlgorithmIdentifier(), macCalculator.getMac());
		PKCS12PBEParams params = PKCS12PBEParams.getInstance(algId.getParameters());

		MacData calculatedMacData = new MacData(dInfo, params.getIV(), params.getIterations().intValue());

		return Arrays.constantTimeAreEqual(calculatedMacData.getEncoded(), macData.getEncoded());
	}

	private void createMacNode(Pfx pfx, DefaultMutableTreeNode parentNode) {

		MacData mData = pfx.getMacData();
		DigestInfo dInfo = mData.getMac();
		ASN1ObjectIdentifier algId = dInfo.getAlgorithmId().getAlgorithm();
		byte[] salt = mData.getSalt();
		int itCount = mData.getIterationCount().intValue();

		DefaultMutableTreeNode macNode = new DefaultMutableTreeNode("MAC");
		parentNode.add(macNode);
		macNode.add(new DefaultMutableTreeNode("Algorithm: " + ObjectIdUtil.toString(algId)));
		macNode.add(new DefaultMutableTreeNode("Salt: " + new String(Hex.encode(salt))));
		macNode.add(new DefaultMutableTreeNode("Iterations: " + itCount));
	}

	private byte[] decryptData(AlgorithmIdentifier algId, char[] password, byte[] data, DefaultMutableTreeNode parentNode)
			throws IOException {

		ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
		parentNode.add(new DefaultMutableTreeNode("Algorithm: " + ObjectIdUtil.toString(algorithm)));

		if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
			PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
			PBEKeySpec pbeSpec = new PBEKeySpec(password);

			parentNode.add(new DefaultMutableTreeNode("IV: " + new String(Hex.encode(pbeParams.getIV()))));
			parentNode.add(new DefaultMutableTreeNode("Iterations: " + pbeParams.getIterations().intValue()));

			try {
				SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm.getId());
				PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
				SecretKey key = keyFact.generateSecret(pbeSpec);

				Cipher cipher = Cipher.getInstance(algorithm.getId());
				cipher.init(Cipher.DECRYPT_MODE, key, defParams);
				return cipher.doFinal(data);
			} catch (Exception e) {
				// TODO error handling
				throw new IOException("exception decrypting data", e);
			}
		} else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
			try {
				Cipher cipher = createPBES2Cipher(password, algId, parentNode);

				return cipher.doFinal(data);
			} catch (Exception e) {
				// TODO error handling
				throw new IOException("exception decrypting data", e);
			}
		}

		return new byte[0];
	}

	private Cipher createPBES2Cipher(char[] password, AlgorithmIdentifier algId, DefaultMutableTreeNode parentNode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, InvalidKeyException {

		PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(algId.getParameters());
		PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbes2Parameters.getKeyDerivationFunc().getParameters());
		AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(pbes2Parameters.getEncryptionScheme());

		ASN1ObjectIdentifier derivationFunctionOid = pbes2Parameters.getKeyDerivationFunc().getAlgorithm();
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(derivationFunctionOid.getId(), BC.getInstance());

		byte[] salt = pbkdf2Params.getSalt();
		int iterations = pbkdf2Params.getIterationCount().intValue();

		parentNode.add(new DefaultMutableTreeNode("Key Derivation Function: "
				+ ObjectIdUtil.toString(derivationFunctionOid)));
		parentNode.add(new DefaultMutableTreeNode("PBKDF2 Salt: " + new String(Hex.encode(salt))));
		parentNode.add(new DefaultMutableTreeNode("PBKDF2 Iterations: " + iterations));
		parentNode.add(new DefaultMutableTreeNode("Encryption Scheme: "
				+ ObjectIdUtil.toString(encScheme.getAlgorithm())));

		SecretKey key;
		if (pbkdf2Params.isDefaultPrf()) {
			key = keyFact.generateSecret(new PBEKeySpec(password, salt, iterations, algOidToKeySize(encScheme)));
		} else {
			key = keyFact.generateSecret(
					new PBKDF2KeySpec(password, salt, iterations, algOidToKeySize(encScheme), pbkdf2Params.getPrf()));
		}

		Cipher cipher = Cipher.getInstance(encScheme.getAlgorithm().getId(), BC.getInstance());
		ASN1Encodable encParams = pbes2Parameters.getEncryptionScheme().getParameters();

		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));

		return cipher;
	}

	private int algOidToKeySize(AlgorithmIdentifier algOid) {

		String id = algOid.getAlgorithm().getId();
		if (PKCSObjectIdentifiers.des_EDE3_CBC.getId().equals(id)) {
			return 192;
		} else if (id_aes128_CBC.getId().equals(id)) {
			return 128;
		} else if (id_aes192_CBC.getId().equals(id)) {
			return 192;
		} else if (id_aes256_CBC.getId().equals(id)) {
			return 256;
		}
		throw new IllegalStateException("Unexpected algorithm: " + algOid.getAlgorithm().getId());
	}

	private Password getEntryPassword(String alias) {
		return currentState.getEntryPassword(alias);
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
		StringBuilder strBuff = new StringBuilder();

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
