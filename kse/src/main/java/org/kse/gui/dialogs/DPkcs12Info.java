/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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

import static java.text.MessageFormat.format;
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
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.secretBag;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.signedData;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.x509Certificate;
import static org.bouncycastle.util.encoders.Base64.decode;
import static org.kse.KSE.BC;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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
import javax.swing.UnsupportedLookAndFeelException;
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
import org.bouncycastle.asn1.ASN1TaggedObject;
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
import org.bouncycastle.util.encoders.Hex;
import org.kse.crypto.CryptoException;
import org.kse.gui.CursorUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;
import org.kse.utilities.oid.ObjectIdUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the properties of a supplied KeyStore.
 */
public class DPkcs12Info extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String NEWLINE = "\n";
    private static final IndentSequence INDENT = new IndentSequence(IndentChar.SPACE, 4);

    private JButton jbOpen;
    private JTree jtrP12Content;

    private CertificateFactory certificateFactory;
    private final byte[] p12Data;
    private final Password password;
    private final File file;
    private boolean cancelled;

    /**
     * Creates a new DProperties dialog.
     *
     * @param parent  Parent frame
     * @throws CryptoException If a problem occurred while getting the properties
     */
    public DPkcs12Info(JFrame parent, byte[] p12Data, Password password, File file) throws CryptoException {
        super(parent, ModalityType.DOCUMENT_MODAL);
        this.p12Data = p12Data;
        this.password = password;
        this.file = file;

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

    private void initComponents() throws CryptoException {
        JButton jbCopy = new JButton(res.getString("DPkcs12Info.jbCopy.text"));
        PlatformUtil.setMnemonic(jbCopy, res.getString("DPkcs12Info.jbCopy.mnemonic").charAt(0));
        jbCopy.setToolTipText(res.getString("DPkcs12Info.jbCopy.tooltip"));
        jbCopy.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DPkcs12Info.this);
                copyPressed();
            } finally {
                CursorUtil.setCursorFree(DPkcs12Info.this);
            }
        });

        jbOpen = new JButton(res.getString("DPkcs12Info.jbOpen.text"));
        jbOpen.addActionListener(evt -> okPressed());

        JButton jbCancel = new JButton(res.getString("DPkcs12Info.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());

        JPanel jpP12Content = new JPanel(new BorderLayout());
        jpP12Content.setBorder(new EmptyBorder(0, 0, 0, 0));

        jtrP12Content = new JTree(createPropertiesNodes());
        jtrP12Content.setRowHeight(Math.max(18, jtrP12Content.getRowHeight()));
        jtrP12Content.setShowsRootHandles(true);
        jtrP12Content.setRootVisible(false);
        jtrP12Content.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        jtrP12Content.setCellRenderer(new Pkcs12InfoTreeCellRend());

        TreeNode topNode = (TreeNode) jtrP12Content.getModel().getRoot();
        expandTwoLevels(new TreePath(topNode));

        JScrollPane jspP12Content =
                PlatformUtil.createScrollPane(jtrP12Content, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                              ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        jspP12Content.setPreferredSize(new Dimension(500, 400));
        jpP12Content.add(jspP12Content, BorderLayout.CENTER);

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets panel, fill", "", ""));
        pane.add(jpP12Content, "span, grow, push, wrap unrel");
        pane.add(jbCopy, "spanx, split 3");
        pane.add(jbCancel, "tag cancel");
        pane.add(jbOpen, "tag ok");

        setTitle(format(res.getString("DPkcs12Info.Title"), file.getName()));
        setResizable(true);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOpen);

        pack();

        SwingUtilities.invokeLater(() -> jbOpen.requestFocus());
    }

    private DefaultMutableTreeNode createPropertiesNodes() throws CryptoException {
        String root = format(res.getString("DPkcs12Info.content.Root"), file.getName());

        DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode(root);
        rootNode.add(addNode(rootNode, "DPkcs12Info.content.File", file.getPath()));
        rootNode.add(addNode(rootNode, "DPkcs12Info.content.Type", "PKCS#12"));

        try {
            parseP12(rootNode, p12Data, password.toCharArray());
        } catch (IOException e) {
            throw new CryptoException(e);
        }

        return rootNode;
    }

    private void parseP12(DefaultMutableTreeNode parentNode, byte[] p12Data, char[] password) throws IOException {
        Pfx pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(p12Data));

        if (pfx.getMacData() != null) {
            createMacNode(pfx, parentNode);
        }

        ContentInfo authSafe = pfx.getAuthSafe();

        if (authSafe.getContentType().equals(data)) {

            ASN1OctetString octetString = ASN1OctetString.getInstance(pfx.getAuthSafe().getContent());
            ContentInfo[] safeContents = AuthenticatedSafe.getInstance(octetString.getOctets()).getContentInfo();

            for (ContentInfo safeContent : safeContents) {

                if (safeContent.getContentType().equals(data)) {

                    DefaultMutableTreeNode dataNode = addNode(parentNode,"DPkcs12Info.content.Pkcs7Data");

                    ASN1InputStream dIn = new ASN1InputStream(((ASN1OctetString) safeContent.getContent()).getOctets());
                    ASN1Sequence seq = (ASN1Sequence) dIn.readObject();

                    for (ASN1Encodable asn1Encodable : seq) {
                        SafeBag b = SafeBag.getInstance(asn1Encodable);

                        processBagNode(password, dataNode, b);
                    }
                } else if (safeContent.getContentType().equals(encryptedData)) {

                    DefaultMutableTreeNode dataNode = addNode(parentNode,"DPkcs12Info.content.Pkcs7EncrData");

                    // decrypt data
                    EncryptedData d = EncryptedData.getInstance(safeContent.getContent());
                    byte[] octets =
                            decryptData(d.getEncryptionAlgorithm(), password, d.getContent().getOctets(), dataNode);

                    if (octets.length == 0) {
                        continue;
                    }

                    // process safe bags
                    ASN1Sequence seq = ASN1Sequence.getInstance(octets);
                    for (ASN1Encodable asn1Encodable : seq) {
                        SafeBag b = SafeBag.getInstance(asn1Encodable);

                        processBagNode(password, dataNode, b);
                    }
                } else if (safeContent.getContentType().equals(envelopedData)) {
                    addNode(parentNode, "DPkcs12Info.content.Pkcs7EnvelopedData");
                } else if (safeContent.getContentType().equals(signedData)) {
                    addNode(parentNode, "DPkcs12Info.content.Pkcs7SignedData");
                } else {
                    addNode(parentNode, "DPkcs12Info.content.UnknownOID", safeContent.getContentType().getId());
                }
            }
        }
    }

    private void processBagNode(char[] password, DefaultMutableTreeNode dataNode, SafeBag safeBag) {
        if (safeBag.getBagId().equals(certBag)) {
            processCertBag(safeBag, addNode(dataNode, "DPkcs12Info.content.CertificateBag"));
        } else if (safeBag.getBagId().equals(pkcs8ShroudedKeyBag)) {
            processShroudedPkcs8Bag(safeBag, addNode(dataNode, "DPkcs12Info.content.Pkcs8ShroudedKeyBag"));
        } else if (safeBag.getBagId().equals(keyBag)) {
            processPkcs8Bag(safeBag, addNode(dataNode, "DPkcs12Info.content.KeyBag"));
        } else if (safeBag.getBagId().equals(secretBag)) {
            processSecretBag(safeBag, addNode(dataNode, "DPkcs12Info.content.SecretBag"));
        } else {
            addNode(dataNode,"DPkcs12Info.content.UnsupportedBagType", ObjectIdUtil.toString(safeBag.getBagId()));
        }
    }

    private void processPkcs8Bag(SafeBag safeBag, DefaultMutableTreeNode parentNode) {
        PrivateKeyInfo kInfo = PrivateKeyInfo.getInstance(safeBag.getBagValue());
        ASN1ObjectIdentifier algorithm = kInfo.getPrivateKeyAlgorithm().getAlgorithm();

        parentNode.add(new DefaultMutableTreeNode(ObjectIdUtil.toString(safeBag.getBagId())));
        parentNode.add(new DefaultMutableTreeNode(ObjectIdUtil.toString(algorithm)));

        processBagAttributes(safeBag, parentNode);
    }

    private void processCertBag(SafeBag safeBag, DefaultMutableTreeNode parentNode) {

        CertBag cb = CertBag.getInstance(safeBag.getBagValue());
        if (!cb.getCertId().equals(x509Certificate)) {
            addNode(parentNode, "DPkcs12Info.content.UnsupportedCertificateType", cb.getCertId());
            processBagAttributes(safeBag, parentNode);
            return;
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

        addNode(parentNode, "DPkcs12Info.content.Subject", subjectDN);
        addNode(parentNode, "DPkcs12Info.content.Issuer", issuerDN);
        addNode(parentNode, "DPkcs12Info.content.SerialNumber", sn);
        addNode(parentNode, "DPkcs12Info.content.Validity", notBefore, notAfter);

        processBagAttributes(safeBag, parentNode);
    }

    private void processShroudedPkcs8Bag(SafeBag safeBag, DefaultMutableTreeNode parentNode) {
        EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue());
        AlgorithmIdentifier encryptionAlgorithm = eIn.getEncryptionAlgorithm();

        addAlgorithmInfoNodes(parentNode, encryptionAlgorithm);

        processBagAttributes(safeBag, parentNode);
    }

    private void processSecretBag(SafeBag safeBag, DefaultMutableTreeNode parentNode) {
        try {
            ASN1Sequence secretBag = ASN1Sequence.getInstance(safeBag.getBagValue());
            ASN1ObjectIdentifier bagType = (ASN1ObjectIdentifier) secretBag.getObjectAt(0);
            ASN1TaggedObject taggedValue = ASN1TaggedObject.getInstance(secretBag.getObjectAt(1));
            byte[] bagValue = ASN1OctetString.getInstance(taggedValue.getExplicitBaseObject().getEncoded()).getOctets();

            // this is how Java stores symmetric keys in PKCS#12
            if (bagType.equals(pkcs8ShroudedKeyBag)) {
                EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(bagValue);
                AlgorithmIdentifier encryptionAlgorithm = eIn.getEncryptionAlgorithm();

                addAlgorithmInfoNodes(parentNode, encryptionAlgorithm);
            } else {
                addNode(parentNode, "DPkcs12Info.content.UnsupportedBagType", ObjectIdUtil.toString(bagType));
            }
        } catch (Exception e) {
            addNode(parentNode, "DPkcs12Info.content.DecodingError", e.getMessage());
        }

        processBagAttributes(safeBag, parentNode);
    }

    private void addAlgorithmInfoNodes(DefaultMutableTreeNode parentNode, AlgorithmIdentifier encryptionAlgorithm) {

        ASN1ObjectIdentifier algOid = encryptionAlgorithm.getAlgorithm();

        String algorithm = ObjectIdUtil.toString(encryptionAlgorithm.getAlgorithm());
        addNode(parentNode, "DPkcs12Info.content.Algorithm", algorithm);

        if (algOid.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
            String iterationCount = getIterationCount(encryptionAlgorithm.getParameters());
            PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(encryptionAlgorithm.getParameters());

            addNode(parentNode, "DPkcs12Info.content.IV", new String(Hex.encode(pbeParams.getIV())));
            addNode(parentNode, "DPkcs12Info.content.Iterations", iterationCount);
        } else if (algOid.equals(PKCSObjectIdentifiers.id_PBES2)) {
            PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());
            PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbes2Parameters.getKeyDerivationFunc().getParameters());
            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(pbes2Parameters.getEncryptionScheme());

            ASN1ObjectIdentifier derivationFunctionOid = pbes2Parameters.getKeyDerivationFunc().getAlgorithm();

            byte[] salt = pbkdf2Params.getSalt();
            int iterations = pbkdf2Params.getIterationCount().intValue();

            addNode(parentNode, "DPkcs12Info.content.KeyDerivationFunction",
                                                             ObjectIdUtil.toString(derivationFunctionOid));
            addNode(parentNode, "DPkcs12Info.content.Pbkdf2Salt", salt.length);
            addNode(parentNode, "DPkcs12Info.content.Pbkdf2Iterations", iterations);
            addNode(parentNode, "DPkcs12Info.content.EncryptionScheme",
                                                             ObjectIdUtil.toString(encScheme.getAlgorithm()));
        }
    }

    private DefaultMutableTreeNode addNode(DefaultMutableTreeNode parentNode, String resKey) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(res.getString(resKey));
        parentNode.add(node);
        return node;
    }

    private DefaultMutableTreeNode addNode(DefaultMutableTreeNode parentNode, String resKey, Object... args) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(format(res.getString(resKey), args));
        parentNode.add(node);
        return node;
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

    private void processBagAttributes(SafeBag b, DefaultMutableTreeNode parentNode) {

        DefaultMutableTreeNode attributesNode = addNode(parentNode, "DPkcs12Info.content.BagAttributes");

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
                    addNode(attributesNode, "DPkcs12Info.content.FriendlyName", alias);
                } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                    ASN1OctetString localId = (ASN1OctetString) attr;
                    String localIdString = new String(Hex.encode(localId.getOctets()));
                    addNode(attributesNode, "DPkcs12Info.content.LocalId", localIdString);
                } else {
                    attributesNode.add(new DefaultMutableTreeNode(aOid.getId()));
                }
            }
        }
    }

    private void createMacNode(Pfx pfx, DefaultMutableTreeNode parentNode) {
        MacData mData = pfx.getMacData();
        DigestInfo dInfo = mData.getMac();
        ASN1ObjectIdentifier algId = dInfo.getAlgorithmId().getAlgorithm();
        byte[] salt = mData.getSalt();
        int itCount = mData.getIterationCount().intValue();

        DefaultMutableTreeNode macNode = addNode(parentNode, "DPkcs12Info.content.MAC");

        addNode(macNode, "DPkcs12Info.content.Algorithm", ObjectIdUtil.toString(algId));
        addNode(macNode, "DPkcs12Info.content.Salt",+ salt.length);
        addNode(macNode, "DPkcs12Info.content.Iterations", itCount);
    }

    private byte[] decryptData(AlgorithmIdentifier algId, char[] password, byte[] data,
                               DefaultMutableTreeNode parentNode) {

        ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
        addNode(parentNode, "DPkcs12Info.content.Algorithm", ObjectIdUtil.toString(algorithm));

        if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
            PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
            PBEKeySpec pbeSpec = new PBEKeySpec(password);

            addNode(parentNode, "DPkcs12Info.content.IV",pbeParams.getIV().length);
            addNode(parentNode, "DPkcs12Info.content.Iterations", pbeParams.getIterations().intValue());

            try {
                var keyFact = SecretKeyFactory.getInstance(algorithm.getId());
                var defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
                SecretKey key = keyFact.generateSecret(pbeSpec);

                Cipher cipher = Cipher.getInstance(algorithm.getId());
                cipher.init(Cipher.DECRYPT_MODE, key, defParams);
                return cipher.doFinal(data);
            } catch (Exception e) {
                addNode(parentNode, "DPkcs12Info.content.DecryptionFailed", e.getMessage());
            }
        } else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
            try {
                Cipher cipher = createPBES2Cipher(password, algId, parentNode);
                return cipher.doFinal(data);
            } catch (Exception e) {
                addNode(parentNode, "DPkcs12Info.content.DecryptionFailed", e.getMessage());
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
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(derivationFunctionOid.getId(), BC);

        byte[] salt = pbkdf2Params.getSalt();
        int iterations = pbkdf2Params.getIterationCount().intValue();

        addNode(parentNode, "DPkcs12Info.content.KeyDerivationFunction", ObjectIdUtil.toString(derivationFunctionOid));
        addNode(parentNode, "DPkcs12Info.content.Salt", + salt.length);
        addNode(parentNode, "DPkcs12Info.content.Iterations", + iterations);
        addNode(parentNode, "DPkcs12Info.content.EncryptionScheme", ObjectIdUtil.toString(encScheme.getAlgorithm()));

        SecretKey key;
        if (pbkdf2Params.isDefaultPrf()) {
            key = keyFact.generateSecret(new PBEKeySpec(password, salt, iterations, algOidToKeySize(encScheme)));
        } else {
            key = keyFact.generateSecret(
                    new PBKDF2KeySpec(password, salt, iterations, algOidToKeySize(encScheme), pbkdf2Params.getPrf()));
        }

        Cipher cipher = Cipher.getInstance(encScheme.getAlgorithm().getId(), BC);
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

    private void copyPressed() {
        String properties = getNodeContents((TreeNode) jtrP12Content.getModel().getRoot(), 0);

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
            for (Enumeration<?> enumChildren = node.children(); enumChildren.hasMoreElements(); ) {
                TreeNode subNode = (TreeNode) enumChildren.nextElement();
                TreePath path = treePath.pathByAddingChild(subNode);
                expandTwoLevels(path);
            }
        }

        jtrP12Content.expandPath(treePath);
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

    public boolean isCancelled() {
        return cancelled;
    }

    private void okPressed() {
        closeDialog();
    }

    private void cancelPressed() {
        cancelled = true;
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick testing
    public static void main(String[] args) throws CryptoException, UnsupportedLookAndFeelException {
        DialogViewer.prepare();
        byte[] p12Data = decode("MIIKbQIBAzCCChcGCSqGSIb3DQEHAaCCCggEggoEMIIKADCCAjcGCSqGSIb3DQEHAaCCAigEggIk\n" +
                                "MIICIDCCAQEGCyqGSIb3DQEMCgECoIGtMIGqMGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDAr\n" +
                                "BBQgr2RYFl2B6XezuzZclsH8406SSwICJxACASAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoE\n" +
                                "ECtN5bUbUZ3c32wJqBrlIKsEQP8KBbXPaqR1mcx5ojKRHRBLcedMr84IkZ7Y6QgnW4LjcBF6yq8E\n" +
                                "AVCDpN0L4BaUM8PawSGWiNX+PBUlFLCDTcgxQjAdBgkqhkiG9w0BCRQxEB4OAGUAZAAyADUANQAx\n" +
                                "ADkwIQYJKoZIhvcNAQkVMRQEElRpbWUgMTczNTg0MzQ2ODg2NjCCARcGCyqGSIb3DQEMCgEFoIHD\n" +
                                "MIHABgsqhkiG9w0BDAoBAqCBsASBrTCBqjBmBgkqhkiG9w0BBQ0wWTA4BgkqhkiG9w0BBQwwKwQU\n" +
                                "HD04sgYqo3j02UtC/cfL/g7iHLQCAicQAgEgMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAM\n" +
                                "PZ4KFREEabcjFRFKCHKXBED1wiiczl1zCjR0KoBcCF9aRZ+UkyZmtg1Z9pDwRXTvM3QstgFtLKLW\n" +
                                "YBIEOSZP3x0mNZr54fR8jYMPjCWNFV2lMUIwHQYJKoZIhvcNAQkUMRAeDgBhAGUAcwAgADIANQA2\n" +
                                "MCEGCSqGSIb3DQEJFTEUBBJUaW1lIDE3Mzc4OTk0MDg2NDYwggfBBgkqhkiG9w0BBwagggeyMIIH\n" +
                                "rgIBADCCB6cGCSqGSIb3DQEHATBmBgkqhkiG9w0BBQ0wWTA4BgkqhkiG9w0BBQwwKwQUsNyHe7Pi\n" +
                                "sqKVjcfPPFqKvn31rqoCAicQAgEgMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAlMRDu41j+\n" +
                                "Rx1y+XnodmSegIIHMIzi23LXsUBRwDzrFWwKAxC3R03KMviVqWXdmICq348oC2QPBF/RAz0F54eI\n" +
                                "XNICmU9HISrtH233dI0nbNTw0RmFdIOvaA0cgjkd+Kkrm8uolk3akt8119+SAvUl5A9hqIojHSWO\n" +
                                "ZVgenbTPLUKdGPLiJovp7U1y6OX0E+9sMsHOK5CtTPsf61V/Y/ic02mCwJ+059aDEZrHPsqEUJOI\n" +
                                "LBO3dVFgkIf6bQvfOIUSOY5YKABqFQf+zYFLArt1ZC5ef7AeWwYGlanGM6bvZNJOiPV33ovmF1qI\n" +
                                "3zayghVS+RziZ5VNboxBmUTAcmf5XAxgABEtviwa3R9FCD51QOlWRZhgkiWAdnqGVVC0iLSgtSLo\n" +
                                "M8KZmqfSYV7zBMoM5GmrXHvxDAklqqh+gGO5wYWinnJeVyv384meX8vpH3dW5TMv5aBdB642kUns\n" +
                                "GXEW0Y/x5J7yF/U5CLMiSobdNmtjLnNP2GqdfO9zMlKXAhSLx84NvQMyZVgVo3ioLzX0pDZPiGmp\n" +
                                "DZQtylcmqTk84mL1wxBdjIPwQ36V5OUnJTJ9jWc9ueEDcaYrdsNarnZG52J6VJ5h7nsUeja/Nb5x\n" +
                                "9Fs8YIPVkf+qJIY1XXZK6VUiKSV2chsdDETsimA+nBRtlZlmxyTH080z5O/G25l5psPBdPkU1v5M\n" +
                                "m2Z2fSCBi9Kivqf3TYXR6HL7OQwDssvSAIlzqA8ssZj3wTWI71w8MJa5mRgZXN7y8b96OeOnvD1w\n" +
                                "KU4133Ek2h032ryCHQccwYtDTg7NliPn1Wg0JqaUrUO07T4XUHmpFo0gUr/QwaSTHBaM6SaCAQG0\n" +
                                "FdvYqB0morkMb45jgRL3WsW7dYvG/4kFT3qafD+tX5gNRGsf4ih2a6POtDyBAzTDzNOtwe8ilj3r\n" +
                                "kkO3mRt4I8BduJfgR978bkKFxu2dHJ09NVaBc5BfNZ6CvxPh4ff/1tP/sldDi/x8wFyucB5nGnwA\n" +
                                "cIEz4tIn/PujZfEBhFD/rTOv23+e93bgfHYZMmVJSSaupGwEWhB4k3Teuwik+Prn+vQ780xl+RZw\n" +
                                "zmQycjXNoqxCEXbMZ6QZv5HJYH+aBTns/eJRjQFyeBN30kzj61qfv3G+QBV4Gm9HrPIBGUuLy7v3\n" +
                                "z5IJ4QhKt9BAtSwL+L8amKBWWhMb7asdJ0ZBPm/nZryCIqi+j1E9SCBXXjPvZZh5aSh0mvU/Z9a9\n" +
                                "9jmVTNFKrympdRfYKVIfJQhJs/PTLgmtiQVyG60zttnuVL9kf3vZEEnW8m6biyx/nUBWW2y6eKEn\n" +
                                "aEsbETwau0CfWsrO//gyvYLVhrLJ/S3zbAamgdQ8ir3ru8NEX/f8tj5js9HeJNUxbhWmfPluCo4Q\n" +
                                "FvOINq3M5S9VYh8sofYKVp7DdVGqa4adU28zt25ENc3jqZtu4os4XfqYJSEX3vNCwW/CfaLNLkrA\n" +
                                "MRQCWU7sWpkvgzvB2dWx+1IGaySfMxT9CvxH98S37nNLsITM7pwx1uwMHMVTxUPvoLuNnpLxX6Kv\n" +
                                "RsWth/QE7UQABWoNdN6REaerWGkwy3CaI1UXLP8iJ7U9Sd1mrl9qxspyhXBIUXnWEz+wssXI5KOO\n" +
                                "Bna3WA9v2Yz2SYSeFZCo/m4vUUR6e3YB6sQbnNQlps3sRxzzixqzLp15XVZMVhZ2/3aRvf6p0OqA\n" +
                                "uP7IsTI+jbW6X9NBT3+qEnXY7gkYWMJpzLuNl0UXHWEtkHe9uWzzQfgfITiXHHTNaitJyMndvsgU\n" +
                                "efZiWK5h7ttMScMBTHwuP+srti9N1bHsocdrbEvwPsm331Spyxwn96iKuhDWTjr7zIrT/hfx7zyu\n" +
                                "0rDsyx0Luii3F2hLIOOEGJtvHkkL4Si0vPXPV10Cq8cOAp93x+sAdvECEZs8nNSEnqZJqu7L17Ry\n" +
                                "haAesa7SoDLEtqrra9fYJ+S9n0A9X5J0qMGiVBY3+KgcCPN84MC3groqUK3irGqeneD2lVbNofaa\n" +
                                "eOLUR2xpFvo3dj5blRoG/6yDBK+Q5zkdm6P6AlbV4v8wkPqOM+DIzAauz6DChZGsaZtGJdzSMssR\n" +
                                "ZHuOMJrCo4sj03slOMGfaaXNiuD1pYZPck4zV4EYTtpMgVclK33EOt8FnwVN27zkHctO8O9bL06R\n" +
                                "kHP0fApSrvshRB0sZbS3itT7+Buy0WmA80tAK+8u12i3AYjs1MeLGOIqDBRb+SyI+TASSiVnIQj0\n" +
                                "S1ygAT6ftgcKKUIysqC6k3Ao71QtWT6v70ZNKCwwyS+gfwmZa/s3hJJXqsvlxtHunS3RmwxwXEkC\n" +
                                "rPClZ768+0XBuusyy2jXKEfLdT5SgLJ1i0zMwcn9sk4uFA53W7E3+vlKaLYhojwxPi64mHQlcUBI\n" +
                                "jXc6JRNSubqtDafwEUPFp02go4Xd3Bap6+echhN9l0cQdfUiVGCLg0wI1KCPs1jBcjJ9BEu2gI1N\n" +
                                "Oo/dgo1Yu3tHJTTJCr/eMwVyagcUjF4l1B/uB80wTTAxMA0GCWCGSAFlAwQCAQUABCAcZbGrc0Y2\n" +
                                "uWhsEEsXVOpo7x5g1vlOcIthi6RL86q1gAQUUddLM9khLX1sxU3HbTuYVH7SPpcCAicQ");

        DialogViewer.run(new DPkcs12Info(new JFrame(), p12Data, new Password("123456".toCharArray()),
                                         new File("test.p12")));
    }
}
