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
package net.sf.keystore_explorer.gui.dialogs;

import static net.sf.keystore_explorer.crypto.x509.X509CertificateVersion.VERSION1;
import static net.sf.keystore_explorer.crypto.x509.X509CertificateVersion.VERSION3;
import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
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
import java.security.Security;
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
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.signing.SignatureType;
import net.sf.keystore_explorer.crypto.x509.X500NameUtils;
import net.sf.keystore_explorer.crypto.x509.X509CertificateGenerator;
import net.sf.keystore_explorer.crypto.x509.X509ExtensionSet;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.crypto.JDistinguishedName;
import net.sf.keystore_explorer.gui.datetime.JDateTime;
import net.sf.keystore_explorer.gui.dialogs.extensions.DAddExtensions;
import net.sf.keystore_explorer.gui.error.DError;

/**
 * Dialog used to generate a certificate based on a supplied key pair and
 * signature algorithm for inclusion in a KeyStore.
 *
 */
public class DGenerateKeyPairCert extends JEscDialog {
    private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlVersion;
    private JRadioButton jrbVersion1;
    private JRadioButton jrbVersion3;
    private JLabel jlSigAlg;
    private JComboBox jcbSignatureAlgorithm;
    private JLabel jlValidityStart;
    private JDateTime jdtValidityStart;
    private JLabel jlValidityEnd;
    private JDateTime jdtValidityEnd;
    private JLabel jlSerialNumber;
    private JTextField jtfSerialNumber;
    private JLabel jlName;
    private JDistinguishedName jdnName;
    private JButton jbAddExtensions;
    private JPanel jpOptions;
    private JPanel jpButtons;
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
     *            The signing key pair (issuer CA)
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
        GridBagConstraints gbcLbl = new GridBagConstraints();
        gbcLbl.gridx = 0;
        gbcLbl.gridwidth = 3;
        gbcLbl.gridheight = 1;
        gbcLbl.insets = new Insets(5, 5, 5, 5);
        gbcLbl.anchor = GridBagConstraints.EAST;

        GridBagConstraints gbcEdCtrl = new GridBagConstraints();
        gbcEdCtrl.gridx = 3;
        gbcEdCtrl.gridwidth = 3;
        gbcEdCtrl.gridheight = 1;
        gbcEdCtrl.insets = new Insets(5, 5, 5, 5);
        gbcEdCtrl.anchor = GridBagConstraints.WEST;

        jlVersion = new JLabel(res.getString("DGenerateKeyPairCert.jlVersion.text"));
        GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
        gbc_jlVersion.gridy = 0;

        jrbVersion1 = new JRadioButton(res.getString("DGenerateKeyPairCert.jrbVersion1.text"));
        jrbVersion1.setToolTipText(res.getString("DGenerateKeyPairCert.jrbVersion1.tooltip"));
        GridBagConstraints gbc_jrbVersion1 = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jrbVersion1.gridy = 0;
        gbc_jrbVersion1.gridwidth = 1;

        jrbVersion3 = new JRadioButton(res.getString("DGenerateKeyPairCert.jrbVersion3.text"));
        jrbVersion3.setToolTipText(res.getString("DGenerateKeyPairCert.jrbVersion3.tooltip"));
        GridBagConstraints gbc_jrbVersion3 = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jrbVersion3.gridx = 4;
        gbc_jrbVersion3.gridy = 0;
        gbc_jrbVersion3.gridwidth = 1;

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbVersion1);
        buttonGroup.add(jrbVersion3);

        jlSigAlg = new JLabel(res.getString("DGenerateKeyPairCert.jlSigAlg.text"));
        GridBagConstraints gbc_jlSigAlg = (GridBagConstraints) gbcLbl.clone();
        gbc_jlSigAlg.gridy = 1;

        jcbSignatureAlgorithm = new JComboBox();
        jcbSignatureAlgorithm.setToolTipText(res.getString("DGenerateKeyPairCert.jcbSignatureAlgorithm.tooltip"));
        jcbSignatureAlgorithm.setMaximumRowCount(10);
        GridBagConstraints gbc_jcbSigAlg = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jcbSigAlg.gridy = 1;

        // populate signature algorithm selector
        if (issuerPrivateKey != null) {
            KeyPairType issuerKeyPairType = KeyPairType.resolveJce(issuerPrivateKey.getAlgorithm());
            DialogHelper.populateSigAlgs(issuerKeyPairType, issuerPrivateKey, provider, jcbSignatureAlgorithm);
        } else {
            // self-signed
            DialogHelper.populateSigAlgs(keyPairType, keyPair.getPrivate(), provider, jcbSignatureAlgorithm);
        }

        Date now = new Date();

        jlValidityStart = new JLabel(res.getString("DGenerateKeyPairCert.jlValidityStart.text"));
        GridBagConstraints gbc_jlValidityStart = (GridBagConstraints) gbcLbl.clone();
        gbc_jlValidityStart.gridy = 2;

        jdtValidityStart = new JDateTime(res.getString("DGenerateKeyPairCert.jdtValidityStart.title"));
        jdtValidityStart.setDateTime(now);
        jdtValidityStart.setToolTipText(res.getString("DGenerateKeyPairCert.jdtValidityStart.tooltip"));
        GridBagConstraints gbc_jvpValidityStart = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jvpValidityStart.gridy = 2;

        jlValidityEnd = new JLabel(res.getString("DGenerateKeyPairCert.jlValidityEnd.text"));
        GridBagConstraints gbc_jlValidityEnd = (GridBagConstraints) gbcLbl.clone();
        gbc_jlValidityEnd.gridy = 3;

        jdtValidityEnd = new JDateTime(res.getString("DGenerateKeyPairCert.jdtValidityEnd.title"));
        jdtValidityEnd.setDateTime(new Date(now.getTime() + TimeUnit.DAYS.toMillis(365)));
        jdtValidityEnd.setToolTipText(res.getString("DGenerateKeyPairCert.jdtValidityEnd.tooltip"));
        GridBagConstraints gbc_jvpValidityEnd = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jvpValidityEnd.gridy = 3;

        jlSerialNumber = new JLabel(res.getString("DGenerateKeyPairCert.jlSerialNumber.text"));
        GridBagConstraints gbc_jlSerialNumber = (GridBagConstraints) gbcLbl.clone();
        gbc_jlSerialNumber.gridy = 4;

        jtfSerialNumber = new JTextField("" + generateSerialNumber(), 20);
        jtfSerialNumber.setToolTipText(res.getString("DGenerateKeyPairCert.jtfSerialNumber.tooltip"));
        GridBagConstraints gbc_jtfSerialNumber = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfSerialNumber.gridy = 4;

        jlName = new JLabel(res.getString("DGenerateKeyPairCert.jlName.text"));
        GridBagConstraints gbc_jlName = (GridBagConstraints) gbcLbl.clone();
        gbc_jlName.gridy = 5;

        jdnName = new JDistinguishedName("Name", 30, true);
        jdnName.setToolTipText(res.getString("DGenerateKeyPairCert.jdnName.tooltip"));
        GridBagConstraints gbc_jdnName = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jdnName.gridy = 5;

        jbAddExtensions = new JButton(res.getString("DGenerateKeyPairCert.jbAddExtensions.text"));
        jbAddExtensions.setMnemonic(res.getString("DGenerateKeyPairCert.jbAddExtensions.mnemonic").charAt(0));
        jbAddExtensions.setToolTipText(res.getString("DGenerateKeyPairCert.jbAddExtensions.tooltip"));
        GridBagConstraints gbc_jbAddExtensions = (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jbAddExtensions.gridy = 6;
        gbc_jbAddExtensions.gridwidth = 7;
        gbc_jbAddExtensions.anchor = GridBagConstraints.EAST;

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

        jrbVersion3.setSelected(true);

        jpOptions = new JPanel(new GridBagLayout());
        jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

        jpOptions.add(jlVersion, gbc_jlVersion);
        jpOptions.add(jrbVersion1, gbc_jrbVersion1);
        jpOptions.add(jrbVersion3, gbc_jrbVersion3);
        jpOptions.add(jlSigAlg, gbc_jlSigAlg);
        jpOptions.add(jcbSignatureAlgorithm, gbc_jcbSigAlg);
        jpOptions.add(jlValidityStart, gbc_jlValidityStart);
        jpOptions.add(jdtValidityStart, gbc_jvpValidityStart);
        jpOptions.add(jlValidityEnd, gbc_jlValidityEnd);
        jpOptions.add(jdtValidityEnd, gbc_jvpValidityEnd);
        jpOptions.add(jlSerialNumber, gbc_jlSerialNumber);
        jpOptions.add(jtfSerialNumber, gbc_jtfSerialNumber);
        jpOptions.add(jlName, gbc_jlName);
        jpOptions.add(jdnName, gbc_jdnName);
        jpOptions.add(jbAddExtensions, gbc_jbAddExtensions);

        jbOK = new JButton(res.getString("DGenerateKeyPairCert.jbOK.text"));
        jbOK.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        jbCancel = new JButton(res.getString("DGenerateKeyPairCert.jbCancel.text"));
        jbCancel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(jpOptions, BorderLayout.CENTER);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

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
            caIssuerName = X500Name.getInstance(issuerCert.getIssuerDN());
            caPublicKey = issuerCert.getPublicKey();
            caSerialNumber = issuerCert.getSerialNumber();
        } else {
            caIssuerName = jdnName.getDistinguishedName(); // May be null
            caPublicKey = keyPair.getPublic();

            String serialNumberStr = jtfSerialNumber.getText().trim();
            if (serialNumberStr.length() != 0) {
                try {
                    caSerialNumber = new BigInteger(serialNumberStr);
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
            serialNumber = new BigInteger(serialNumberStr);
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

        X500Name name = jdnName.getDistinguishedName();

        if (name == null) {
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
                certificate = generator.generateSelfSigned(name, validityStart, validityEnd, keyPair.getPublic(),
                        keyPair.getPrivate(), signatureType, serialNumber, extensions, provider);
            } else {
                certificate = generator.generate(name,
                        X500NameUtils.x500PrincipalToX500Name(issuerCert.getSubjectX500Principal()),
                        validityStart, validityEnd, keyPair.getPublic(), issuerPrivateKey, signatureType, serialNumber,
                        extensions, provider);
            }
        } catch (CryptoException ex) {
            DError dError = new DError(this, ex);
            dError.setLocationRelativeTo(getParent());
            dError.setVisible(true);
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
        Security.addProvider(new BouncyCastleProvider());
        javax.swing.UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
                    keyGen.initialize(1024);
                    KeyPair keyPair = keyGen.genKeyPair();

                    DGenerateKeyPairCert dialog = new DGenerateKeyPairCert(new javax.swing.JFrame(), "test", keyPair, KeyPairType.RSA, null, null, null);
                    dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                        @Override
                        public void windowClosing(java.awt.event.WindowEvent e) {
                            System.exit(0);
                        }
                    });
                    dialog.setVisible(true);
                } catch(Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
