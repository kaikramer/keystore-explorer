/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.gui.dialogs.extensions;

import static org.kse.crypto.x509.ExtendedKeyUsageType.ADOBE_PDF_SIGNING;
import static org.kse.crypto.x509.ExtendedKeyUsageType.ANY_EXTENDED_KEY_USAGE;
import static org.kse.crypto.x509.ExtendedKeyUsageType.CLIENT_AUTH;
import static org.kse.crypto.x509.ExtendedKeyUsageType.CODE_SIGNING;
import static org.kse.crypto.x509.ExtendedKeyUsageType.DOCUMENT_SIGNING;
import static org.kse.crypto.x509.ExtendedKeyUsageType.EMAIL_PROTECTION;
import static org.kse.crypto.x509.ExtendedKeyUsageType.ENCRYPTED_FILE_SYSTEM;
import static org.kse.crypto.x509.ExtendedKeyUsageType.IPSEC_END_SYSTEM;
import static org.kse.crypto.x509.ExtendedKeyUsageType.IPSEC_TUNNEL;
import static org.kse.crypto.x509.ExtendedKeyUsageType.IPSEC_USER;
import static org.kse.crypto.x509.ExtendedKeyUsageType.OCSP_SIGNING;
import static org.kse.crypto.x509.ExtendedKeyUsageType.SERVER_AUTH;
import static org.kse.crypto.x509.ExtendedKeyUsageType.SMARTCARD_LOGON;
import static org.kse.crypto.x509.ExtendedKeyUsageType.TIME_STAMPING;
import static org.kse.crypto.x509.ExtendedKeyUsageType.TSL_SIGNING;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.kse.crypto.x509.ExtendedKeyUsageType;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.CursorUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit an Extended Key Usage extension.
 */
public class DExtendedKeyUsage extends DExtension {
    private static final long serialVersionUID = -972351635055954L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");
    private static ResourceBundle resCryptoX509 = ResourceBundle.getBundle("org/kse/crypto/x509/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlExtendedKeyUsage;
    private JCheckBox jcbCodeSigning;
    private JCheckBox jcbDocumentSigning;
    private JCheckBox jcbEmailProtection;
    private JCheckBox jcbEncryptedFileSystem;
    private JCheckBox jcbIpSecurityEndSystem;
    private JCheckBox jcbIpSecurityTunnelTermination;
    private JCheckBox jcbIpSecurityUser;
    private JCheckBox jcbOcspSigning;
    private JCheckBox jcbTimeStamping;
    private JCheckBox jcbTlsWebClientAuthentication;
    private JCheckBox jcbTlsWebServerAuthentication;
    private JCheckBox jcbSmartcardLogon;
    private JCheckBox jcbAnyExtendedKeyUsage;
    private JCheckBox jcbAdobePDFSigning;
    private JCheckBox jcbTslSigning;
    private JCheckBox jcbCustomExtKeyUsage;
    private Set<ASN1ObjectIdentifier> customExtKeyUsagesOids = new HashSet<>();
    private JButton jbAddEku;
    private JButton jbOK;
    private JButton jbCancel;

    private byte[] value;

    /**
     * Creates a new DExtendedKeyUsage dialog.
     *
     * @param parent The parent dialog
     */
    public DExtendedKeyUsage(JDialog parent) {
        super(parent);
        setTitle(res.getString("DExtendedKeyUsage.Title"));
        initComponents();
    }

    /**
     * Creates a new DExtendedKeyUsage dialog.
     *
     * @param parent The parent dialog
     * @param value  Extended Key Usage DER-encoded
     * @throws IOException If value could not be decoded
     */
    public DExtendedKeyUsage(JDialog parent, byte[] value) throws IOException {
        super(parent);
        setTitle(res.getString("DExtendedKeyUsage.Title"));
        initComponents();
        prepopulateWithValue(value);
    }

    private void initComponents() {
        jlExtendedKeyUsage = new JLabel(res.getString("DExtendedKeyUsage.jlExtendedKeyUsage.text"));

        jcbCodeSigning = new JCheckBox(res.getString("DExtendedKeyUsage.jcbCodeSigning.text"));
        jcbCodeSigning.setToolTipText(resCryptoX509.getString("CodeSigningExtKeyUsage"));

        jcbDocumentSigning = new JCheckBox(res.getString("DExtendedKeyUsage.jcbDocumentSigning.text"));
        jcbDocumentSigning.setToolTipText(resCryptoX509.getString("DocumentSigningExtKeyUsage"));

        jcbAdobePDFSigning = new JCheckBox(res.getString("DExtendedKeyUsage.jcbAdobePDFSigning.text"));
        jcbAdobePDFSigning.setToolTipText(resCryptoX509.getString("AdobePDFSigningExtKeyUsage"));

        jcbTslSigning = new JCheckBox(res.getString("DExtendedKeyUsage.jcbTslSigning.text"));
        jcbTslSigning.setToolTipText(resCryptoX509.getString("TSLSignExtKeyUsage"));

        jcbEncryptedFileSystem = new JCheckBox(res.getString("DExtendedKeyUsage.jcbEncryptedFileSystem.text"));
        jcbEncryptedFileSystem.setToolTipText(resCryptoX509.getString("EncryptedFileSystemExtKeyUsage"));

        jcbEmailProtection = new JCheckBox(res.getString("DExtendedKeyUsage.jcbEmailProtection.text"));
        jcbEmailProtection.setToolTipText(resCryptoX509.getString("EmailProtectionExtKeyUsage"));

        jcbIpSecurityEndSystem = new JCheckBox(res.getString("DExtendedKeyUsage.jcbIpSecurityEndSystem.text"));
        jcbIpSecurityEndSystem.setToolTipText(resCryptoX509.getString("IpsecEndSystemExtKeyUsage"));

        jcbIpSecurityTunnelTermination = new JCheckBox(
                res.getString("DExtendedKeyUsage.jcbIpSecurityTunnelTermination.text"));
        jcbIpSecurityTunnelTermination.setToolTipText(resCryptoX509.getString("IpsecTunnelExtKeyUsage"));

        jcbIpSecurityUser = new JCheckBox(res.getString("DExtendedKeyUsage.jcbIpSecurityUser.text"));
        jcbIpSecurityUser.setToolTipText(resCryptoX509.getString("IpsecUserExtKeyUsage"));

        jcbOcspSigning = new JCheckBox(res.getString("DExtendedKeyUsage.jcbOcspSigning.text"));
        jcbOcspSigning.setToolTipText(resCryptoX509.getString("OcspSigningExtKeyUsage"));

        jcbTimeStamping = new JCheckBox(res.getString("DExtendedKeyUsage.jcbTimeStamping.text"));
        jcbTimeStamping.setToolTipText(resCryptoX509.getString("TimeStampingExtKeyUsage"));

        jcbTlsWebClientAuthentication = new JCheckBox(
                res.getString("DExtendedKeyUsage.jcbTlsWebClientAuthentication.text"));
        jcbTlsWebClientAuthentication.setToolTipText(resCryptoX509.getString("ClientAuthExtKeyUsage"));

        jcbTlsWebServerAuthentication = new JCheckBox(
                res.getString("DExtendedKeyUsage.jcbTlsWebServerAuthentication.text"));
        jcbTlsWebServerAuthentication.setToolTipText(resCryptoX509.getString("ServerAuthExtKeyUsage"));

        jcbSmartcardLogon = new JCheckBox(res.getString("DExtendedKeyUsage.jcbSmartcardLogon.text"));
        jcbSmartcardLogon.setToolTipText(resCryptoX509.getString("SmartcardLogonExtKeyUsage"));

        jcbAnyExtendedKeyUsage = new JCheckBox(res.getString("DExtendedKeyUsage.jcbAnyExtendedKeyUsage.text"));
        jcbAnyExtendedKeyUsage.setToolTipText(resCryptoX509.getString("AnyExtendedKeyUsageExtKeyUsage"));

        jcbCustomExtKeyUsage = new JCheckBox(res.getString("DExtendedKeyUsage.jcbCustomExtendedKeyUsage.text"));
        jbAddEku = new JButton(res.getString("DExtendedKeyUsage.jbAddEku.text"));
        jbOK = new JButton(res.getString("DExtendedKeyUsage.jbOK.text"));
        jbCancel = new JButton(res.getString("DExtendedKeyUsage.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "", ""));
        pane.add(jlExtendedKeyUsage, "spanx, wrap unrel");
        pane.add(jcbAdobePDFSigning, "");
        pane.add(jcbAnyExtendedKeyUsage, "");
        pane.add(jcbCodeSigning, "wrap");
        pane.add(jcbDocumentSigning, "");
        pane.add(jcbEncryptedFileSystem, "");
        pane.add(jcbEmailProtection, "wrap");
        pane.add(jcbIpSecurityEndSystem, "");
        pane.add(jcbIpSecurityTunnelTermination, "");
        pane.add(jcbIpSecurityUser, "wrap");
        pane.add(jcbOcspSigning, "");
        pane.add(jcbSmartcardLogon, "");
        pane.add(jcbTimeStamping, "wrap");
        pane.add(jcbTlsWebClientAuthentication, "");
        pane.add(jcbTlsWebServerAuthentication, "");
        pane.add(jcbTslSigning, "wrap");
        pane.add(jcbCustomExtKeyUsage, "spanx, split");
        pane.add(jbAddEku, "wrap unrel");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        // actions
        jcbCustomExtKeyUsage.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExtendedKeyUsage.this);
                if (customExtKeyUsagesOids.isEmpty()) {
                    addCustomExtKeyUsagePressed();
                }
            } finally {
                CursorUtil.setCursorFree(DExtendedKeyUsage.this);
            }
        });
        jbAddEku.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExtendedKeyUsage.this);
                addCustomExtKeyUsagePressed();
            } finally {
                CursorUtil.setCursorFree(DExtendedKeyUsage.this);
            }
        });
        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1792160787358938936L;

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

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void prepopulateWithValue(byte[] value) throws IOException {
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(value);

        for (KeyPurposeId keyPurposeId : extendedKeyUsage.getUsages()) {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) keyPurposeId.toASN1Primitive();

            ExtendedKeyUsageType type = ExtendedKeyUsageType.resolveOid(oid.getId());

            if (type == SERVER_AUTH) {
                jcbTlsWebServerAuthentication.setSelected(true);
            } else if (type == CLIENT_AUTH) {
                jcbTlsWebClientAuthentication.setSelected(true);
            } else if (type == CODE_SIGNING) {
                jcbCodeSigning.setSelected(true);
            } else if (type == DOCUMENT_SIGNING) {
                jcbDocumentSigning.setSelected(true);
            } else if (type == ADOBE_PDF_SIGNING) {
                jcbAdobePDFSigning.setSelected(true);
            } else if (type == TSL_SIGNING) {
                jcbTslSigning.setSelected(true);
            } else if (type == EMAIL_PROTECTION) {
                jcbEmailProtection.setSelected(true);
            } else if (type == ENCRYPTED_FILE_SYSTEM) {
                jcbEncryptedFileSystem.setSelected(true);
            } else if (type == IPSEC_END_SYSTEM) {
                jcbIpSecurityEndSystem.setSelected(true);
            } else if (type == IPSEC_TUNNEL) {
                jcbIpSecurityTunnelTermination.setSelected(true);
            } else if (type == IPSEC_USER) {
                jcbIpSecurityUser.setSelected(true);
            } else if (type == SMARTCARD_LOGON) {
                jcbSmartcardLogon.setSelected(true);
            } else if (type == TIME_STAMPING) {
                jcbTimeStamping.setSelected(true);
            } else if (type == OCSP_SIGNING) {
                jcbOcspSigning.setSelected(true);
            } else if (type == ANY_EXTENDED_KEY_USAGE) {
                jcbAnyExtendedKeyUsage.setSelected(true);
            } else {
                customExtKeyUsagesOids.add(oid);
            }
        }
        jcbCustomExtKeyUsage.setSelected(!customExtKeyUsagesOids.isEmpty());
    }

    private void addCustomExtKeyUsagePressed() {
        DCustomExtKeyUsage dCustomExtKeyUsage = new DCustomExtKeyUsage(this, customExtKeyUsagesOids);
        dCustomExtKeyUsage.setLocationRelativeTo(this);
        dCustomExtKeyUsage.setVisible(true);
        customExtKeyUsagesOids = dCustomExtKeyUsage.getObjectIds();
        jcbCustomExtKeyUsage.setSelected(!customExtKeyUsagesOids.isEmpty());
    }

    private void okPressed() {
        if (!jcbTlsWebServerAuthentication.isSelected() && !jcbTlsWebClientAuthentication.isSelected() &&
            !jcbCodeSigning.isSelected() && !jcbEmailProtection.isSelected() && !jcbIpSecurityEndSystem.isSelected() &&
            !jcbIpSecurityTunnelTermination.isSelected() && !jcbIpSecurityUser.isSelected() &&
            !jcbTimeStamping.isSelected() && !jcbOcspSigning.isSelected() && !jcbDocumentSigning.isSelected() &&
            !jcbAdobePDFSigning.isSelected() && !jcbTslSigning.isSelected() && !jcbEncryptedFileSystem.isSelected() &&
            !jcbAnyExtendedKeyUsage.isSelected() && !jcbSmartcardLogon.isSelected() &&
            !jcbCustomExtKeyUsage.isSelected()) {
            JOptionPane.showMessageDialog(this, res.getString("DExtendedKeyUsage.ValueReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        ArrayList<KeyPurposeId> keyPurposeIds = new ArrayList<>();

        if (jcbTlsWebServerAuthentication.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(SERVER_AUTH.oid())));
        }

        if (jcbTlsWebClientAuthentication.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(CLIENT_AUTH.oid())));
        }

        if (jcbCodeSigning.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(CODE_SIGNING.oid())));
        }

        if (jcbDocumentSigning.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(DOCUMENT_SIGNING.oid())));
        }

        if (jcbAdobePDFSigning.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(ADOBE_PDF_SIGNING.oid())));
        }

        if (jcbTslSigning.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(TSL_SIGNING.oid())));
        }

        if (jcbEmailProtection.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(EMAIL_PROTECTION.oid())));
        }

        if (jcbEncryptedFileSystem.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(ENCRYPTED_FILE_SYSTEM.oid())));
        }

        if (jcbIpSecurityEndSystem.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IPSEC_END_SYSTEM.oid())));
        }

        if (jcbIpSecurityTunnelTermination.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IPSEC_TUNNEL.oid())));
        }

        if (jcbIpSecurityUser.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IPSEC_USER.oid())));
        }

        if (jcbTimeStamping.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(TIME_STAMPING.oid())));
        }

        if (jcbOcspSigning.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(OCSP_SIGNING.oid())));
        }

        if (jcbSmartcardLogon.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(SMARTCARD_LOGON.oid())));
        }

        if (jcbAnyExtendedKeyUsage.isSelected()) {
            keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(ANY_EXTENDED_KEY_USAGE.oid())));
        }
        if (jcbCustomExtKeyUsage.isSelected()) {
            for (ASN1ObjectIdentifier customExcKeyUsageOid : customExtKeyUsagesOids) {
                keyPurposeIds.add(KeyPurposeId.getInstance(customExcKeyUsageOid));
            }
        }
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
                keyPurposeIds.toArray(new KeyPurposeId[0]));

        try {
            value = extendedKeyUsage.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            DError.displayError(this, e);
            return;
        }

        closeDialog();
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public String getOid() {
        return X509ExtensionType.EXTENDED_KEY_USAGE.oid();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    public static void main(String[] args) throws Exception {
        DExtendedKeyUsage dialog = new DExtendedKeyUsage(new JDialog());
        DialogViewer.run(dialog);
    }
}
