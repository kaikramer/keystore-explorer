/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.datetime.JDateTime;
import org.kse.gui.dialogs.DialogHelper;
import org.kse.utilities.DialogViewer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import net.miginfocom.swing.MigLayout;

/**
 * Dialog that display the data to create a JWT (JSON Web Token)
 */
public class DSignJwt extends JEscDialog {
    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlId;
    private JTextField jtfId;
    private JButton jbGenId;
    private JLabel jlIssuer;
    private JTextField jtfIssuer;
    private JLabel jlIssuedAt;
    private JDateTime jdtIssuedAt;
    private JLabel jlSubject;
    private JTextField jtfSubject;
    private JLabel jlNotBefore;
    private JDateTime jdtNotBefore;
    private JLabel jlExpiration;
    private JDateTime jdtExpiration;
    private JLabel jlAudience;
    private JTextField jtfAudience;
    private JLabel jlSignatureAlgorithm;
    private JComboBox<SignatureType> jcbSignatureAlgorithm;
    private JClaims jpClaims;

    private JButton jbOK;
    private JButton jbCancel;

    private KeyPairType signKeyPairType;
    private PrivateKey signPrivateKey;
    private SignatureType signatureType;

    private JFrame parent;

    private boolean isOk = false;

    /**
     * Creates a new DSignJwt
     *
     * @param parent          The parent frame
     * @param signKeyPairType Key pair type
     * @param signPrivateKey  Private key certificate
     */
    public DSignJwt(JFrame parent, KeyPairType signKeyPairType, PrivateKey signPrivateKey) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.parent = parent;
        this.signKeyPairType = signKeyPairType;
        this.signPrivateKey = signPrivateKey;
        setTitle(res.getString("DSignJwt.Title"));
        initComponents();
    }

    private void initComponents() {
        Date now = new Date();

        jlId = new JLabel(res.getString("DSignJwt.jlId.text"));
        jtfId = new JTextField("", 23);
        jtfId.setToolTipText(res.getString("DSignJwt.jtfId.tooltip"));

        jbGenId = new JButton();
        jbGenId.setIcon(new ImageIcon(getClass().getResource("images/genid.png")));
        jbGenId.setToolTipText(res.getString("DSignJwt.jbGenId.tooltip"));

        jlIssuer = new JLabel(res.getString("DSignJwt.jlIssuer.text"));
        jtfIssuer = new JTextField("", 23);
        jtfIssuer.setToolTipText(res.getString("DSignJwt.jtfIssuer.tooltip"));

        jlIssuedAt = new JLabel(res.getString("DSignJwt.jlIssuedAt.text"));
        jdtIssuedAt = new JDateTime(res.getString("DSignJwt.jdtIssuedAt.text"), true);
        jdtIssuedAt.setDateTime(null);
        jdtIssuedAt.setToolTipText(res.getString("DSignJwt.jdtIssuedAt.tooltip"));

        jlSubject = new JLabel(res.getString("DSignJwt.jlSubject.text"));
        jtfSubject = new JTextField("", 23);
        jtfSubject.setToolTipText(res.getString("DSignJwt.jtfSubject.tooltip"));

        jlNotBefore = new JLabel(res.getString("DSignJwt.jlNotBefore.text"));
        jdtNotBefore = new JDateTime(res.getString("DSignJwt.jdtNotBefore.text"), true);
        jdtNotBefore.setDateTime(null);
        jdtNotBefore.setToolTipText(res.getString("DSignJwt.jdtNotBefore.tooltip"));

        jlExpiration = new JLabel(res.getString("DSignJwt.jlExpiration.text"));
        jdtExpiration = new JDateTime(res.getString("DSignJwt.jdtExpiration.text"), true);
        jdtExpiration.setDateTime(addOneDayCalendar(now));
        jdtExpiration.setToolTipText(res.getString("DSignJwt.jdtExpiration.tooltip"));

        jlAudience = new JLabel(res.getString("DSignJwt.jlAudience.text"));
        jtfAudience = new JTextField("", 23);
        jtfAudience.setToolTipText(res.getString("DSignJwt.jtfAudience.tooltip"));

        jlSignatureAlgorithm = new JLabel(res.getString("DSignJwt.jlSignatureAlgorithm.text"));

        jcbSignatureAlgorithm = new JComboBox<>();
        jcbSignatureAlgorithm.setMaximumRowCount(10);
        if (signPrivateKey != null) {
            // JWS uses specific algorithms. The defaults provide unsupported algorithms.
            DialogHelper.populateSigAlgs(signKeyPairType, signPrivateKey, jcbSignatureAlgorithm);
            if (KeyPairType.RSA == signKeyPairType) {
                // These algorithms are not supported by JWS
                jcbSignatureAlgorithm.removeItem(SignatureType.RIPEMD160_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA1_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA224_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA1WITHRSAANDMGF1);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA224WITHRSAANDMGF1);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_224_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_256_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_384_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_512_RSA);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_224WITHRSAANDMGF1);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_256WITHRSAANDMGF1);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_384WITHRSAANDMGF1);
                jcbSignatureAlgorithm.removeItem(SignatureType.SHA3_512WITHRSAANDMGF1);
            }
        }
        jcbSignatureAlgorithm.setToolTipText(res.getString("DSignJwt.jcbSignatureAlgorithm.tooltip"));

        jpClaims = new JClaims(parent);

        jbOK = new JButton(res.getString("DSignJwt.jbOK.text"));
        jbCancel = new JButton(res.getString("DSignJwt.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));

        pane.add(jlId, "");
        pane.add(jtfId, "");
        pane.add(jbGenId, "wrap");

        pane.add(jlIssuer, "");
        pane.add(jtfIssuer, "wrap");

        pane.add(jlIssuedAt, "");
        pane.add(jdtIssuedAt, "wrap");

        pane.add(jlSubject, "");
        pane.add(jtfSubject, "wrap");

        pane.add(jlNotBefore, "");
        pane.add(jdtNotBefore, "wrap");

        pane.add(jlExpiration, "");
        pane.add(jdtExpiration, "wrap");

        pane.add(jlAudience, "");
        pane.add(jtfAudience, "wrap");

        // Don't show the signature algorithm for ECDSA and EDDSA.
        // The JWS algorithm is derived from the curve.
        if (KeyPairType.EC != signKeyPairType && KeyPairType.EDDSA != signKeyPairType && KeyPairType.ED25519 != signKeyPairType) {
            pane.add(jlSignatureAlgorithm, "");
            pane.add(jcbSignatureAlgorithm, "wrap");
        }
        pane.add(jpClaims, "spanx, growx, wrap unrel");

        pane.add(jpButtons, "right, spanx");

        populateFields();
        jbGenId.addActionListener(evt -> genIdPressed());
        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());

        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void populateFields() {

    }

    private void genIdPressed() {
        jtfId.setText(UUID.randomUUID().toString());
        jtfIssuer.requestFocus();
    }

    private void okPressed() {
        isOk = true;
        signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    public String getIssuer() {
        if (!jtfIssuer.getText().isEmpty()) {
            return jtfIssuer.getText();
        } else {
            return null;
        }
    }

    public String getId() {
        if (!jtfId.getText().isEmpty()) {
            return jtfId.getText();
        } else {
            return null;
        }
    }

    public Date getIssuedAt() {
        return jdtIssuedAt.getDateTime();
    }

    public Date getNotBefore() {
        return jdtNotBefore.getDateTime();
    }

    public Date getExpiration() {
        return jdtExpiration.getDateTime();

    }

    public String getSubject() {
        if (!jtfSubject.getText().isEmpty()) {
            return jtfSubject.getText();
        } else {
            return null;
        }
    }

    public String getAudience() {
        if (!jtfAudience.getText().isEmpty()) {
            return jtfAudience.getText();
        } else {
            return null;
        }
    }

    public List<CustomClaim> getCustomClaims() {
        return jpClaims.getCustomClaims();
    }

    public boolean isOk() {
        return isOk;
    }

    public JWSAlgorithm getAlgorithm() {
        JWSAlgorithm signatureAlgorithm = null;

        if (KeyPairType.RSA == signKeyPairType) {
            // For RSA determine JWS algorithm using the signature type
            switch (signatureType) {
                case SHA256_RSA:
                    signatureAlgorithm = JWSAlgorithm.RS256;
                    break;
                case SHA384_RSA:
                    signatureAlgorithm = JWSAlgorithm.RS384;
                    break;
                case SHA512_RSA:
                    signatureAlgorithm = JWSAlgorithm.RS512;
                    break;
                case SHA256WITHRSAANDMGF1:
                    signatureAlgorithm = JWSAlgorithm.PS256;
                    break;
                case SHA384WITHRSAANDMGF1:
                    signatureAlgorithm = JWSAlgorithm.PS384;
                    break;
                case SHA512WITHRSAANDMGF1:
                    signatureAlgorithm = JWSAlgorithm.PS512;
                    break;
                default:
                    break;
            }
        } else if (KeyPairType.EC == signKeyPairType) {
            // For EC determine the algorithm based on the curve not the signature type
            Curve curve = getCurve();
            if (Curve.P_256 == curve) {
                signatureAlgorithm = JWSAlgorithm.ES256;
            } else if (Curve.P_384 == curve) {
                signatureAlgorithm = JWSAlgorithm.ES384;
            } else if (Curve.P_521 == curve) {
                signatureAlgorithm = JWSAlgorithm.ES512;
            } else if (Curve.SECP256K1 == curve) {
                signatureAlgorithm = JWSAlgorithm.ES256K;
            }
        } else if (KeyPairType.EDDSA == signKeyPairType) {
            // Only Ed25519 is supported. Must figure out the curve if Nimbus JOSE ever adds an Ed448 signer.
            // Likely use the signatureType since only one signature type is supported for each Edwards curve.
            signatureAlgorithm = JWSAlgorithm.Ed25519;
        } else if (KeyPairType.ED25519 == signKeyPairType) {
            signatureAlgorithm = JWSAlgorithm.Ed25519;
        }

        return signatureAlgorithm;
    }

    public Curve getCurve() {
        if (KeyPairType.EC == signKeyPairType) {
            if (signPrivateKey instanceof ECPrivateKey) {
                return Curve.forECParameterSpec(((ECPrivateKey) signPrivateKey).getParams());
            }
        }
        return null;
    }

    public static Date addOneDayCalendar(Date date) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.DATE, 1);
        return c.getTime();
    }

    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DSignJwt(new javax.swing.JFrame(), KeyPairType.RSA, null));
    }
}
