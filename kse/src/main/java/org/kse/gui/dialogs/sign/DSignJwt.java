/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
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
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.KSE;
import org.kse.crypto.ecc.EdDSACurves;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.datetime.JDateTime;
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
    private JComboBox<JWSAlgorithm> jcbSignatureAlgorithm;
    private JClaims jpClaims;

    private JButton jbOK;
    private JButton jbCancel;

    private KeyPairType signKeyPairType;
    private PrivateKey signPrivateKey;

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
        if (KeyPairType.RSA == signKeyPairType) {
            jcbSignatureAlgorithm.addItem(JWSAlgorithm.RS256);
            jcbSignatureAlgorithm.addItem(JWSAlgorithm.RS384);
            jcbSignatureAlgorithm.addItem(JWSAlgorithm.RS512);
            jcbSignatureAlgorithm.addItem(JWSAlgorithm.PS256);
            jcbSignatureAlgorithm.addItem(JWSAlgorithm.PS384);
            jcbSignatureAlgorithm.addItem(JWSAlgorithm.PS512);
        } else if (KeyPairType.EDDSA == signKeyPairType) {
            if (EdDSACurves.ED25519.jce().equals(((EdECPrivateKey) signPrivateKey).getParams().getName())) {
                // EdDSA is default for compatibility though deprecated in RFC 9864.
                jcbSignatureAlgorithm.addItem(JWSAlgorithm.EdDSA);
                jcbSignatureAlgorithm.addItem(JWSAlgorithm.Ed25519);
            } else {
                // EdDSA is last since it is deprecated in RFC 9864 and some implementations
                // assume that EdDSA is only Ed25519.
                jcbSignatureAlgorithm.addItem(JWSAlgorithm.Ed448);
                jcbSignatureAlgorithm.addItem(JWSAlgorithm.EdDSA);
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

        // Don't show the signature algorithm for ECDSA.
        // The JWS algorithm is derived from the curve.
        if (KeyPairType.EC != signKeyPairType && KeyPairType.ECDSA != signKeyPairType) {
            pane.add(jlSignatureAlgorithm, "");
            pane.add(jcbSignatureAlgorithm, "wrap");
        }

        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpClaims, "spanx, growx, wrap unrel");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jpButtons, "spanx, growx");

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
        if (KeyPairType.EC == signKeyPairType || KeyPairType.ECDSA == signKeyPairType) {
            // For EC the JWS algorithm is derived from the curve, not chosen by the user
            Curve curve = getCurve();
            if (Curve.P_256 == curve) {
                return JWSAlgorithm.ES256;
            } else if (Curve.P_384 == curve) {
                return JWSAlgorithm.ES384;
            } else if (Curve.P_521 == curve) {
                return JWSAlgorithm.ES512;
            } else if (Curve.SECP256K1 == curve) {
                return JWSAlgorithm.ES256K;
            }
            return null;
        }

        // RSA and EdDSA/Ed25519: return the algorithm selected in the combo box
        return (JWSAlgorithm) jcbSignatureAlgorithm.getSelectedItem();
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
        KeyPair keyPair = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 1024, KSE.BC);
        DialogViewer.run(new DSignJwt(new javax.swing.JFrame(), KeyPairType.RSA, keyPair.getPrivate()));
    }
}
