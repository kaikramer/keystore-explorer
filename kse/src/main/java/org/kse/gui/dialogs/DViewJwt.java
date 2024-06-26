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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import org.kse.crypto.CryptoException;
import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the JSON Web Token (JWT).
 */
public class DViewJwt extends JEscDialog {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JLabel jlHeader;
    private JTextArea jtaHeader;
    private JScrollPane jspHeader;
    private JLabel jlPayload;
    private JTextArea jtaPayload;
    private JScrollPane jspPayload;
    private JLabel jlEncoded;
    private JTextArea jtaEncoded;
    private JScrollPane jspEncoded;
    private JLabel jlPublicKey;
    private JTextArea jtaPublicKey;
    private JScrollPane jspPublicKey;
    
    private JButton jbCopy;
    private JButton jbOK;
    private JButton jbVerify;
    private JPanel jpButtons;

    private JWT jwt;

    /**
     * Creates a new DViewJwt dialog.
     *
     * @param parent The parent frame
     * @param jwt    The encoded JWT
     */
    public DViewJwt(JFrame parent, JWT jwt) {
        super(parent, Dialog.ModalityType.MODELESS);
        setTitle(res.getString("DViewJwt.Title"));
        this.jwt = jwt;
        initComponents();
    }

    private void initComponents() {
        jlHeader = new JLabel(res.getString("DViewJwt.jlHeader.text"));

        jtaHeader = new JTextArea();
        jtaHeader.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaHeader.setEditable(false);
        jtaHeader.setLineWrap(false);
        jtaHeader.setToolTipText(res.getString("DViewJwt.jtaHeader.tooltip"));

        jspHeader = PlatformUtil.createScrollPane(jtaHeader, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                  ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        jlPayload = new JLabel(res.getString("DViewJwt.jlPayload.text"));

        jtaPayload = new JTextArea();
        jtaPayload.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaPayload.setEditable(false);
        jtaPayload.setLineWrap(false);
        jtaPayload.setToolTipText(res.getString("DViewJwt.jtaPayload.tooltip"));

        jspPayload = PlatformUtil.createScrollPane(jtaPayload, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                   ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        jlEncoded = new JLabel(res.getString("DViewJwt.jlEncoded.text"));

        jtaEncoded = new JTextArea();
        jtaEncoded.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaEncoded.setEditable(true);
        jtaEncoded.setLineWrap(true);
        jtaEncoded.setToolTipText(res.getString("DViewJwt.jtaEncoded.tooltip"));
        jtaEncoded.addFocusListener(new FocusListener() {

            @Override
            public void focusGained(FocusEvent arg0) {
            }

            @Override
            public void focusLost(FocusEvent arg0) {
                try {
                    JWT jwtVeri = JWTParser.parse(jtaEncoded.getText());
                    if (!jwt.equals(jwtVeri)) {
                        jwt = jwtVeri;
                        populateDialog();
                    }
                } catch (ParseException e) {
                    jtaPayload.setText("");
                    jtaHeader.setText("");
                }
            }
        });

        jspEncoded = PlatformUtil.createScrollPane(jtaEncoded, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        jlPublicKey = new JLabel(res.getString("DViewJwt.jlPublicKey.text"));

        jtaPublicKey = new JTextArea();
        jtaPublicKey.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaPublicKey.setEditable(true);
        jtaPublicKey.setLineWrap(true);
        jtaPublicKey.setToolTipText(res.getString("DViewJwt.jtaPublicKey.tooltip"));

        jspPublicKey = PlatformUtil.createScrollPane(jtaPublicKey, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        jbCopy = new JButton(res.getString("DViewJwt.jbCopy.text"));
        jbCopy.setToolTipText(res.getString("DViewJwt.jbCopy.tooltip"));
        PlatformUtil.setMnemonic(jbCopy, res.getString("DViewJwt.jbCopy.mnemonic").charAt(0));

        jbOK = new JButton(res.getString("DViewJwt.jbOK.text"));

        jbVerify = new JButton(res.getString("DViewJwt.jbVerify.text"));
        jbVerify.setToolTipText(res.getString("DViewJwt.jbVerify.tooltip"));
        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlHeader, "");
        pane.add(jspHeader, "width 400lp:400lp:400lp, height 150lp:150lp:150lp");
        pane.add(jlPayload, "");
        pane.add(jspPayload, "width 400lp:400lp:400lp, height 150lp:150lp:150lp, wrap");
        pane.add(jlEncoded, "");
        pane.add(jspEncoded, "width 400lp:400lp:400lp, height 200lp:200lp:200lp");
        pane.add(jlPublicKey, "");
        pane.add(jspPublicKey, "width 400lp:400lp:400lp, height 200lp:200lp:200lp, wrap");
        
        jpButtons = PlatformUtil.createDialogButtonPanel(jbCopy, jbVerify, "insets 0");

        pane.add(jpButtons, "right, spanx");
        pane.add(new JSeparator(), "spanx, growx, wrap unrel:push");

        pane.add(jbOK, "spanx, tag ok");

        // actions

        jbOK.addActionListener(evt -> okPressed());

        jbVerify.addActionListener(evt -> verifyPressed());

        jbCopy.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewJwt.this);
                copyPressed();
            } finally {
                CursorUtil.setCursorFree(DViewJwt.this);
            }
        });

        setResizable(false);

        populateDialog();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbCopy);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private void populateDialog() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        Header header = jwt.getHeader();
        jtaHeader.setText(gson.toJson(header.toJSONObject()));

        if (jwt instanceof JWSObject) {
            Payload payload = ((JWSObject) jwt).getPayload();
            jtaPayload.setText(gson.toJson(payload.toJSONObject()));
        } else {
            jtaPayload.setText("{}");
        }

        jtaEncoded.setText(jwt.serialize());
    }

    private void okPressed() {
        closeDialog();
    }

    private static byte[] decodeIfBase64(String data) {
        byte[] dataAsBytes = data.getBytes();

        // first handle base64 encoded binary data
        try {
            dataAsBytes = Base64.getDecoder().decode(data.trim());
        } catch (IllegalArgumentException e) {
            // was not valid b64
        }
        return dataAsBytes;
    }
    
    private void verifyPressed() {
        String data = jtaPublicKey.getText();
        if (data.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DViewJwt.InvalidPublicKey.message"),
                    res.getString("DViewJwt.Verify.Title"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        byte[] dataAsBytes = decodeIfBase64(data);
        try {
            CryptoFileType fileType = CryptoFileUtil.detectFileType(dataAsBytes);
            if (fileType != CryptoFileType.OPENSSL_PUB) {
                JOptionPane.showMessageDialog(this, res.getString("DViewJwt.InvalidPublicKey.message"),
                        res.getString("DViewJwt.Verify.Title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            PublicKey publicKey = OpenSslPubUtil.load(dataAsBytes);
            var signedJWT = SignedJWT.parse(jwt.serialize());
            JWSVerifier verifier = null;
            if (publicKey instanceof ECPublicKey) {
                verifier = new ECDSAVerifier((ECPublicKey) publicKey);
            } else if (publicKey instanceof RSAPublicKey) {
                verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            } else {
                JOptionPane.showMessageDialog(this, res.getString("DViewJwt.InvalidPublicKey.message"),
                        res.getString("DViewJwt.Verify.Title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (signedJWT.verify(verifier)) {
                JOptionPane.showMessageDialog(this, res.getString("DViewJwt.SignatureVerified.message"),
                        res.getString("DViewJwt.Verify.Title"), JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, res.getString("DViewJwt.InvalidSignature.message"),
                        res.getString("DViewJwt.Verify.Title"), JOptionPane.ERROR_MESSAGE);
            }
        } catch (IOException | CryptoException | JOSEException | ParseException ex) {
            DError.displayError(this, ex);
        }
    }

    public void setPublicKey(String publicKey) {
        jtaPublicKey.setText(publicKey);
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    private void copyPressed() {
        String policy = jtaEncoded.getText();

        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection copy = new StringSelection(policy);
        clipboard.setContents(copy, copy);
    }

    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        JWT jwt = JWTParser.parse(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

        DViewJwt dialog = new DViewJwt(new javax.swing.JFrame(), jwt);
        DialogViewer.run(dialog);
    }

}
