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

package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the JSON Web Token (JWT).
 */
public class DViewJwt extends JEscDialog {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JLabel jlAlgorithm;
    private JTextField jtfAlgorithm;
    private JLabel jlPayload;
    private JTextArea jtaPayload;
    private JScrollPane jspPayload;
    private JLabel jlEncoded;
    private JTextArea jtaEncoded;
    private JScrollPane jspEncoded;
    private JButton jbCopy;
    private JButton jbOK;

    private JWT jwt;

    /**
     * Creates a new DViewJwt dialog.
     *
     * @param parent The parent frame
     * @param jwt    The encoded JWT
     */
    public DViewJwt(JFrame parent, JWT jwt) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        setTitle(res.getString("DViewJwt.Title"));
        this.jwt = jwt;
        initComponents();
    }

    private void initComponents() {
        jlAlgorithm = new JLabel(res.getString("DViewJwt.jlAlgorithm.text"));

        jtfAlgorithm = new JTextField();
        jtfAlgorithm.setEditable(false);
        jtfAlgorithm.setToolTipText(res.getString("DViewJwt.jtfAlgorithm.tooltip"));

        jlPayload = new JLabel(res.getString("DViewJwt.jlPayload.text"));

        jtaPayload = new JTextArea();
        jtaPayload.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaPayload.setBackground(jtfAlgorithm.getBackground());
        jtaPayload.setEditable(false);
        jtaPayload.setLineWrap(true);
        jtaPayload.setToolTipText(res.getString("DViewJwt.jtaPayload.tooltip"));

        jspPayload = PlatformUtil.createScrollPane(jtaPayload, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                                   ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        jspPayload.setBorder(jtfAlgorithm.getBorder());

        jlEncoded = new JLabel(res.getString("DViewJwt.jlEncoded.text"));

        jtaEncoded = new JTextArea();
        jtaEncoded.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        jtaEncoded.setBackground(jtfAlgorithm.getBackground());
        jtaEncoded.setEditable(false);
        jtaEncoded.setLineWrap(true);
        jtaEncoded.setToolTipText(res.getString("DViewJwt.jtaEncoded.tooltip"));

        jspEncoded = PlatformUtil.createScrollPane(jtaEncoded, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                                   ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        jspEncoded.setBorder(jtfAlgorithm.getBorder());

        jbCopy = new JButton(res.getString("DViewJwt.jbCopy.text"));
        jbCopy.setToolTipText(res.getString("DViewJwt.jbCopy.tooltip"));
        PlatformUtil.setMnemonic(jbCopy, res.getString("DViewJwt.jbCopy.mnemonic").charAt(0));

        jbOK = new JButton(res.getString("DViewJwt.jbOK.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlAlgorithm, "");
        pane.add(jtfAlgorithm, "growx, pushx, wrap");
        pane.add(jlPayload, "");
        pane.add(jspPayload, "width 300lp:300lp:300lp, height 150lp:150lp:150lp, wrap");
        pane.add(jlEncoded, "");
        pane.add(jspEncoded, "width 300lp:300lp:300lp, height 150lp:150lp:150lp, wrap");
        pane.add(jbCopy, "spanx");
        pane.add(new JSeparator(), "spanx, growx, wrap unrel:push");
        pane.add(jbOK, "spanx, tag ok");

        // actions

        jbOK.addActionListener(evt -> okPressed());

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
        jtfAlgorithm.setText(jwt.getHeader().getAlgorithm().getName());

        if (jwt instanceof JWSObject) {
            Payload payload = ((JWSObject) jwt).getPayload();
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            jtaPayload.setText(gson.toJson(payload.toJSONObject()));
        } else {
            jtaPayload.setText("{}");
        }

        jtaEncoded.setText(jwt.serialize());
    }

    private void okPressed() {
        closeDialog();
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
        JWT jwt = JWTParser.parse("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9" +
                                   ".eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9");

        DViewJwt dialog = new DViewJwt(new javax.swing.JFrame(), jwt);
        DialogViewer.run(dialog);
    }

}
