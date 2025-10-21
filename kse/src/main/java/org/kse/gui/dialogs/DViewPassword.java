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

package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.kse.crypto.KeyInfo;
import org.kse.crypto.secretkey.PasswordType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.password.DChangePassword;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a password stored in a key store.
 */
public class DViewPassword extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private KsePreferences preferences = PreferencesManager.getPreferences();

    private JLabel jlAlgorithm;
    private JTextField jtfAlgorithm;
    private JLabel jlPassword;
    private JPasswordField jpfPassword;
    private JButton jbUpdate;
    private JButton jbCancel;
    private JButton jbOK;

    private SecretKey password;

    private boolean editable;
    private boolean keyHasChanged = false;
    private Password newPassword;

    /**
     * Creates a new DViewPassword dialog.
     *
     * @param parent      Parent frame
     * @param title       The dialog title
     * @param password    Secret key to display
     * @param editable    Secret key can be edited/replaced
     */
    public DViewPassword(JFrame parent, String title, SecretKey password, boolean editable) {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        this.password = password;
        this.editable = editable;
        initComponents();
    }

    /**
     * Creates new DViewPassword dialog where the parent is a dialog.
     *
     * @param parent      Parent dialog
     * @param title       The dialog title
     * @param modality    Dialog modality
     * @param password    Secret key to display
     * @param editable    Secret key can be edited/replaced
     */
    public DViewPassword(JDialog parent, String title, ModalityType modality, SecretKey password, boolean editable) {
        super(parent, title, modality);
        this.password = password;
        this.editable = editable;
        initComponents();
    }

    private void initComponents() {

        jlAlgorithm = new JLabel(res.getString("DViewPassword.jlAlgorithm.text"));

        // 25 columns is big enough to fit the longest algorithm name.
        jtfAlgorithm = new JTextField(25);
        jtfAlgorithm.setEditable(false);
        jtfAlgorithm.setToolTipText(res.getString("DViewPassword.jtfAlgorithm.tooltip"));

        jlPassword = new JLabel(res.getString("DViewPassword.jlPassword.text"));

        jpfPassword = new JPasswordField();
        jpfPassword.setEditable(false);
        jpfPassword.setToolTipText(res.getString("DViewPassword.jtfPassword.tooltip"));

        jbUpdate = new JButton(res.getString("DViewPassword.jbUpdate.text"));
        jbCancel = new JButton(res.getString("DViewPassword.jbCancel.text"));
        jbOK = new JButton(res.getString("DViewPassword.jbOK.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlAlgorithm, "");
        pane.add(jtfAlgorithm, "growx, pushx, wrap");
        pane.add(jlPassword, "");
        if (editable) {
            pane.add(jpfPassword, "growx");
            pane.add(jbUpdate, "wrap");
        } else {
            pane.add(jpfPassword, "growx, wrap");
        }
        pane.add(new JSeparator(), "spanx, growx, wrap");
        if (editable) {
            pane.add(jbCancel, "spanx, split 2, tag cancel");
            pane.add(jbOK, "tag ok");
        } else {
            pane.add(jbOK, "spanx, tag ok");
        }

        jbUpdate.addActionListener(evt -> updatePressed());

        jbOK.addActionListener(evt -> okPressed());

        jbCancel.addActionListener(evt -> cancelPressed());

        setResizable(false);

        populateDialog();

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

    private void populateDialog() {
        KeyInfo keyInfo = SecretKeyUtil.getKeyInfo(password);

        String algorithm = keyInfo.getAlgorithm();

        // Try and get friendly algorithm name
        PasswordType passwordType = PasswordType.resolveJce(algorithm);

        if (passwordType != null) {
            algorithm = passwordType.friendly();
        }

        jtfAlgorithm.setText(algorithm);

        jpfPassword.setText(new String(password.getEncoded()));
        jpfPassword.setCaretPosition(0);
    }

    private void updatePressed() {
        Password password = new Password(jpfPassword.getPassword());
        DChangePassword dChangePassword = new DChangePassword(this, DEFAULT_MODALITY_TYPE, password, preferences);
        dChangePassword.setLocationRelativeTo(this);
        dChangePassword.setVisible(true);

        newPassword = dChangePassword.getNewPassword();
        if (newPassword != null) {
            jpfPassword.setText(new String(newPassword.toCharArray()));
        }
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void okPressed() {

        if (editable && newPassword != null) {
            byte[] newKeyRaw = newPassword.toByteArray();
            this.password = new SecretKeySpec(newKeyRaw, 0, newKeyRaw.length, password.getAlgorithm());
            this.keyHasChanged = true;
        }

        closeDialog();
    }

    /**
     *
     * @return True if the password has changed.
     */
    public boolean keyHasChanged() {
        return keyHasChanged;
    }

    /**
     *
     * @return The password as a SecretKey.
     */
    public SecretKey getSecretKey() {
        return password;
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick UI testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        byte[] password = "DemoPassword".getBytes();
        final SecretKey secretKey = new SecretKeySpec(password, 0, password.length, PasswordType.PBEWITHHMACSHA256.jce());
        DViewPassword dialog = new DViewPassword(new JFrame(), "View Password Details", secretKey, true);
        DialogViewer.run(dialog);
    }
}
