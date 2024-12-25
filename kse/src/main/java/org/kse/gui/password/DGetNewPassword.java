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
package org.kse.gui.password;

import static org.kse.gui.password.PasswordDialogHelper.createPasswordInputField;
import static org.kse.gui.password.PasswordDialogHelper.preFillPasswordFields;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.kse.gui.components.JEscDialog;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used for entering and confirming a password.
 */
public class DGetNewPassword extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/password/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlFirst;
    private JComponent jpfFirst;
    private JLabel jlConfirm;
    private JPasswordField jpfConfirm;
    private JCheckBox jcbStoreInPasswordManager;
    private JButton jbOK;
    private JButton jbCancel;

    private KsePreferences preferences;
    private boolean askUserForPasswordManager = false;
    private Password password;

    /**
     * Creates new DGetNewPassword dialog where the parent is a frame.
     *
     * @param parent      Parent frame
     * @param title       The dialog's title
     * @param preferences Preferences
     */
    public DGetNewPassword(JFrame parent, String title, KsePreferences preferences) {
        this(parent, title, preferences, false);
    }

    /**
     * Creates new DGetNewPassword dialog where the parent is a frame.
     *
     * @param parent      Parent frame
     * @param title       The dialog's title
     * @param preferences Preferences
     * @param askUserForPasswordManager Whether to show the checkbox asking the user if they want to use the pwd-mgr
     */
    public DGetNewPassword(JFrame parent, String title, KsePreferences preferences,
                           boolean askUserForPasswordManager) {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        this.preferences = preferences;
        this.askUserForPasswordManager = askUserForPasswordManager;
        initComponents();
    }

    /**
     * Creates new DGetNewPassword dialog where the parent is a dialog.
     *
     * @param parent      Parent dialog
     * @param title       The dialog's title
     * @param modality    Dialog modality
     * @param preferences Preferences
     */
    public DGetNewPassword(JDialog parent, String title, Dialog.ModalityType modality,
                           KsePreferences preferences) {
        super(parent, title, modality);
        this.preferences = preferences;
        initComponents();
    }

    private void initComponents() {
        jlFirst = new JLabel(res.getString("DGetNewPassword.jlFirst.text"));
        jpfFirst = createPasswordInputField(preferences.getPasswordQualityConfig());

        jlConfirm = new JLabel(res.getString("DGetNewPassword.jlConfirm.text"));
        jpfConfirm = new JPasswordField(15);
        jpfConfirm.putClientProperty("JPasswordField.cutCopyAllowed", true);

        if (preferences.getPasswordGeneratorSettings().isEnabled()) {
            preFillPasswordFields(jpfFirst, jpfConfirm);
        }

        jbOK = new JButton(res.getString("DGetNewPassword.jbOK.text"));

        jbCancel = new JButton(res.getString("DGetNewPassword.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        jcbStoreInPasswordManager = new JCheckBox(res.getString("DGetNewPassword.jcbStoreInPasswordManager.text"));
        jcbStoreInPasswordManager.setSelected(true);
        jcbStoreInPasswordManager.setVisible(askUserForPasswordManager);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]rel[grow]", ""));
        pane.add(jlFirst, "");
        pane.add(jpfFirst, "wrap, growx");
        pane.add(jlConfirm, "");
        pane.add(jpfConfirm, "growx, wrap unrelated");
        pane.add(jcbStoreInPasswordManager, "hidemode 3, split 2, spanx, growx, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap unrelated");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

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
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jpfFirst.requestFocus());
    }

    /**
     * Get the password set in the dialog.
     *
     * @return The password or null if none was set
     */
    public Password getPassword() {
        return password;
    }

    /**
     * Return whether user wants to use password manager or not
     * @return True if password manager is requested
     */
    public boolean isPasswordManagerWanted() {
        return jcbStoreInPasswordManager.isSelected();
    }

    private boolean checkPassword() {
        Password firstPassword;

        if (jpfFirst instanceof JPasswordQualityField) {
            char[] firstPasswordChars = ((JPasswordQualityField) jpfFirst).getPassword();

            if (firstPasswordChars == null) {
                JOptionPane.showMessageDialog(this, res.getString("MinimumPasswordQualityNotMet.message"), getTitle(),
                                              JOptionPane.WARNING_MESSAGE);
                return false;
            }

            firstPassword = new Password(firstPasswordChars);
        } else {
            firstPassword = new Password(((JPasswordField) jpfFirst).getPassword());
        }

        Password confirmPassword = new Password(jpfConfirm.getPassword());

        if (firstPassword.equals(confirmPassword)) {
            password = firstPassword;
            return true;
        }

        JOptionPane.showMessageDialog(this, res.getString("PasswordsNoMatch.message"), getTitle(),
                                      JOptionPane.WARNING_MESSAGE);

        return false;
    }

    private void okPressed() {
        if (checkPassword()) {
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
        KsePreferences ksePreferences = new KsePreferences();
        ksePreferences.setPasswordQualityConfig(new PasswordQualityConfig(false, false, 20));
        DialogViewer.run(new DGetNewPassword(new javax.swing.JFrame(), "New Password", ksePreferences, true));
    }
}
