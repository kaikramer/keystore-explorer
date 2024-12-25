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

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.kse.gui.components.JEscDialog;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used for entering and confirming a password and checking it against an
 * old password which may or may not have been supplied to the dialog.
 */
public class DChangePassword extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/password/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlOld;
    private JPasswordField jpfOld;
    private JLabel jlFirst;
    private JComponent jpfFirst;
    private JLabel jlConfirm;
    private JPasswordField jpfConfirm;
    private JButton jbOK;
    private JButton jbCancel;

    private Password newPassword;
    private Password oldPassword;
    private final KsePreferences preferences;

    /**
     * Creates new DChangePassword dialog where the parent is a frame.
     *
     * @param parent                Parent frame
     * @param modality              The dialog's title
     * @param oldPassword           The password to be changed
     * @param preferences           Preferences
     */
    public DChangePassword(JFrame parent, ModalityType modality, Password oldPassword,
                           KsePreferences preferences) {
        this(parent, modality, res.getString("DChangePassword.Title"), oldPassword, preferences);
    }

    /**
     * Creates new DChangePassword dialog where the parent is a frame.
     *
     * @param parent                Parent frame
     * @param modality              The dialog's title
     * @param title                 Is dialog modal?
     * @param oldPassword           The password to be changed
     * @param preferences           Preferences
     */
    public DChangePassword(JFrame parent, ModalityType modality, String title, Password oldPassword,
                           KsePreferences preferences) {
        super(parent, title, modality);
        this.oldPassword = oldPassword;
        this.preferences = preferences;
        initComponents();
    }

    /**
     * Creates new DChangePassword dialog where the parent is a dialog.
     *
     * @param parent                Parent frame
     * @param modality              Dialog modality
     * @param oldPassword           The password to be changed
     * @param preferences           Preferences
     */
    public DChangePassword(JDialog parent, ModalityType modality, Password oldPassword,
                           KsePreferences preferences) {
        this(parent, res.getString("DChangePassword.Title"), modality, oldPassword, preferences);
    }

    /**
     * Creates new DChangePassword dialog where the parent is a dialog.
     *
     * @param parent                Parent frame
     * @param title                 The dialog's title
     * @param modality              Dialog modality
     * @param oldPassword           The password to be changed
     * @param preferences           Preferences
     */
    public DChangePassword(JDialog parent, String title, ModalityType modality, Password oldPassword,
                           KsePreferences preferences) {
        super(parent, title, modality);
        this.oldPassword = oldPassword;
        this.preferences = preferences;
        initComponents();
    }

    private void initComponents() {
        getContentPane().setLayout(new BorderLayout());

        jlOld = new JLabel(res.getString("DChangePassword.jlOld.text"));

        if (oldPassword != null) {
            jpfOld = new JPasswordField("1234567890", 15);
            jpfOld.setEnabled(false);
        } else {
            jpfOld = new JPasswordField(15);
        }

        jlFirst = new JLabel(res.getString("DChangePassword.jlFirst.text"));

        jpfFirst = createPasswordInputField(preferences.getPasswordQualityConfig());

        jlConfirm = new JLabel(res.getString("DChangePassword.jlConfirm.text"));

        jpfConfirm = new JPasswordField(15);
        jpfConfirm.putClientProperty("JPasswordField.cutCopyAllowed", true);

        if (preferences.getPasswordGeneratorSettings().isEnabled()) {
            preFillPasswordFields(jpfFirst, jpfConfirm);
        }

        jbOK = new JButton(res.getString("DChangePassword.jbOK.text"));

        jbCancel = new JButton(res.getString("DChangePassword.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]rel[grow]", ""));
        pane.add(jlOld, "");
        pane.add(jpfOld, "growx, wrap");
        pane.add(jlFirst, "");
        pane.add(jpfFirst, "growx, wrap");
        pane.add(jlConfirm, "");
        pane.add(jpfConfirm, "growx, wrap unrel");
        pane.add(new JSeparator(), "spanx, growx, wrap unrelated");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        jbOK.addActionListener(evt -> okPressed());

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
    }

    /**
     * Get the new password set in the dialog.
     *
     * @return The new password or null if none was set
     */
    public Password getNewPassword() {
        return newPassword;
    }

    /**
     * Get the old password set in the dialog.
     *
     * @return The old password or null if none was set/supplied
     */
    public Password getOldPassword() {
        return oldPassword;
    }

    private boolean checkPassword() {
        Password oldPassword = new Password(jpfOld.getPassword());

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
            this.oldPassword = oldPassword;
            newPassword = firstPassword;
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

    public static void main(String[] args) throws Exception {
        KsePreferences ksePreferences = new KsePreferences();
        ksePreferences.setPasswordQualityConfig(new PasswordQualityConfig(false, false, 20));
        DialogViewer.run(new DChangePassword(new JFrame(), ModalityType.APPLICATION_MODAL,
                                             new Password("123456".toCharArray()),
                                             ksePreferences));
    }
}
