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
package org.kse.gui.passwordmanager;

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
import javax.swing.SwingUtilities;

import org.kse.gui.components.JEscDialog;
import org.kse.gui.components.JMultiLineLabel;
import org.kse.gui.password.JPasswordQualityField;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used for initialising the KSE Password Manager
 */
public class DInitPasswordManager extends JEscDialog {
    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/passwordmanager/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JMultiLineLabel jmllExplanations;
    private JLabel jlFirst;
    private JComponent jpfFirst;
    private JLabel jlConfirm;
    private JPasswordField jpfConfirm;
    private JButton jbOK;
    private JButton jbCancel;

    private PasswordQualityConfig passwordQualityConfig;
    private Password password;

    /**
     * Creates new DInitPasswordManager dialog where the parent is a frame.
     *
     * @param parent                Parent frame
     * @param passwordQualityConfig Password quality configuration
     */
    public DInitPasswordManager(JFrame parent, PasswordQualityConfig passwordQualityConfig) {
        super(parent, res.getString("DInitPasswordManager.Title"), ModalityType.DOCUMENT_MODAL);
        this.passwordQualityConfig = passwordQualityConfig;
        initComponents();
    }

    /**
     * Creates new DInitPasswordManager dialog where the parent is a dialog.
     *
     * @param parent                Parent dialog
     * @param passwordQualityConfig Password quality configuration
     */
    public DInitPasswordManager(JDialog parent, PasswordQualityConfig passwordQualityConfig) {
        super(parent, res.getString("DInitPasswordManager.Title"), ModalityType.DOCUMENT_MODAL);
        this.passwordQualityConfig = passwordQualityConfig;
        initComponents();
    }

    private void initComponents() {
        jmllExplanations = new JMultiLineLabel(res.getString("DInitPasswordManager.jmllExplanations.text"));

        jlFirst = new JLabel(res.getString("DInitPasswordManager.jlFirst.text"));
        jpfFirst = createPasswordInputField(passwordQualityConfig);

        jlConfirm = new JLabel(res.getString("DInitPasswordManager.jlConfirm.text"));
        jpfConfirm = new JPasswordField(15);
        jpfConfirm.putClientProperty("JPasswordField.cutCopyAllowed", true);

        jbOK = new JButton(res.getString("DInitPasswordManager.jbOK.text"));

        jbCancel = new JButton(res.getString("DInitPasswordManager.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]rel[grow]", ""));
        pane.add(jmllExplanations, "growx, spanx, wrap unrelated");
        pane.add(jlFirst, "");
        pane.add(jpfFirst, "growx, wrap 0");
        pane.add(jlConfirm, "");
        pane.add(jpfConfirm, "growx, wrap related");
        pane.add(new JSeparator(), "spanx, growx, wrap related");
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

    private JComponent createPasswordInputField(PasswordQualityConfig passwordQualityConfig) {
        if (passwordQualityConfig.getEnabled()) {
            if (passwordQualityConfig.getEnforced()) {
                return new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
            } else {
                return new JPasswordQualityField(15);
            }
        } else {
            JPasswordField jPasswordField = new JPasswordField(15);
            jPasswordField.putClientProperty("JPasswordField.cutCopyAllowed", true);
            return jPasswordField;
        }

    }

    /**
     * Get the password set in the dialog.
     *
     * @return The password or null if none was set
     */
    public Password getPassword() {
        return password;
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
        DialogViewer.run(new DInitPasswordManager(new JFrame(), new PasswordQualityConfig(false, false, 20)));
    }
}
