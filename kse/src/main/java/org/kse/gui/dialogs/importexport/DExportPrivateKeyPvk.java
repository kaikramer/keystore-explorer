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
package org.kse.gui.dialogs.importexport;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.password.JPasswordQualityField;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.io.FileNameUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export a private key from a KeyStore entry
 * as PVK.
 */
public class DExportPrivateKeyPvk extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlKeyType;
    private JRadioButton jrbExchange;
    private JRadioButton jrbSignature;
    private JLabel jlEncrypt;
    private JLabel jlEncryptionStrength;
    private JRadioButton jrbStrong;
    private JRadioButton jrbWeak;
    private JCheckBox jcbEncrypt;
    private JLabel jlPassword;
    private JComponent jpfPassword;
    private JLabel jlConfirmPassword;
    private JPasswordField jpfConfirmPassword;
    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JPanel jpButtons;
    private JButton jbExport;
    private JButton jbCancel;

    private String entryAlias;
    private PrivateKey privateKey;
    private PasswordQualityConfig passwordQualityConfig;
    private boolean exportSelected = false;
    private File exportFile;
    private int keyType;
    private boolean encrypt;
    private boolean strongEncryption;
    private Password exportPassword;

    /**
     * Creates a new DExportPrivateKeyPvk dialog.
     *
     * @param parent                The parent frame
     * @param entryAlias            The KeyStore entry to export private key from
     * @param privateKey            Private key to export from
     * @param passwordQualityConfig Password quality configuration
     */
    public DExportPrivateKeyPvk(JFrame parent, String entryAlias, PrivateKey privateKey,
                                PasswordQualityConfig passwordQualityConfig) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);

        this.entryAlias = entryAlias;
        this.privateKey = privateKey;
        this.passwordQualityConfig = passwordQualityConfig;

        initComponents();
    }

    private void initComponents() {
        jlKeyType = new JLabel(res.getString("DExportPrivateKeyPvk.jlKeyType.text"));

        jrbExchange = new JRadioButton(res.getString("DExportPrivateKeyPvk.jrbExchange.text"));
        jrbExchange.setToolTipText(res.getString("DExportPrivateKeyPvk.jrbExchange.tooltip"));
        PlatformUtil.setMnemonic(jrbExchange, res.getString("DExportPrivateKeyPvk.jrbExchange.mnemonic").charAt(0));
        jrbExchange.setSelected(true);

        jrbSignature = new JRadioButton(res.getString("DExportPrivateKeyPvk.jrbSignature.text"));
        jrbSignature.setToolTipText(res.getString("DExportPrivateKeyPvk.jrbSignature.tooltip"));
        PlatformUtil.setMnemonic(jrbSignature, res.getString("DExportPrivateKeyPvk.jrbSignature.mnemonic").charAt(0));

        ButtonGroup keyTypes = new ButtonGroup();
        keyTypes.add(jrbExchange);
        keyTypes.add(jrbSignature);

        if (privateKey instanceof DSAPrivateKey) {
            jrbSignature.setSelected(true);

            jrbExchange.setEnabled(false);
            jrbSignature.setEnabled(false);
        }

        jlEncrypt = new JLabel(res.getString("DExportPrivateKeyPvk.jlEncrypt.text"));

        jcbEncrypt = new JCheckBox();
        jcbEncrypt.setSelected(true);
        jcbEncrypt.setToolTipText(res.getString("DExportPrivateKeyPvk.jcbEncrypt.tooltip"));

        jlEncryptionStrength = new JLabel(res.getString("DExportPrivateKeyPvk.jlEncryptionStrength.text"));

        jrbStrong = new JRadioButton(res.getString("DExportPrivateKeyPvk.jrbStrong.text"));
        jrbStrong.setToolTipText(res.getString("DExportPrivateKeyPvk.jrbStrong.tooltip"));
        PlatformUtil.setMnemonic(jrbStrong, res.getString("DExportPrivateKeyPvk.jrbStrong.mnemonic").charAt(0));
        jrbStrong.setSelected(true);

        jrbWeak = new JRadioButton(res.getString("DExportPrivateKeyPvk.jrbWeak.text"));
        jrbWeak.setToolTipText(res.getString("DExportPrivateKeyPvk.jrbWeak.tooltip"));
        PlatformUtil.setMnemonic(jrbWeak, res.getString("DExportPrivateKeyPvk.jrbWeak.mnemonic").charAt(0));

        ButtonGroup encryptionStrengths = new ButtonGroup();
        encryptionStrengths.add(jrbStrong);
        encryptionStrengths.add(jrbWeak);

        jlPassword = new JLabel(res.getString("DExportPrivateKeyPvk.jlPassword.text"));

        if (passwordQualityConfig.getEnabled()) {
            if (passwordQualityConfig.getEnforced()) {
                jpfPassword = new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
            } else {
                jpfPassword = new JPasswordQualityField(15);
            }
        } else {
            jpfPassword = new JPasswordField(15);
        }

        jpfPassword.setToolTipText(res.getString("DExportPrivateKeyPvk.jpqfPassword.tooltip"));

        jlConfirmPassword = new JLabel(res.getString("DExportPrivateKeyPvk.jlConfirmPassword.text"));

        jpfConfirmPassword = new JPasswordField(15);
        jpfConfirmPassword.setToolTipText(res.getString("DExportPrivateKeyPvk.jpfConfirmPassword.tooltip"));

        jlExportFile = new JLabel(res.getString("DExportPrivateKeyPvk.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportPrivateKeyPvk.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportPrivateKeyPvk.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportPrivateKeyPvk.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportPrivateKeyPvk.jbBrowse.mnemonic").charAt(0));

        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyPvk.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyPvk.this);
            }
        });

        jcbEncrypt.addItemListener(evt -> {
            if (jcbEncrypt.isSelected()) {
                jrbStrong.setEnabled(true);
                jrbWeak.setEnabled(true);
                jpfPassword.setEnabled(true);
                jpfConfirmPassword.setEnabled(true);
            } else {
                jrbStrong.setEnabled(false);
                jrbWeak.setEnabled(false);
                jpfPassword.setEnabled(false);
                if (jpfPassword instanceof JPasswordQualityField) {
                    ((JPasswordQualityField) jpfPassword).setPassword("");
                } else {
                    ((JPasswordField) jpfPassword).setText("");
                }
                jpfConfirmPassword.setEnabled(false);
                jpfConfirmPassword.setText("");
            }
        });

        jbExport = new JButton(res.getString("DExportPrivateKeyPvk.jbExport.text"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DExportPrivateKeyPvk.jbExport.mnemonic").charAt(0));
        jbExport.setToolTipText(res.getString("DExportPrivateKeyPvk.jbExport.tooltip"));
        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyPvk.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyPvk.this);
            }
        });

        jbCancel = new JButton(res.getString("DExportPrivateKeyPvk.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        jpButtons = PlatformUtil.createDialogButtonPanel(jbExport, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));
        pane.add(jlKeyType, "");
        pane.add(jrbExchange, "split 2");
        pane.add(jrbSignature, "wrap");
        pane.add(jlEncrypt, "");
        pane.add(jcbEncrypt, "wrap");
        pane.add(jlEncryptionStrength, "");
        pane.add(jrbStrong, "split 2");
        pane.add(jrbWeak, "wrap");
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "wrap");
        pane.add(jlConfirmPassword, "");
        pane.add(jpfConfirmPassword, "wrap");
        pane.add(jlExportFile, "");
        pane.add(jtfExportFile, "");
        pane.add(jbBrowse, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "right, spanx");

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed();
            }
        });

        setTitle(MessageFormat.format(res.getString("DExportPrivateKeyPvk.Title"), entryAlias));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
        File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.PVK_EXT);
        jtfExportFile.setText(csrFile.getPath());
    }

    /**
     * Has the user chosen to export?
     *
     * @return True if they have
     */
    public boolean exportSelected() {
        return exportSelected;
    }

    /**
     * Get chosen export file.
     *
     * @return Export file
     */
    public File getExportFile() {
        return exportFile;
    }

    /**
     * Get chosen key type.
     *
     * @return PvkPrivateKeyUtil.PVK_KEY_EXCHANGE or
     *         PvkPrivateKeyUtil.PVK_KEY_SIGNATURE.
     */
    public int getKeyType() {
        return keyType;
    }

    /**
     * Encrypt exported private key?
     *
     * @return True if encryption selected
     */
    public boolean encrypt() {
        return encrypt;
    }

    /**
     * Use strong encryption for exported key?
     *
     * @return True if strong encryption selected
     */
    public boolean useStrongEncryption() {
        return strongEncryption;
    }

    /**
     * Get export encryption password.
     *
     * @return Export password
     */
    public Password getExportPassword() {
        return exportPassword;
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getPvkFileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportPrivateKeyPvk.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                       chooser.showSaveDialog(this) :
                       chooser.showDialog(this, res.getString("DExportPrivateKeyPvk.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
        }
    }

    private void exportPressed() {
        if (jrbExchange.isSelected()) {
            keyType = MsPvkUtil.PVK_KEY_EXCHANGE;
        } else {
            keyType = MsPvkUtil.PVK_KEY_SIGNATURE;
        }

        encrypt = jcbEncrypt.isSelected();

        if (encrypt) {
            strongEncryption = jrbStrong.isSelected();

            Password firstPassword;

            if (jpfPassword instanceof JPasswordQualityField) {
                char[] firstPasswordChars = ((JPasswordQualityField) jpfPassword).getPassword();

                if (firstPasswordChars == null) {
                    JOptionPane.showMessageDialog(this, res.getString(
                                                          "DExportPrivateKeyPvk.MinimumPasswordQualityNotMet.message"),
                                                  res.getString("DExportPrivateKeyPvk.Simple.Title"),
                                                  JOptionPane.WARNING_MESSAGE);
                    return;
                }

                firstPassword = new Password(firstPasswordChars);
            } else {
                firstPassword = new Password(((JPasswordField) jpfPassword).getPassword());
            }

            Password confirmPassword = new Password(jpfConfirmPassword.getPassword());

            if (firstPassword.equals(confirmPassword)) {
                exportPassword = firstPassword;
            } else {
                JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyPvk.PasswordsNoMatch.message"),
                                              res.getString("DExportPrivateKeyPvk.Simple.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        String exportFileChars = jtfExportFile.getText().trim();

        if (exportFileChars.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyPvk.ExportFileRequired.message"),
                                          res.getString("DExportPrivateKeyPvk.Simple.Title"),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileChars);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportPrivateKeyPvk.OverWriteExportFile.message"),
                                                  exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message,
                                                         res.getString("DExportPrivateKeyPvk.Simple.Title"),
                                                         JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return;
            }
        }

        this.exportFile = exportFile;

        exportSelected = true;

        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
