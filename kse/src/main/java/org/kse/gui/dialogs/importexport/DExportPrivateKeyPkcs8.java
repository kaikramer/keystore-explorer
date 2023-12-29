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
package org.kse.gui.dialogs.importexport;

import static org.kse.gui.FileChooserFactory.P8_EXT;
import static org.kse.gui.FileChooserFactory.PEM_EXT;
import static org.kse.gui.FileChooserFactory.getPkcs8FileChooser;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.crypto.Password;
import org.kse.crypto.privatekey.Pkcs8PbeType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.password.JPasswordQualityField;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export a private key from a KeyStore entry
 * as PKCS #8.
 */
public class DExportPrivateKeyPkcs8 extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");

    public static final String PEM_FILE_EXT = "." + P8_EXT + "." + PEM_EXT;
    public static final String NON_PEM_FILE_EXT = "." + P8_EXT;

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JPanel jpOptions;
    private JLabel jlEncrypt;
    private JCheckBox jcbEncrypt;
    private JLabel jlPbeAlg;
    private JComboBox<Pkcs8PbeType> jcbPbeAlg;
    private JLabel jlPassword;
    private JComponent jpfPassword;
    private JLabel jlConfirmPassword;
    private JPasswordField jpfConfirmPassword;
    private JLabel jlExportPem;
    private JCheckBox jcbExportPem;
    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JButton jbExport;
    private JButton jbCancel;

    private String entryAlias;
    private PasswordQualityConfig passwordQualityConfig;
    private boolean exportSelected = false;
    private File exportFile;
    private boolean encrypt;
    private Pkcs8PbeType pbeAlgorithm;
    private Password exportPassword;
    private boolean pemEncode;

    /**
     * Creates a new DExportPrivateKeyPkcs8 dialog.
     *
     * @param parent                The parent frame
     * @param entryAlias            The KeyStore entry to export private key from
     * @param passwordQualityConfig Password quality configuration
     */
    public DExportPrivateKeyPkcs8(JFrame parent, String entryAlias, PasswordQualityConfig passwordQualityConfig) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.entryAlias = entryAlias;
        this.passwordQualityConfig = passwordQualityConfig;
        initComponents();
    }

    private void initComponents() {
        jlEncrypt = new JLabel(res.getString("DExportPrivateKeyPkcs8.jlEncrypt.text"));

        jcbEncrypt = new JCheckBox();
        jcbEncrypt.setSelected(true);
        jcbEncrypt.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jcbEncrypt.tooltip"));

        jlPbeAlg = new JLabel(res.getString("DExportPrivateKeyPkcs8.jlPbeAlg.text"));

        jcbPbeAlg = new JComboBox<>();
        populatePbeAlgs();
        jcbPbeAlg.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jcbPbeAlg.tooltip"));
        jcbPbeAlg.setSelectedIndex(0);

        jlPassword = new JLabel(res.getString("DExportPrivateKeyPkcs8.jlPassword.text"));

        if (passwordQualityConfig.getEnabled()) {
            if (passwordQualityConfig.getEnforced()) {
                jpfPassword = new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
            } else {
                jpfPassword = new JPasswordQualityField(15);
            }
        } else {
            jpfPassword = new JPasswordField(15);
        }

        jpfPassword.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jpqfPassword.tooltip"));

        jlConfirmPassword = new JLabel(res.getString("DExportPrivateKeyPkcs8.jlConfirmPassword.text"));

        jpfConfirmPassword = new JPasswordField(15);
        jpfConfirmPassword.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jpfConfirmPassword.tooltip"));

        jlExportPem = new JLabel(res.getString("DExportPrivateKeyPkcs8.jlExportPem.text"));

        jcbExportPem = new JCheckBox();
        jcbExportPem.setSelected(true);
        jcbExportPem.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jcbExportPem.tooltip"));

        jlExportFile = new JLabel(res.getString("DExportPrivateKeyPkcs8.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportPrivateKeyPkcs8.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportPrivateKeyPkcs8.jbBrowse.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DExportPrivateKeyPkcs8.jbExport.text"));
        jbCancel = new JButton(res.getString("DExportPrivateKeyPkcs8.jbCancel.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));
        pane.add(jlEncrypt, "");
        pane.add(jcbEncrypt, "wrap");
        pane.add(jlPbeAlg, "");
        pane.add(jcbPbeAlg, "growx, pushx, wrap");
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "wrap");
        pane.add(jlConfirmPassword, "");
        pane.add(jpfConfirmPassword, "wrap");
        pane.add(jlExportPem, "");
        pane.add(jcbExportPem, "wrap");
        pane.add(jlExportFile, "");
        pane.add(jtfExportFile, "growx, split");
        pane.add(jbBrowse, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbExport, "right, spanx, split, tag ok");
        pane.add(jbCancel, "tag cancel");

        // actions

        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyPkcs8.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyPkcs8.this);
            }
        });

        jcbEncrypt.addItemListener(evt -> {
            if (jcbEncrypt.isSelected()) {
                jcbPbeAlg.setEnabled(true);
                jpfPassword.setEnabled(true);
                jpfConfirmPassword.setEnabled(true);
            } else {
                jcbPbeAlg.setEnabled(false);
                jpfPassword.setEnabled(false);
                if (jpfPassword instanceof JPasswordQualityField) {
                    ((JPasswordQualityField) jpfPassword).setText("");
                } else {
                    ((JPasswordField) jpfPassword).setText("");
                }
                jpfConfirmPassword.setEnabled(false);
                jpfConfirmPassword.setText("");
            }
        });

        PlatformUtil.setMnemonic(jbExport, res.getString("DExportPrivateKeyPkcs8.jbExport.mnemonic").charAt(0));
        jbExport.setToolTipText(res.getString("DExportPrivateKeyPkcs8.jbExport.tooltip"));
        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyPkcs8.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyPkcs8.this);
            }
        });

        jcbExportPem.addItemListener(evt -> {
            String currentFileName = jtfExportFile.getText();
            String pemFileExt = "." + PEM_EXT;
            // add or remove ".pem" depending on current selection of PEM checkbox
            if (jcbExportPem.isSelected() && !currentFileName.contains(pemFileExt)) {
                jtfExportFile.setText(currentFileName + pemFileExt);
            } else if (!jcbExportPem.isSelected() && currentFileName.contains(pemFileExt)) {
                jtfExportFile.setText(currentFileName.replaceAll(pemFileExt, ""));
            }
        });

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

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(MessageFormat.format(res.getString("DExportPrivateKeyPkcs8.Title"), entryAlias));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
        File csrFile = new File(currentDirectory, sanitizedAlias + PEM_FILE_EXT);
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
     * Encrypt exported private key?
     *
     * @return True if encryption selected
     */
    public boolean encrypt() {
        return encrypt;
    }

    /**
     * Get PBE algorithm used for encryption.
     *
     * @return PBE algorithm
     */
    public Pkcs8PbeType getPbeAlgorithm() {
        return pbeAlgorithm;
    }

    /**
     * Get export encryption password.
     *
     * @return Export password
     */
    public Password getExportPassword() {
        return exportPassword;
    }

    /**
     * Was the option to PEM encode selected?
     *
     * @return True if it was
     */
    public boolean pemEncode() {
        return pemEncode;
    }

    private void populatePbeAlgs() {
        Pkcs8PbeType[] pbeAlgs = Pkcs8PbeType.values();

        for (Pkcs8PbeType pbeAlg : pbeAlgs) {
            jcbPbeAlg.addItem(pbeAlg);
        }

        jcbPbeAlg.setSelectedItem(Pkcs8PbeType.PBES2_AES256_SHA256);
    }

    private void browsePressed() {
        JFileChooser chooser = getPkcs8FileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportPrivateKeyPkcs8.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                       chooser.showSaveDialog(this) :
                       chooser.showDialog(this, res.getString("DExportPrivateKeyPkcs8.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
        }
    }

    private void exportPressed() {
        encrypt = jcbEncrypt.isSelected();

        if (encrypt) {
            pbeAlgorithm = (Pkcs8PbeType) jcbPbeAlg.getSelectedItem();

            Password firstPassword;

            if (jpfPassword instanceof JPasswordQualityField) {
                char[] firstPasswordChars = ((JPasswordQualityField) jpfPassword).getPassword();

                if (firstPasswordChars == null) {
                    JOptionPane.showMessageDialog(this, res.getString(
                                                          "DExportPrivateKeyPkcs8.MinimumPasswordQualityNotMet.message"),
                                                  res.getString("DExportPrivateKeyPkcs8.Simple.Title"),
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
                JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyPkcs8.PasswordsNoMatch.message"),
                                              res.getString("DExportPrivateKeyPkcs8.Simple.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        pemEncode = jcbExportPem.isSelected();

        String exportFileStr = jtfExportFile.getText().trim();

        if (exportFileStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyPkcs8.ExportFileRequired.message"),
                                          res.getString("DExportPrivateKeyPkcs8.Simple.Title"),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileStr);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportPrivateKeyPkcs8.OverWriteExportFile.message"),
                                                  exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message,
                                                         res.getString("DExportPrivateKeyPkcs8.Simple.Title"),
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

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DExportPrivateKeyPkcs8(new JFrame(), "alias", new PasswordQualityConfig(false, false, 1)));
    }
}
