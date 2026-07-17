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
 *
 */

package org.kse.gui.dialogs.importexport;

import static org.kse.gui.FileChooserFactory.JWK_EXT;
import static org.kse.gui.FileChooserFactory.OPENSSL_PVK_EXT;

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
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.password.JPasswordQualityField;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

import com.nimbusds.jose.JWEAlgorithm;
import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export a private key from a KeyStore entry as JWK.
 */
public class DExportPrivateKeyJwk extends JEscDialog {
    private static final long serialVersionUID = 1L;

    public static final String JWK_FILE_EXT = '.' + OPENSSL_PVK_EXT + '.' + JWK_EXT;
    private static final String CANCEL_KEY = "CANCEL_KEY";

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");

    private JLabel jlEncrypt;
    private JCheckBox jcbEncrypt;
    private JLabel jlJweAlg;
    private JComboBox<JWEAlgorithm> jcbJweAlg;
    private JLabel jlPassword;
    private JComponent jpfPassword;
    private JLabel jlConfirmPassword;
    private JPasswordField jpfConfirmPassword;
    private JRadioButton jrbFmtJson;
    private JRadioButton jrbFmtCompact;
    private ButtonGroup buttonGroup;
    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JButton jbExport;
    private JButton jbCancel;

    private final String entryAlias;
    private PasswordQualityConfig passwordQualityConfig;
    private File exportFile;
    private boolean exportSelected;
    private boolean encrypt;
    private JWEAlgorithm jweAlgorithm;
    private Password exportPassword;
    private boolean jwkCompactFormat;

    /**
     * Creates a new DExportPrivateKeyJwk dialog.
     *
     * @param parent                The parent frame
     * @param entryAlias            The KeyStore entry to export private key from
     * @param passwordQualityConfig Password quality configuration
     */
    public DExportPrivateKeyJwk(JFrame parent, String entryAlias, PasswordQualityConfig passwordQualityConfig) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.entryAlias = entryAlias;
        this.passwordQualityConfig = passwordQualityConfig;
        initComponents();
    }

    private void initComponents() {

        jlEncrypt = new JLabel(res.getString("DExportPrivateKeyJwk.jlEncrypt.text"));

        jcbEncrypt = new JCheckBox();
        jcbEncrypt.setSelected(true);
        jcbEncrypt.setToolTipText(res.getString("DExportPrivateKeyJwk.jcbEncrypt.tooltip"));

        jlJweAlg = new JLabel(res.getString("DExportPrivateKeyJwk.jlJweAlg.text"));

        jcbJweAlg = new JComboBox<>();
        populatePbeAlgs();
        jcbJweAlg.setToolTipText(res.getString("DExportPrivateKeyJwk.jcbJweAlg.tooltip"));

        jlPassword = new JLabel(res.getString("DExportPrivateKeyJwk.jlPassword.text"));

        if (passwordQualityConfig.getEnabled()) {
            if (passwordQualityConfig.getEnforced()) {
                jpfPassword = new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
            } else {
                jpfPassword = new JPasswordQualityField(15);
            }
        } else {
            jpfPassword = new JPasswordField(15);
        }

        jpfPassword.setToolTipText(res.getString("DExportPrivateKeyJwk.jpqfPassword.tooltip"));

        jlConfirmPassword = new JLabel(res.getString("DExportPrivateKeyJwk.jlConfirmPassword.text"));

        jpfConfirmPassword = new JPasswordField(15);
        jpfConfirmPassword.setToolTipText(res.getString("DExportPrivateKeyJwk.jpfConfirmPassword.tooltip"));

        jrbFmtJson = new JRadioButton(res.getString("DExportPrivateKeyJwk.jrbFmtJson.text"));
        jrbFmtJson.setToolTipText(res.getString("DExportPrivateKeyJwk.jrbFmtJson.tooltip"));

        jrbFmtCompact = new JRadioButton(res.getString("DExportPrivateKeyJwk.jrbFmtCompact.text"));
        jrbFmtCompact.setToolTipText(res.getString("DExportPrivateKeyJwk.jrbFmtCompact.tooltip"));

        buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbFmtJson);
        buttonGroup.add(jrbFmtCompact);
        jrbFmtJson.setSelected(true);

        jlExportFile = new JLabel(res.getString("DExportPrivateKeyJwk.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportPrivateKeyJwk.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportPrivateKeyJwk.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportPrivateKeyJwk.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportPrivateKeyJwk.jbBrowse.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DExportPrivateKeyJwk.jbExport.text"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DExportPrivateKeyJwk.jbExport.mnemonic").charAt(0));
        jbExport.setToolTipText(res.getString("DExportPrivateKeyJwk.jbExport.tooltip"));

        jbCancel = new JButton(res.getString("DExportPrivateKeyJwk.jbCancel.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
        pane.add(jlEncrypt, "");
        pane.add(jcbEncrypt, "wrap");
        pane.add(jlJweAlg, "");
        pane.add(jcbJweAlg, "growx, pushx, wrap");
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "wrap");
        pane.add(jlConfirmPassword, "");
        pane.add(jpfConfirmPassword, "wrap");
        pane.add(new JLabel("Format:"), "");
        pane.add(jrbFmtJson, "split 2");
        pane.add(jrbFmtCompact, "wrap");
        pane.add(jlExportFile, "");
        pane.add(jtfExportFile, "");
        pane.add(jbBrowse, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jbExport, "right, spanx, split, tag ok");
        pane.add(jbCancel, "tag cancel");

        // actions

        jcbEncrypt.addItemListener(evt -> {
            jcbJweAlg.setEnabled(jcbEncrypt.isSelected());
            jpfPassword.setEnabled(jcbEncrypt.isSelected());
            jpfConfirmPassword.setEnabled(jcbEncrypt.isSelected());
            jrbFmtCompact.setEnabled(jcbEncrypt.isSelected());
            jrbFmtJson.setEnabled(jcbEncrypt.isSelected());
            if (!jcbEncrypt.isSelected()) {
                if (jpfPassword instanceof JPasswordQualityField) {
                    ((JPasswordQualityField) jpfPassword).setPassword("");
                } else {
                    ((JPasswordField) jpfPassword).setText("");
                }
                jpfConfirmPassword.setText("");
            }
        });

        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyJwk.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyJwk.this);
            }
        });

        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyJwk.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyJwk.this);
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
                cancelPressed();
            }
        });

        setTitle(MessageFormat.format(res.getString("DExportPrivateKeyJwk.Title"), entryAlias));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
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
     * Get JWE algorithm used for encryption.
     *
     * @return JWE algorithm
     */
    public JWEAlgorithm getJweAlgorithm() {
        return jweAlgorithm;
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
     * Was the option to use the compact format selected?
     *
     * @return True if it was
     */
    public boolean compactFormat() {
        return jwkCompactFormat;
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
        File csrFile = new File(currentDirectory, sanitizedAlias + JWK_FILE_EXT);
        jtfExportFile.setText(csrFile.getPath());
    }

    private void populatePbeAlgs() {

        for (JWEAlgorithm jweAlg : JWEAlgorithm.Family.PBES2) {
            jcbJweAlg.addItem(jweAlg);
        }

        jcbJweAlg.setSelectedItem(JWEAlgorithm.PBES2_HS256_A128KW);
    }

    private void exportPressed() {
        encrypt = jcbEncrypt.isSelected();

        if (encrypt) {
            jweAlgorithm = (JWEAlgorithm) jcbJweAlg.getSelectedItem();

            Password firstPassword;

            if (jpfPassword instanceof JPasswordQualityField) {
                char[] firstPasswordChars = ((JPasswordQualityField) jpfPassword).getPassword();

                if (firstPasswordChars == null) {
                    JOptionPane.showMessageDialog(this, res.getString(
                                                          "DExportPrivateKeyJwk.MinimumPasswordQualityNotMet.message"),
                                                  res.getString("DExportPrivateKeyJwk.Simple.Title"),
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
                JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyJwk.PasswordsNoMatch.message"),
                                              res.getString("DExportPrivateKeyJwk.Simple.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        jwkCompactFormat = jrbFmtCompact.isSelected();

        String exportFileChars = jtfExportFile.getText().trim();

        if (exportFileChars.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyJwk.ExportFileRequired.message"),
                    res.getString("DExportPrivateKeyJwk.Simple.Title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileChars);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportPrivateKeyJwk.OverWriteExportFile.message"),
                    exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message,
                    res.getString("DExportPrivateKeyJwk.Simple.Title"),
                    JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return;
            }
        }

        this.exportFile = exportFile;

        exportSelected = true;

        closeDialog();
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getOpenSslPvkFileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportPrivateKeyJwk.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                chooser.showSaveDialog(this) :
                chooser.showDialog(this, res.getString("DExportPrivateKeyJwk.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
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
        DialogViewer.run(new DExportPrivateKeyJwk(new JFrame(), "alias", new PasswordQualityConfig(false, false, 1)));
    }
}
