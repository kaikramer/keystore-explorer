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
package org.kse.gui.dialogs.importexport;

import static org.kse.gui.FileChooserFactory.*;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Window;
import java.awt.event.*;
import java.io.File;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.*;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export a public key from a KeyStore entry
 * as OpenSSL.
 */
public class DExportPublicKey extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");

    private static final String FULL_PEM_FILE_EXT = "." + PUBLIC_KEY_EXT + "." + PEM_EXT;
    private boolean isKeyExportableAsJWK;

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JRadioButton jrbExportOpenSsl;
    private JRadioButton jrbExportOpenSslPem;
    private JRadioButton jrbExportJwk;

    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JButton jbExport;
    private JButton jbCancel;

    private String entryAlias;
    private boolean exportSelected = false;
    private File exportFile;

    private PubkeyFormat selectedPubKeyFormat = PubkeyFormat.OPENSSL_PEM;

    /**
     * Creates a new DExportPublicKey dialog.
     *
     * @param parent               The parent frame or dialog
     * @param entryAlias           The KeyStore entry to export public key from
     * @param isKeyExportableAsJWK The JWK support for the public key
     */
    public DExportPublicKey(Window parent, String entryAlias, boolean isKeyExportableAsJWK) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.entryAlias = entryAlias;
        this.isKeyExportableAsJWK = isKeyExportableAsJWK;
        initComponents();
    }

    private void initComponents() {
        jrbExportOpenSslPem = new JRadioButton(res.getString("DExportPublicKey.jrbExportOpenSslPem.text"));
        jrbExportOpenSslPem.setSelected(true);
        jrbExportOpenSslPem.setName("jcbExportOpenSslPem");
        jrbExportOpenSslPem.setToolTipText(res.getString("DExportPublicKey.jrbExportOpenSslPem.tooltip"));

        jrbExportOpenSsl = new JRadioButton(res.getString("DExportPublicKey.jrbExportOpenSsl.text"));
        jrbExportOpenSsl.setSelected(false);
        jrbExportOpenSsl.setName("jrbExportOpenSsl");
        jrbExportOpenSsl.setToolTipText(res.getString("DExportPublicKey.jrbExportOpenSsl.tooltip"));

        jrbExportJwk = new JRadioButton(res.getString("DExportPublicKey.jrbExportJwk.text"));
        jrbExportJwk.setSelected(false);
        jrbExportJwk.setEnabled(isKeyExportableAsJWK);
        jrbExportJwk.setName("jrbExportJwk");
        jrbExportJwk.setToolTipText(res.getString("DExportPublicKey.jrbExportJwk.tooltip"));

        jlExportFile = new JLabel(res.getString("DExportPublicKey.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportPublicKey.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportPublicKey.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportPublicKey.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportPublicKey.jbBrowse.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DExportPublicKey.jbExport.text"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DExportPublicKey.jbExport.mnemonic").charAt(0));
        jbExport.setToolTipText(res.getString("DExportPublicKey.jbExport.tooltip"));

        jbCancel = new JButton(res.getString("DExportPublicKey.jbCancel.text"));

        ButtonGroup keyTypes = new ButtonGroup();
        keyTypes.add(jrbExportOpenSslPem);
        keyTypes.add(jrbExportOpenSsl);
        keyTypes.add(jrbExportJwk);

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[grow 0]0[grow]", "[]unrel[]"));

        // Add the radio buttons on the left, and keep the label and text field in the second column
        pane.add(jrbExportOpenSslPem, "cell 0 0, align left");
        pane.add(jrbExportOpenSsl, "cell 0 1, align left");
        pane.add(jrbExportJwk, "cell 0 2, align left");

        pane.add(jlExportFile, "cell 0 3, align left");
        pane.add(jtfExportFile, "cell 0 3, growx");
        pane.add(jbBrowse, "cell 0 3, align left, wrap");

        // Add separator and buttons
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbExport, "right, spanx, split 2, tag ok");
        pane.add(jbCancel, "tag cancel");

        // actions
        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPublicKey.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportPublicKey.this);
            }
        });

        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPublicKey.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportPublicKey.this);
            }
        });

        jrbExportOpenSslPem.addItemListener(evt -> {
            String currentFileName = jtfExportFile.getText();
            String pemFileExt = "." + PEM_EXT;
            // add or remove ".pem" depending on current selection of PEM checkbox
            if (jrbExportOpenSslPem.isSelected() && !currentFileName.contains(pemFileExt)) {
                jtfExportFile.setText(currentFileName + pemFileExt);
                selectedPubKeyFormat = PubkeyFormat.OPENSSL_PEM;
            } else if (!jrbExportOpenSslPem.isSelected() && currentFileName.contains(pemFileExt)) {
                jtfExportFile.setText(currentFileName.replaceAll(pemFileExt, ""));
                selectedPubKeyFormat = PubkeyFormat.OPENSSL;
            }
        });

        jrbExportJwk.addItemListener(evt -> {
            String currentFileName = jtfExportFile.getText();
            String jwkFileExt = "." + JWK_EXT;
            if (jrbExportJwk.isSelected() && !currentFileName.contains(jwkFileExt)) {
                jtfExportFile.setText(currentFileName + jwkFileExt);
                selectedPubKeyFormat = PubkeyFormat.JWK;
            } else if (!jrbExportJwk.isSelected() && currentFileName.contains(jwkFileExt)) {
                jtfExportFile.setText(currentFileName.replaceAll(jwkFileExt, ""));
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

        setTitle(MessageFormat.format(res.getString("DExportPublicKey.Title"), entryAlias));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
        File csrFile = new File(currentDirectory, sanitizedAlias + FULL_PEM_FILE_EXT);
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
     * Was the option to PEM encode selected?
     *
     * @return True if it was
     */
    public boolean pemEncode() {
        return selectedPubKeyFormat == PubkeyFormat.OPENSSL_PEM;
    }

    /**
     * @return The selected public key format.
     */
    public PubkeyFormat getSelectedPubKeyFormat() {
        return selectedPubKeyFormat;
    }

    private void browsePressed() {
        JFileChooser chooser = getPublicKeyFileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportPublicKey.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                       chooser.showSaveDialog(this) :
                       chooser.showDialog(this, res.getString("DExportPublicKey.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
        }
    }

    private void exportPressed() {
        String exportFileStr = jtfExportFile.getText().trim();

        if (exportFileStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportPublicKey.ExportFileRequired.message"),
                                          res.getString("DExportPublicKey.Simple.Title"),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileStr);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportPublicKey.OverWriteExportFile.message"),
                                                  exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message,
                                                         res.getString("DExportPublicKey.Simple.Title"),
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

    public enum PubkeyFormat {
        OPENSSL,
        OPENSSL_PEM,
        JWK
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DExportPublicKey(new JFrame(), "alias", true));
    }
}
