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
package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import java.util.jar.JarFile;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.apache.commons.io.IOUtils;
import org.kse.KSE;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.JarSigner;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dialogs.DialogHelper;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;
import org.kse.utilities.net.URLs;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the presents JAR signing options.
 */
public class DSignFile extends JEscDialog {
    // TODO JW - update this after adjusting the fields
    private static final long serialVersionUID = -5095469699284737624L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlInputFile;
    private JPanel jpInputFile;
    private JTextField jtfInputFile;
    private JButton jbInputFileBrowse;
    private JLabel jlDetachedSignature;
    private JCheckBox jcbDetachedSignature;
    private JLabel jlSignatureAlgorithm;
    private JComboBox<SignatureType> jcbSignatureAlgorithm;
    private JLabel jlAddTimestamp;
    private JCheckBox jcbAddTimestamp;
    private JLabel jlTimestampServerUrl;
    private JComboBox<String> jcbTimestampServerUrl;
    private JPanel jpButtons;
    private JButton jbOK;
    private JButton jbCancel;

    private PrivateKey signPrivateKey;
    private KeyPairType signKeyPairType;
    private File inputFile;
    // TODO JW - get rid of outputFile. It will be set automatically.
    private File outputFile;
    private boolean detachedSignature;
    private SignatureType signatureType;
    private String tsaUrl;
    private boolean successStatus = true;

    /**
     * Creates a new DSignFile dialog.
     *
     * @param parent          The parent frame
     * @param signPrivateKey  Signing key pair's private key
     * @param signKeyPairType Signing key pair's type
     * @param isCounterSign   True if the dialog should be counter signing a signature. False for signing a file.
     */
    public DSignFile(JFrame parent, PrivateKey signPrivateKey, KeyPairType signKeyPairType, boolean isCounterSign) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.signPrivateKey = signPrivateKey;
        this.signKeyPairType = signKeyPairType;
        // TODO JW - for counter signing only choose a signature file.
        String title = "DSignFile.Sign.Title";;
        if (isCounterSign) {
            title = "DSignFile.CounterSign.Title";
        }
        setTitle(res.getString(title));
        initComponents(isCounterSign);
    }

    /**
     * Initializes the dialogue panel and associated elements
     *
     * @param isCounterSign True for counter signing. False for signing.
     */
    private void initComponents(boolean isCounterSign) {
        jlDetachedSignature = new JLabel(res.getString("DSignFile.jlDetachedSignature.text"));
        jcbDetachedSignature = new JCheckBox();
        jcbDetachedSignature.setSelected(true);
        jcbDetachedSignature.setToolTipText(res.getString("DSignFile.jcbDetachedSignature.tooltip"));

        jlInputFile = new JLabel(res.getString("DSignFile.jlInputFile.text"));
        jtfInputFile = new JTextField(30);
        jtfInputFile.setCaretPosition(0);
        jtfInputFile.setToolTipText(res.getString("DSignFile.jtfInputFile.tooltip"));

        jbInputFileBrowse = new JButton(res.getString("DSignFile.jbInputFileBrowse.text"));
        PlatformUtil.setMnemonic(jbInputFileBrowse, res.getString("DSignFile.jbInputFileBrowse.mnemonic").charAt(0));
        jbInputFileBrowse.setToolTipText(res.getString("DSignFile.jbInputFileBrowse.tooltip"));

        // TODO JW - Remove default panel margin/insets.
        jpInputFile = new JPanel();
        jpInputFile.add(jtfInputFile);
        jpInputFile.add(jbInputFileBrowse);

        jlSignatureAlgorithm = new JLabel(res.getString("DSignFile.jlSignatureAlgorithm.text"));
        jcbSignatureAlgorithm = new JComboBox<>();
        DialogHelper.populateSigAlgs(signKeyPairType, this.signPrivateKey, jcbSignatureAlgorithm);
        jcbSignatureAlgorithm.setToolTipText(res.getString("DSignFile.jcbSignatureAlgorithm.tooltip"));

        jlAddTimestamp = new JLabel(res.getString("DSignFile.jlAddTimestamp.text"));
        jcbAddTimestamp = new JCheckBox();
        jcbAddTimestamp.setSelected(false);
        jcbAddTimestamp.setToolTipText(res.getString("DSignFile.jcbAddTimestamp.tooltip"));

        jlTimestampServerUrl = new JLabel(res.getString("DSignFile.jlTimestampServerUrl.text"));
        jcbTimestampServerUrl = new JComboBox<>();
        jcbTimestampServerUrl.setEditable(true);
        jcbTimestampServerUrl.setEnabled(false);
        jcbTimestampServerUrl.setToolTipText(res.getString("DSignFile.jcbTimestampServerUrl.tooltip"));
        jcbTimestampServerUrl.setModel(new DefaultComboBoxModel<>(URLs.TSA_URLS));

        jbOK = new JButton(res.getString("DSignFile.jbOK.text"));

        jbCancel = new JButton(res.getString("DSignFile.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[para]unrel[right]unrel[]", "[]unrel[]"));
        pane.add(jlInputFile, "skip");
        pane.add(jpInputFile, "wrap");
        pane.add(jlDetachedSignature, "skip");
        pane.add(jcbDetachedSignature, "wrap");
        pane.add(jlSignatureAlgorithm, "skip");
        pane.add(jcbSignatureAlgorithm, "sgx, wrap");
        pane.add(jlAddTimestamp, "skip");
        pane.add(jcbAddTimestamp, "wrap");
        pane.add(jlTimestampServerUrl, "skip");
        pane.add(jcbTimestampServerUrl, "sgx, wrap para");
        pane.add(new JSeparator(), "spanx, growx, wrap para");
        pane.add(jpButtons, "right, spanx");

        // actions
        jbInputFileBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignFile.this);
                inputFileBrowsePressed(isCounterSign);
            } finally {
                CursorUtil.setCursorFree(DSignFile.this);
            }
        });

        jcbAddTimestamp.addItemListener(evt -> enableDisableElements());
        jcbDetachedSignature.addItemListener(evt -> enableDisableElements());

        jbOK.addActionListener(evt -> okPressed());

        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        jbCancel.addActionListener(evt -> cancelPressed());

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
        setLocationRelativeTo(null);

    }

    /**
     * This function enables and disables elements in the dialog
     */
    protected void enableDisableElements() {
        jcbTimestampServerUrl.setEnabled(jcbAddTimestamp.isSelected());
    }

    /**
     * Get chosen input file.
     *
     * @return <b>File</b> input file
     */
    public File getInputFile() {
        return inputFile;
    }

    /**
     * Get chosen output file.
     *
     * @return <b>File</b> output file
     */
    public File getOutputFile() {
        return outputFile;
    }

    /**
     * Get the chosen detached signature setting
     * 
     * @return <b>boolean</b> detached signature setting
     */
    public boolean isDetachedSignature() {
        return detachedSignature;
    }

    /**
     * Get chosen signature type.
     *
     * @return <b>SignatureType</b> or null if dialog cancelled
     */
    public SignatureType getSignatureType() {
        return signatureType;
    }

    /**
     * Get chosen TSA URL.
     *
     * @return <b>String</b> TSA URL or null if dialog cancelled
     */
    public String getTimestampingServerUrl() {
        return tsaUrl;
    }

    /**
     * The function checks the following
     * <p>
     * - dialog fields to ensure they are not empty
     * <p>
     * - output file paths for overwriting files
     */
    private void okPressed() {
        // check if any files selected
        if (inputFile == null) {
            JOptionPane.showMessageDialog(this, res.getString("DSignFile.InputFileRequired.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        // check if time stamp URL is empty
        if (jcbAddTimestamp.isSelected() && jcbTimestampServerUrl.getSelectedItem().toString().isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DSignFile.EmptyTimestampUrl.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
        detachedSignature = jcbDetachedSignature.isSelected();

        // check add time stamp is selected and assign value
        if (jcbAddTimestamp.isSelected()) {
            tsaUrl = jcbTimestampServerUrl.getSelectedItem().toString();
        }

        outputFile = new File(inputFile.getAbsolutePath() + (detachedSignature ? ".p7s" : ".p7m"));

        closeDialog();
    }

//    /**
//     * Set output JAR files and check files for overwrite
//     *
//     * @return <b>Boolean</b> true if successful false if no option chosen
//     */
//    private boolean setOutputJarFiles(File[] files) {
//        String outputJarPrefix = jtfPrefix.getText().trim();
//        String outputJarSuffix = jtfSuffix.getText().trim();
//        final String FILE_SUFFIX = ".jar";
//        JCheckBox checkbox = new JCheckBox(res.getString("DSignFile.OverwriteSkip.message"));
//
//        // set input files array to output files list
//        this.outputJarFiles = new ArrayList<>(Arrays.asList(files));
//
//        if (jrbOutputJarFixes.isSelected()) {
//            // loop through output JAR files
//            for (int i = 0; i < outputJarFiles.size(); i++) {
//                // set prefix and suffix to the file name
//                String fileBaseName = FileNameUtil.removeExtension(outputJarFiles.get(i).getName());
//                String outFileName =
//                        outputJarFiles.get(i).getParent() + "\\" + outputJarPrefix + fileBaseName + outputJarSuffix +
//                        FILE_SUFFIX;
//                // replace file object in arraylist
//                this.outputJarFiles.set(i, new File(outFileName));
//
//                if (!checkbox.isSelected()) {
//                    // check if file exists
//                    if (outputJarFiles.get(i).isFile()) {
//                        String message = MessageFormat.format(res.getString("DSignFile.OverWriteOutputJarFile.message"),
//                                                              outputJarFiles.get(i));
//                        Object[] params = { message, checkbox };
//
//                        // check if overwrite is allowed and present checkbox to skip overwrite message
//                        int selected = JOptionPane.showConfirmDialog(this, params, getTitle(),
//                                                                     JOptionPane.YES_NO_OPTION);
//                        if (selected != JOptionPane.YES_OPTION) {
//                            this.outputJarFiles.clear();
//                            return false;
//                        }
//                    }
//                }
//            }
//        }
//        return true;
//    }

//    /**
//     * Checks to overwrite an existing signature
//     *
//     * @return <b>Boolean</b> continues jar signing if true cancels process if false
//     */
//    private boolean checkSignature(File[] files) {
//        JCheckBox checkbox = new JCheckBox(res.getString("DSignFile.OverwriteSkip.message"));
//
//        for (File file : files) {
//            try {
//                // check if the existing signature matches the current signature
//                if (JarSigner.hasSignature(file, this.signatureName)) {
//                    String message = MessageFormat.format(res.getString("DSignFile.SignatureOverwrite.message"),
//                            this.signatureName, file.getName());
//                    Object[] params = {message, checkbox};
//                    // check if overwrite is allowed and present checkbox to skip overwrite message
//                    int selected = JOptionPane.showConfirmDialog(this, params, getTitle(), JOptionPane.YES_NO_OPTION);
//                    if (selected != JOptionPane.YES_OPTION) {
//                        return false;
//                    }
//                }
//            } catch (IOException ex) {
//                DError.displayError(this, ex);
//                return false;
//            }
//            // check to skip overwrite alert message
//            if (checkbox.isSelected()) {
//                return true;
//            }
//        }
//        return true;
//    }

    /**
     * Get input file
     */
    private void inputFileBrowsePressed(boolean isCounterSign) {
        JFileChooser chooser;

        if (!isCounterSign) {
            chooser = FileChooserFactory.getAllFileChooser();
            chooser.setDialogTitle(res.getString("DSignFile.ChooseInputFile.Sign.Title"));
        } else {
            chooser = FileChooserFactory.getSignatureFileChooser();
            chooser.setDialogTitle(res.getString("DSignFile.ChooseInputFile.CounterSign.Title"));
        }
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DSignFile.InputFileChooser.button"));

        int rtnValue = chooser.showOpenDialog(this);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            inputFile = chosenFile;
            // TODO JW - Is there a better location for this code?
            jtfInputFile.setText(inputFile.getAbsolutePath());
            jtfInputFile.setCaretPosition(0);
        }
    }

    /**
     * Returns the current success status
     *
     * @return successStatus true if successful false if not
     */
    public boolean isSuccessful() {
        return successStatus;
    }

    /**
     * Call the close dialog method
     */
    private void cancelPressed() {
        successStatus = false;
        closeDialog();
    }

    /**
     * Close the dialog method
     */
    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick UI testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyPairType.RSA.jce(), KSE.BC);
        kpg.initialize(1024, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        DSignFile dialog = new DSignFile(new JFrame(), kp.getPrivate(), KeyPairType.RSA, false);
        DialogViewer.run(dialog);
    }
}