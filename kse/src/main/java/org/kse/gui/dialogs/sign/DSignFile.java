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
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
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
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.kse.KSE;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.dialogs.DialogHelper;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.net.URLs;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the presents JAR signing options.
 */
public class DSignFile extends JEscDialog {
    private static final long serialVersionUID = 9162242907697268949L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlInputFile;
    private JTextField jtfInputFile;
    private JButton jbInputFileBrowse;
    private JLabel jlOutputFile;
    private JTextField jtfOutputFile;
    private JButton jbOutputFileBrowse;
    private JLabel jlCounterSign;
    private JCheckBox jcbCounterSign;
    private JLabel jlDetachedSignature;
    private JCheckBox jcbDetachedSignature;
    private JLabel jlOutputPem;
    private JCheckBox jcbOutputPem;
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
    private File outputFile;
    private CMSSignedData inputSignature;
    private boolean outputFileChosen;
    private boolean enableCounterSign;
    private boolean detachedSignature = true;
    private boolean outputPem;
    private SignatureType signatureType;
    private String tsaUrl;
    private boolean successStatus = true;

    /**
     * Creates a new DSignFile dialog.
     *
     * @param parent          The parent frame
     * @param signPrivateKey  Signing key pair's private key
     * @param signKeyPairType Signing key pair's type
     */
    public DSignFile(JFrame parent, PrivateKey signPrivateKey, KeyPairType signKeyPairType) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.signPrivateKey = signPrivateKey;
        this.signKeyPairType = signKeyPairType;
        setTitle(res.getString("DSignFile.Sign.Title"));
        initComponents();
    }

    /**
     * Initializes the dialogue panel and associated elements
     */
    private void initComponents() {
        resetToDefault();

        jlInputFile = new JLabel(res.getString("DSignFile.jlInputFile.text"));
        jtfInputFile = new JTextField(30);
        jtfInputFile.setCaretPosition(0);
        jtfInputFile.setToolTipText(res.getString("DSignFile.jtfInputFile.tooltip"));

        jbInputFileBrowse = new JButton(res.getString("DSignFile.jbInputFileBrowse.text"));
        PlatformUtil.setMnemonic(jbInputFileBrowse, res.getString("DSignFile.jbInputFileBrowse.mnemonic").charAt(0));
        jbInputFileBrowse.setToolTipText(res.getString("DSignFile.jbInputFileBrowse.tooltip"));

        jlOutputFile = new JLabel(res.getString("DSignFile.jlOutputFile.text"));
        jtfOutputFile = new JTextField(30);
        jtfOutputFile.setCaretPosition(0);
        jtfOutputFile.setToolTipText(res.getString("DSignFile.jtfOutputFile.tooltip"));

        jbOutputFileBrowse = new JButton(res.getString("DSignFile.jbOutputFileBrowse.text"));
        PlatformUtil.setMnemonic(jbOutputFileBrowse, res.getString("DSignFile.jbOutputFileBrowse.mnemonic").charAt(0));
        jbOutputFileBrowse.setToolTipText(res.getString("DSignFile.jbOutputFileBrowse.tooltip"));

        jlCounterSign = new JLabel(res.getString("DSignFile.jlCounterSign.text"));
        jlCounterSign.setEnabled(enableCounterSign);
        jcbCounterSign = new JCheckBox();
        jcbCounterSign.setSelected(enableCounterSign);
        jcbCounterSign.setEnabled(enableCounterSign);
        jcbCounterSign.setToolTipText(res.getString("DSignFile.jcbCounterSign.tooltip"));

        jlDetachedSignature = new JLabel(res.getString("DSignFile.jlDetachedSignature.text"));
        jcbDetachedSignature = new JCheckBox();
        jcbDetachedSignature.setSelected(detachedSignature);
        jcbDetachedSignature.setToolTipText(res.getString("DSignFile.jcbDetachedSignature.tooltip"));

        jlOutputPem = new JLabel(res.getString("DSignFile.jlOutputPem.text"));
        jcbOutputPem = new JCheckBox();
        jcbOutputPem.setSelected(outputPem);
        jcbOutputPem.setToolTipText(res.getString("DSignFile.jcbOutputPem.tooltip"));

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
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));
        pane.add(jlInputFile, "");
        pane.add(jtfInputFile, "");
        pane.add(jbInputFileBrowse, "wrap");
        pane.add(jlOutputFile, "");
        pane.add(jtfOutputFile, "");
        pane.add(jbOutputFileBrowse, "wrap");
        pane.add(jlCounterSign, "");
        pane.add(jcbCounterSign, "wrap");
        pane.add(jlDetachedSignature, "");
        pane.add(jcbDetachedSignature, "wrap");
        pane.add(jlOutputPem, "");
        pane.add(jcbOutputPem, "wrap");
        pane.add(jlSignatureAlgorithm, "");
        pane.add(jcbSignatureAlgorithm, "wrap");
        pane.add(jlAddTimestamp, "");
        pane.add(jcbAddTimestamp, "wrap");
        pane.add(jlTimestampServerUrl, "");
        pane.add(jcbTimestampServerUrl, "wrap para");
        pane.add(new JSeparator(), "spanx, growx, wrap para");
        pane.add(jpButtons, "right, spanx");

        // actions
        jbInputFileBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignFile.this);
                inputFileBrowsePressed();
            } finally {
                CursorUtil.setCursorFree(DSignFile.this);
            }
        });

        jbOutputFileBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSignFile.this);
                outputFileBrowsePressed();
            } finally {
                CursorUtil.setCursorFree(DSignFile.this);
            }
        });

        jcbCounterSign.addActionListener(evt -> updateOutputFile());
        jcbDetachedSignature.addItemListener(evt -> detachedSignatureStateChange());
        jcbAddTimestamp.addItemListener(evt -> enableDisableTsaElements());

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
     * This function enables and disables elements in the dialog.
     */
    protected void updateControls() {
        jlCounterSign.setEnabled(enableCounterSign);
        jcbCounterSign.setEnabled(enableCounterSign);
        jcbCounterSign.setSelected(enableCounterSign);

        jcbDetachedSignature.setSelected(detachedSignature);
        jcbOutputPem.setSelected(outputPem);
        updateOutputFile();
    }

    protected void detachedSignatureStateChange() {
        detachedSignature = jcbDetachedSignature.isSelected();
        updateOutputFile();
    }

    /**
     * This function enables and disables the TSA elements in the dialog
     */
    protected void enableDisableTsaElements() {
        jcbTimestampServerUrl.setEnabled(jcbAddTimestamp.isSelected());
    }

    private void resetToDefault() {
        inputSignature = null;
        enableCounterSign = false;
        detachedSignature = true;
        outputPem = false;
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
     * Gets the chosen output PEM setting
     *
     * @return <b>booleans</b> output PEM setting
     */
    public boolean isOutputPem() {
        return outputPem;
    }

    /**
     * Gets the counter sign setting.
     *
     * @return <b>booleans</b> output counterSign setting
     */
    public boolean isCounterSign() {
        return jcbCounterSign.isSelected();
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

        if (!outputFileChosen) {
            outputFile = new File(jtfOutputFile.getText());
        }

        // warn if overwriting a file when not counter signing
        if (outputFile.exists() && (!enableCounterSign || !jcbCounterSign.isSelected())) {
            int selected = JOptionPane.showConfirmDialog(this,
                    MessageFormat.format(res.getString("DSignFile.OverWriteOutput.message"), outputFile.getName()),
                    getTitle(), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

            if (selected != JOptionPane.YES_OPTION) {
                return;
            }
        }

        detachedSignature = jcbDetachedSignature.isSelected();
        outputPem = jcbOutputPem.isSelected();
        signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();

        // check add time stamp is selected and assign value
        if (jcbAddTimestamp.isSelected()) {
            tsaUrl = jcbTimestampServerUrl.getSelectedItem().toString();
        }

        closeDialog();
    }

    /**
     * Get input file
     */
    private void inputFileBrowsePressed() {
        JFileChooser chooser;

        chooser = FileChooserFactory.getAllFileChooser();
        chooser.setDialogTitle(res.getString("DSignFile.ChooseInputFile.Sign.Title"));
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DSignFile.InputFileChooser.button"));

        int rtnValue = chooser.showOpenDialog(this);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            inputFile = chosenFile;

            inputFileUpdated();
        }
    }

    /**
     * Get output file
     */
    private void outputFileBrowsePressed() {
        JFileChooser chooser = FileChooserFactory.getSignatureFileChooser();
        chooser.setDialogTitle(res.getString("DSignFile.ChooseOutputFile.Title"));
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DSignFile.OutputFileChooser.button"));

        int rtnValue = chooser.showOpenDialog(this);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            outputFile = chosenFile;
            outputFileChosen = true;

            updateOutputFile();
        }
    }

    private void inputFileUpdated() {
        if (inputFile.exists()) {
            // reset to defaults
            resetToDefault();

            try {
                byte[] signature = Files.readAllBytes(inputFile.toPath());

                if (PemUtil.isPemFormat(signature)) {
                    PemInfo signaturePem = PemUtil.decode(signature);
                    if (signaturePem != null) {
                        signature = signaturePem.getContent();
                    }
                    outputPem = CmsUtil.isCmsPemType(signaturePem);
                }

                inputSignature = new CMSSignedData(signature);
                enableCounterSign = !inputSignature.isCertificateManagementMessage();
                detachedSignature = inputSignature.isDetachedSignature();
            } catch (IOException | CMSException e) {
                // Eat the exception.
                // For IOException - don't know what failed, assume the file is not PKCS#7.
                // For CMSException - know for certain that the file is not PKCS#7.
            }
        }

        jtfInputFile.setText(inputFile.getAbsolutePath());
        jtfInputFile.setCaretPosition(0);
        updateControls();
    }

    private void updateOutputFile() {
        if (!outputFileChosen) {
            String addedExtension = "";

            if (!enableCounterSign || !jcbCounterSign.isSelected()) {
                addedExtension = detachedSignature ? ".p7s" : ".p7m";
            }
            outputFile = new File(inputFile.getAbsolutePath() + addedExtension);
        }

        jtfOutputFile.setText(outputFile.getAbsolutePath());
        jtfOutputFile.setCaretPosition(0);
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

        DSignFile dialog = new DSignFile(new JFrame(), kp.getPrivate(), KeyPairType.RSA);
        DialogViewer.run(dialog);
    }
}