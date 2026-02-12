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
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.privatekey.MsPvkUtil;
import org.kse.crypto.privatekey.OpenSslPvkUtil;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.privatekey.PrivateKeyFormat;
import org.kse.crypto.privatekey.PrivateKeyPbeNotSupportedException;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.dialogs.DGenerateKeyPairCert;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.dialogs.DViewKeyPair;
import org.kse.gui.dialogs.DViewPrivateKey;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.passwordmanager.Password;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that allows the user to pick a private key file and an optional
 * certificate file to import as a key pair.
 */
public class DImportKeyPair extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlPrivateKey;
    private JTextField jtfPrivateKeyPath;
    private JButton jbPrivateKeyBrowse;
    private JButton jbPrivateKeyDetails;
    private JLabel jlPassword;
    private JPasswordField jpfPassword;
    private JLabel jlCertificate;
    private JTextField jtfCertificatePath;
    private JButton jbCertificateBrowse;
    private JButton jbCertificateDetails;
    private JButton jbImport;
    private JButton jbCancel;

    private boolean disableDocumentListener;

    private CryptoFileType fileType;
    private boolean encrypted;
    private PrivateKey privateKey;
    private X509Certificate[] certificateChain;

    /**
     * Creates a new DImportKeyPair dialog.
     *
     * @param parent The parent frame
     */
    public DImportKeyPair(JFrame parent) {
        super(parent, ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    private void initComponents() {
        jlPrivateKey = new JLabel(res.getString("DImportKeyPair.jlPrivateKey.text"));

        jtfPrivateKeyPath = new JTextField(30);
        jtfPrivateKeyPath.setToolTipText(res.getString("DImportKeyPair.jtfPrivateKeyPath.tooltip"));

        jtfPrivateKeyPath.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void changedUpdate(DocumentEvent e) {
                filePathChanged();
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                filePathChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filePathChanged();
            }

            private void filePathChanged() {
                if (!disableDocumentListener) {
                    File file = new File(jtfPrivateKeyPath.getText());
                    if (file.exists() && file.isFile()) {
                        detectFileType(file);
                    } else {
                        // reset to default if the text is not a file
                        setEnabledPassword(false);
                        setEnabledCertificate(false);
                    }
                }
            }
        });

        jbPrivateKeyBrowse = new JButton(res.getString("DImportKeyPair.jbPrivateKeyBrowse.text"));
        PlatformUtil.setMnemonic(jbPrivateKeyBrowse,
                                 res.getString("DImportKeyPair.jbPrivateKeyBrowse.mnemonic").charAt(0));
        jbPrivateKeyBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DImportKeyPair.this);
                privateKeyBrowsePressed();
            } finally {
                CursorUtil.setCursorFree(DImportKeyPair.this);
            }
        });
        jbPrivateKeyBrowse.setToolTipText(res.getString("DImportKeyPair.jbPrivateKeyBrowse.tooltip"));

        jbPrivateKeyDetails = new JButton(res.getString("DImportKeyPair.jbPrivateKeyDetails.text"));
        jbPrivateKeyDetails.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DImportKeyPair.this);
                privateKeyDetailsPressed();
            } finally {
                CursorUtil.setCursorFree(DImportKeyPair.this);
            }
        });
        PlatformUtil.setMnemonic(jbPrivateKeyDetails,
                                 res.getString("DImportKeyPair.jbPrivateKeyDetails.mnemonic").charAt(0));
        jbPrivateKeyDetails.setToolTipText(res.getString("DImportKeyPair.jbPrivateKeyDetails.tooltip"));

        jlPassword = new JLabel(res.getString("DImportKeyPair.jlPassword.text"));

        jpfPassword = new JPasswordField(15);
        jpfPassword.setToolTipText(res.getString("DImportKeyPair.jpfPassword.tooltip"));

        jlCertificate = new JLabel(res.getString("DImportKeyPair.jlCertificate.text"));

        jtfCertificatePath = new JTextField(30);
        jtfCertificatePath.setToolTipText(res.getString("DImportKeyPair.jtfCertificatePath.tooltip"));

        jbCertificateBrowse = new JButton(res.getString("DImportKeyPair.jbCertificateBrowse.text"));
        jbCertificateBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DImportKeyPair.this);
                certificateBrowsePressed();
            } finally {
                CursorUtil.setCursorFree(DImportKeyPair.this);
            }
        });
        PlatformUtil.setMnemonic(jbCertificateBrowse,
                                 res.getString("DImportKeyPair.jbCertificateBrowse.mnemonic").charAt(0));
        jbCertificateBrowse.setToolTipText(res.getString("DImportKeyPair.jbCertificateBrowse.tooltip"));

        jbCertificateDetails = new JButton(res.getString("DImportKeyPair.jbCertificateDetails.text"));
        jbCertificateDetails.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DImportKeyPair.this);
                certificateDetailsPressed();
            } finally {
                CursorUtil.setCursorFree(DImportKeyPair.this);
            }
        });
        PlatformUtil.setMnemonic(jbCertificateDetails,
                                 res.getString("DImportKeyPair.jbCertificateDetails.mnemonic").charAt(0));
        jbCertificateDetails.setToolTipText(res.getString("DImportKeyPair.jbCertificateDetails.tooltip"));

        jbImport = new JButton(res.getString("DImportKeyPair.jbImport.text"));
        PlatformUtil.setMnemonic(jbImport, res.getString("DImportKeyPair.jbImport.mnemonic").charAt(0));
        jbImport.setToolTipText(res.getString("DImportKeyPair.jbImport.tooltip"));
        jbImport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DImportKeyPair.this);
                importPressed();
            } finally {
                CursorUtil.setCursorFree(DImportKeyPair.this);
            }
        });

        jbCancel = new JButton(res.getString("DImportKeyPair.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                CANCEL_KEY);

        jbCancel.addActionListener(evt -> cancelPressed());

        setEnabledPassword(false);
        setEnabledCertificate(false);

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));
        pane.add(jlPrivateKey, "");
        pane.add(jtfPrivateKeyPath, "");
        pane.add(jbPrivateKeyBrowse, "");
        pane.add(jbPrivateKeyDetails, "wrap");
        pane.add(jlPassword, "");
        pane.add(jpfPassword, "wrap");
        pane.add(jlCertificate, "");
        pane.add(jtfCertificatePath, "");
        pane.add(jbCertificateBrowse, "");
        pane.add(jbCertificateDetails, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbImport, "right, spanx, split, tag ok");
        pane.add(jbCancel, "tag cancel");

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

        setTitle(res.getString("DImportKeyPair.Title"));
        setResizable(false);

        getRootPane().setDefaultButton(jbImport);

        pack();
    }

    private void setEnabledPassword(boolean enabled) {
        jlPassword.setEnabled(enabled);
        jpfPassword.setEnabled(enabled);
        // Wipe out the password when the file changes so that an unencrypted file
        // does not see that there is any password text.
        jpfPassword.setText(null);
    }

    private void setEnabledCertificate(boolean enabled) {
        jlCertificate.setEnabled(enabled);
        jtfCertificatePath.setEnabled(enabled);
        jbCertificateBrowse.setEnabled(enabled);
        jbCertificateDetails.setEnabled(enabled);
    }

    private void privateKeyBrowsePressed() {
        JFileChooser chooser = FileChooserFactory.getKeyFileChooser();

        File currentFile = new File(jtfPrivateKeyPath.getText());

        if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
            chooser.setCurrentDirectory(currentFile.getParentFile());
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DImportKeyPair.ChoosePrivateKey.Title"));

        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DImportKeyPair.PrivateKeyFileChooser.button"));

        int rtnValue = chooser.showOpenDialog(this);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);

            disableDocumentListener = true;
            jtfPrivateKeyPath.setText(chosenFile.toString());
            jtfPrivateKeyPath.setCaretPosition(0);
            disableDocumentListener = false;

            detectFileType(chosenFile);
        }
    }

    private void detectFileType(File chosenFile) {
        try {
            fileType = CryptoFileUtil.detectFileType(chosenFile);

            if (fileType == CryptoFileType.PKCS12_KS || fileType == CryptoFileType.ENC_PKCS8_PVK
                    || fileType == CryptoFileType.ENC_OPENSSL_PVK || fileType == CryptoFileType.ENC_MS_PVK) {
                encrypted = true;
            } else if (fileType == CryptoFileType.UNENC_PKCS8_PVK || fileType == CryptoFileType.UNENC_OPENSSL_PVK
                    || fileType == CryptoFileType.UNENC_MS_PVK) {
                encrypted = false;
            } else {
                JOptionPane.showMessageDialog(this, res.getString("DImportKeyPair.NotKeyPairFile.message"),
                        getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }

            switch (fileType) {
            case ENC_PKCS8_PVK:
            case UNENC_PKCS8_PVK:
            case ENC_OPENSSL_PVK:
            case UNENC_OPENSSL_PVK:
                // check for certs in the private key file
                try {
                    certificateChain = X509CertUtil.loadCertificates(Files.readAllBytes(chosenFile.toPath()));
                } catch (CryptoException e) {
                    // ignore since a failure likely means that there
                    // are no certificates, which is ok.

                    // Need to reset certificateChain in case the user chose a file that
                    // had certificates, and then decided to choose a different file that
                    // does not have certificates.
                    certificateChain = null;
                }
                break;
            default:
                // PKCS #12 or MS PVK -- just reset the certificateChain

                // Need to reset certificateChain in case the user chose a file that
                // had certificates, and then decided to choose a different file that
                // does not have certificates.
                certificateChain = null;
                break;
            }

            boolean isSelectCertificateFile = fileType != CryptoFileType.PKCS12_KS && (certificateChain == null
                    || certificateChain.length == 0);

            setEnabledPassword(encrypted);
            setEnabledCertificate(isSelectCertificateFile);
        } catch (FileNotFoundException | NoSuchFileException e) {
            JOptionPane.showMessageDialog(this,
                    MessageFormat.format(res.getString("DImportKeyPair.NoReadFile.message"),
                                         chosenFile), getTitle(),
                    JOptionPane.WARNING_MESSAGE);
        } catch (IOException e) {
            DError.displayError(this, e);
        }
    }

    private void certificateBrowsePressed() {
        JFileChooser chooser = FileChooserFactory.getCertFileChooser();

        File currentFile = new File(jtfCertificatePath.getText());

        if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
            chooser.setCurrentDirectory(currentFile.getParentFile());
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DImportKeyPair.ChooseCertificate.Title"));

        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DImportKeyPair.CertificateFileChooser.button"));

        int rtnValue = chooser.showOpenDialog(this);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfCertificatePath.setText(chosenFile.toString());
            jtfCertificatePath.setCaretPosition(0);
        }
    }

    private void privateKeyDetailsPressed() {
        try {
            String path = new File(jtfPrivateKeyPath.getText()).getName();

            PrivateKey privateKey = loadPrivateKey();

            if (privateKey != null) {
                JDialog dViewDetails;
                // This condition covers these cases:
                // 1. The file type is PKCS #12
                // 2. The file type is PEM with a certificate chain in it
                if (!jtfCertificatePath.isEnabled() && certificateChain != null && certificateChain.length > 0) {
                    dViewDetails = new DViewKeyPair(this, MessageFormat.format(
                            res.getString("DImportKeyPair.ViewKeyPairDetails.Title"), path), privateKey,
                            certificateChain);
                } else {
                    dViewDetails = new DViewPrivateKey(this,
                            MessageFormat.format(res.getString("DImportKeyPair.ViewPrivateKeyDetails.Title"), path),
                            privateKey, Optional.ofNullable(getPrivateKeyFormat()));
                }
                dViewDetails.setLocationRelativeTo(this);
                dViewDetails.setVisible(true);
            }
        } catch (CryptoException ex) {
            DError.displayError(this, ex);
        }
    }

    private PrivateKeyFormat getPrivateKeyFormat() {
        PrivateKeyFormat format;
        switch (fileType) {
            case ENC_PKCS8_PVK:
            case UNENC_PKCS8_PVK:
               format = PrivateKeyFormat.PKCS8;
               break;
            case ENC_OPENSSL_PVK:
            case UNENC_OPENSSL_PVK:
                format = PrivateKeyFormat.PKCS1;
                break;
            case ENC_MS_PVK:
            case UNENC_MS_PVK:
                format = PrivateKeyFormat.MSPVK;
                break;
            default:
                // Ignore the file types since detectFileType filters out unsupported file types.
                format = null;
                break;
        }
        return format;
    }

    private PrivateKey loadPrivateKey() {
        String privateKeyPath = jtfPrivateKeyPath.getText().trim();

        if (privateKeyPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DImportKeyPair.PrivateKeyRequired.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
            return null;
        }

        File privateKeyFile = new File(privateKeyPath);

        try {
            PrivateKey privateKey = null;
            byte[] pvkData = Files.readAllBytes(privateKeyFile.toPath());

            Password password = null;
            if (encrypted) {
                password = new Password(jpfPassword.getPassword());
            }

            switch (fileType) {
                case PKCS12_KS:
                    privateKey = loadPkcs12(privateKeyFile, password);
                    break;
                case ENC_PKCS8_PVK:
                    privateKey = Pkcs8Util.loadEncrypted(pvkData, password);
                    break;
                case UNENC_PKCS8_PVK:
                    privateKey = Pkcs8Util.load(pvkData);
                    break;
                case ENC_OPENSSL_PVK:
                    privateKey = OpenSslPvkUtil.loadEncrypted(pvkData, password);
                    break;
                case UNENC_OPENSSL_PVK:
                    privateKey = OpenSslPvkUtil.load(pvkData);
                    break;
                case ENC_MS_PVK:
                    privateKey = MsPvkUtil.loadEncrypted(pvkData, password);
                    break;
                case UNENC_MS_PVK:
                    privateKey = MsPvkUtil.load(pvkData);
                    break;
                default:
                    JOptionPane.showMessageDialog(this, res.getString("DImportKeyPair.NotKeyPairFile.message"),
                            getTitle(), JOptionPane.WARNING_MESSAGE);
                    break;
            }

            return privateKey;
        } catch (PrivateKeyPbeNotSupportedException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                                                  res.getString("DImportKeyPair.PrivateKeyPbeNotSupported" +
                                                                ".message"), ex.getUnsupportedPbe()),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
        } catch (FileNotFoundException | NoSuchFileException ex) {
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(res.getString("DImportKeyPair.NoReadFile.message"),
                                                               privateKeyFile), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
        } catch (Exception ex) {
            Problem problem = createLoadKeyProblem(ex, privateKeyFile);

            DProblem dProblem = new DProblem(this, res.getString("DImportKeyPair.ProblemLoadingKey.Title"),
                                             problem);
            dProblem.setLocationRelativeTo(this);
            dProblem.setVisible(true);
        }
        return null;
    }

    private PrivateKey loadPkcs12(File file, Password password) {
        try {
            KseKeyStore pkcs12 = KeyStoreUtil.load(file, password, KeyStoreType.PKCS12);

            // Find a key pair in the PKCS #12 KeyStore
            PrivateKey privKey = null;
            ArrayList<Certificate> certsList = new ArrayList<>();

            // Look for key pair entries first
            for (Enumeration<String> aliases = pkcs12.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();

                if (pkcs12.isKeyEntry(alias)) {
                    Key key = pkcs12.getKey(alias, password.toCharArray());
                    if (key instanceof PrivateKey) {
                        privKey = (PrivateKey) key;
                        Certificate[] certs = pkcs12.getCertificateChain(alias);
                        if ((certs != null) && (certs.length > 0)) {
                            Collections.addAll(certsList, certs);
                            break;
                        }
                    }
                }
            }

            // No key pair entries found, but a key entry was found, look for certificate entries
            if (privKey != null && certsList.isEmpty()) {
                for (Enumeration<String> aliases = pkcs12.aliases(); aliases.hasMoreElements(); ) {
                    String alias = aliases.nextElement();

                    Certificate certificate = pkcs12.getCertificate(alias);
                    if (certificate != null) {
                        certsList.add(certificate);
                    }
                }
            }

            if (privKey == null || certsList.isEmpty()) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                                                      res.getString("DImportKeyPair.NoKeyPairFound.message"),
                                                      file.getName()), getTitle(), JOptionPane.INFORMATION_MESSAGE);
                return null;
            }

            certificateChain = X509CertUtil.convertCertificates(certsList.toArray(Certificate[]::new));

            return privKey;
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(res.getString("DImportKeyPair.NoReadFile.message"),
                                                               file), getTitle(), JOptionPane.WARNING_MESSAGE);
            return null;
        } catch (Exception ex) {
            Problem problem = createLoadPkcs12Problem(ex, file);

            DProblem dProblem = new DProblem(this, res.getString("DImportKeyPair.ProblemLoadingKeyPair.Title"),
                                             problem);
            dProblem.setLocationRelativeTo(this);
            dProblem.setVisible(true);

            return null;
        }
    }

    private Problem createLoadPkcs12Problem(Exception exception, File file) {
        String problemStr = MessageFormat.format(res.getString("DImportKeyPair.NoLoadEncryptedKeyPair.Problem"),
                                                 file.getName());

        String[] causes = new String[] { res.getString("DImportKeyPair.PasswordIncorrectKey.Cause"),
                                         res.getString("DImportKeyPair.CorruptedKeyPair.Cause") };

        return new Problem(problemStr, causes, exception);
    }

    private Problem createLoadKeyProblem(Exception exception, File file) {
        String problemStr;
        ArrayList<String> causeList = new ArrayList<>();

        if (encrypted) {
            problemStr = MessageFormat.format(res.getString("DImportKeyPair.NoLoadEncryptedKey.Problem"),
                    file.getName());
            causeList.add(res.getString("DImportKeyPair.PasswordIncorrectKey.Cause"));
        } else {
            problemStr = MessageFormat.format(res.getString("DImportKeyPair.NoLoadUnencryptedKey.Problem"),
                    file.getName());
        }

        causeList.add(res.getString("DImportKeyPair.CorruptedKey.Cause"));

        String[] causes = causeList.toArray(String[]::new);

        return new Problem(problemStr, causes, exception);
    }

    private void certificateDetailsPressed() {
        try {
            X509Certificate[] certs = loadCertificates(null);

            if (certs != null && certs.length != 0) {
                String path = new File(jtfCertificatePath.getText()).getName();

                DViewCertificate dViewCertificate = new DViewCertificate(this, MessageFormat.format(
                        res.getString("DImportKeyPair.ViewCertificateDetails.Title"), path), certs, null,
                                                                         DViewCertificate.NONE);
                dViewCertificate.setLocationRelativeTo(this);
                dViewCertificate.setVisible(true);
            }
        } catch (CryptoException ex) {
            DError.displayError(this, ex);
        }
    }

    private X509Certificate[] generateCertificate(PrivateKey privateKey) {
        try {
            KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);
            KeyPair keyPair = KeyPairUtil.generateKeyPair(privateKey);

            DGenerateKeyPairCert dGenerateKeyPairCert = new DGenerateKeyPairCert((JFrame) this.getParent(), null,
                    res.getString("DImportKeyPair.GenerateKeyPairCert.Title"), keyPair,
                    keyPairType, null, null, KSE.BC);
            dGenerateKeyPairCert.setLocationRelativeTo(this.getParent());
            dGenerateKeyPairCert.setVisible(true);
            X509Certificate certificate = dGenerateKeyPairCert.getCertificate();
            if (certificate != null) {
                return new X509Certificate[] { certificate };
            }
        } catch (CryptoException ex) {
            DError.displayError(this, ex);
        }
        return null;
    }

    private X509Certificate[] loadCertificates(PrivateKey privateKey) {
        String certificatePath = jtfCertificatePath.getText().trim();

        if (certificatePath.isEmpty()) {
            // ML-KEM certs cannot be self-signed -- so a cert cannot be generated
            boolean isSelfSignPossible = privateKey != null && !KeyPairType.isMlKEM(KeyPairUtil.getKeyPairType(privateKey));
            if (!isSelfSignPossible) {
                JOptionPane.showMessageDialog(this, res.getString("DImportKeyPair.CertificateRequired.message"),
                        getTitle(), JOptionPane.WARNING_MESSAGE);
                return null;
            }

            int selected = JOptionPane.showConfirmDialog(this,
                    res.getString("DImportKeyPair.ConfirmGenerateCert.message"),
                    res.getString("DImportKeyPair.ConfirmGenerateCert.Title"), JOptionPane.YES_NO_OPTION);

            if (selected != JOptionPane.YES_OPTION) {
                return null;
            }
            return generateCertificate(privateKey);
        }

        File certificateFile = new File(certificatePath);

        try {
            byte[] certsBytes = Files.readAllBytes(certificateFile.toPath());
            X509Certificate[] certs = X509CertUtil.loadCertificates(certsBytes);

            if (certs.length == 0) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                                                      res.getString("DImportKeyPair.NoCertsFound.message"), certificateFile), getTitle(),
                                              JOptionPane.WARNING_MESSAGE);
            }

            return certs;
        } catch (FileNotFoundException | NoSuchFileException ex) {
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(res.getString("DImportKeyPair.NoReadFile.message"),
                                                               certificateFile), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return null;
        } catch (Exception ex) {
            Problem problem = createLoadCertsProblem(ex, certificateFile);

            DProblem dProblem = new DProblem(this, res.getString("DImportKeyPair.ProblemLoadingCerts.Title"),
                                             problem);
            dProblem.setLocationRelativeTo(this);
            dProblem.setVisible(true);

            return null;
        }
    }

    private Problem createLoadCertsProblem(Exception exception, File certsFile) {
        String problemStr = MessageFormat.format(res.getString("DImportKeyPair.NoLoadCerts.Problem"),
                                                 certsFile.getName());

        String[] causes = new String[] { res.getString("DImportKeyPair.NotCerts.Cause"),
                                         res.getString("DImportKeyPair.CorruptedCerts.Cause") };

        return new Problem(problemStr, causes, exception);
    }

    /**
     * Get the private part of the key pair chosen by the user for import.
     *
     * @return The private key or null if the user has not chosen a key pair
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Get the certificate chain part of the key pair chosen by the user for
     * import.
     *
     * @return The certificate chain or null if the user has not chosen a key
     *         pair
     */
    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    private void importPressed() {
        try {
            PrivateKey privateKey = loadPrivateKey();

            if (privateKey == null) {
                return;
            }

            if (certificateChain == null) {
                X509Certificate[] certs = loadCertificates(privateKey);

                if (certs == null || certs.length == 0) {
                    return;
                }

                if (!KeyPairUtil.validKeyPair(privateKey, certs[0].getPublicKey())) {
                    JOptionPane.showMessageDialog(this, res.getString("DImportKeyPair.KeyPairInvalid.message"),
                            getTitle(), JOptionPane.WARNING_MESSAGE);
                    return;
                }

                certificateChain = certs;
            }

            this.privateKey = privateKey;
            certificateChain = X509CertUtil.orderX509CertChain(certificateChain);

            closeDialog();
        } catch (Exception ex) {
            DError.displayError(this, ex);
        }
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
