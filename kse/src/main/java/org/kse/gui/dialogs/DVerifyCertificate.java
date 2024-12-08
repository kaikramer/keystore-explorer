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

package org.kse.gui.dialogs;

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
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
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

import org.kse.crypto.ocsp.OcspDigestAlgorithm;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.OpenAction;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.history.KeyStoreHistory;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that allows to verify the revocation status and the certificate chain.
 */
public class DVerifyCertificate extends JEscDialog {

    private static final long serialVersionUID = 1L;

    public enum VerifyOptions {
        CRL_DIST,
        CRL_FILE,
        OCSP_AIA, // Authority Information Access
        OCSP_URL,
        CHAIN
    }

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private String certificateAlias;

    private JRadioButton jrbCrlCheckDistPoint;
    private JRadioButton jrbCrlCheckFile;
    private JTextField jtfCrlFile;
    private JButton jbLoadCrl;
    private JRadioButton jrbOcspAiaCheck;
    private JRadioButton jrbOcspUrlCheck;
    private JTextField jtfOcspUrl;
    private JRadioButton jrbChainCheck;
    private JCheckBox jcbSelectKeyStore;
    private JPanel jpButtons;
    private JButton jbOk;
    private JButton jbCancel;

    private JComboBox<KeyStoreHistory> jcbKeyStore;
    private JButton jbLoadKeystore;

    private JComboBox<OcspDigestAlgorithm> jcbOcspDigestAlgorithm;
    private JCheckBox jcbOcspIncludeNonce;

    private boolean verifySelected = false;
    private VerifyOptions verifyOption = VerifyOptions.CRL_DIST;
    private String fileCrl;
    private String ocspUrl;

    private KseFrame kseFrame;

    /**
     * Creates a new DVerifyCertificate dialog.
     *
     * @param parent           The parent frame
     * @param certificateAlias The certificate alias
     * @param kseFrame         KeyStore Explorer application frame
     */
    public DVerifyCertificate(JFrame parent, String certificateAlias, KseFrame kseFrame) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.certificateAlias = certificateAlias;
        this.kseFrame = kseFrame;
        initComponents();
    }

    private void initComponents() {

        jrbCrlCheckDistPoint = new JRadioButton(res.getString("DVerifyCertificate.jrbCrlCheckDistPoint.text"));
        jrbCrlCheckDistPoint.setToolTipText(res.getString("DVerifyCertificate.jrbCrlCheckDistPoint.tooltip"));

        jrbCrlCheckFile = new JRadioButton(res.getString("DVerifyCertificate.jrbCrlCheckFile.text"));
        jrbCrlCheckFile.setToolTipText(res.getString("DVerifyCertificate.jrbCrlCheckFile.tooltip"));

        jtfCrlFile = new JTextField("", 20);
        jtfCrlFile.setEditable(false);
        jtfCrlFile.setToolTipText(res.getString("DVerifyCertificate.jtfCrlFile.tooltip"));

        jbLoadCrl = new JButton();
        jbLoadCrl.setIcon(new ImageIcon(getClass().getResource("images/open.png")));
        jbLoadCrl.setToolTipText(res.getString("DVerifyCertificate.jbLoadCrl.tooltip"));
        jbLoadCrl.setEnabled(false);

        jrbOcspAiaCheck = new JRadioButton(res.getString("DVerifyCertificate.jrbOcspAiaCheck.text"));
        jrbOcspAiaCheck.setToolTipText(res.getString("DVerifyCertificate.jrbOcspAiaCheck.tooltip"));

        jrbOcspUrlCheck = new JRadioButton(res.getString("DVerifyCertificate.jrbOcspUrlCheck.text"));
        jrbOcspUrlCheck.setToolTipText(res.getString("DVerifyCertificate.jrbOcspUrlCheck.tooltip"));

        jtfOcspUrl = new JTextField("", 20);
        jtfOcspUrl.setEditable(false);
        jtfOcspUrl.setToolTipText(res.getString("DVerifyCertificate.jtfOcspUrl.tooltip"));

        jcbOcspDigestAlgorithm = new JComboBox<>(new DefaultComboBoxModel<>(OcspDigestAlgorithm.values()));
        jcbOcspDigestAlgorithm.setToolTipText(res.getString("DVerifyCertificate.jcbOcspDigestAlgorithm.tooltip"));
        jcbOcspDigestAlgorithm.setEnabled(false);

        jcbOcspIncludeNonce = new JCheckBox(res.getString("DVerifyCertificate.jcbOcspIncludeNonce.text"));
        jcbOcspIncludeNonce.setToolTipText(res.getString("DVerifyCertificate.jcbOcspIncludeNonce.tooltip"));
        jcbOcspIncludeNonce.setEnabled(false);

        jrbChainCheck = new JRadioButton(res.getString("DVerifyCertificate.jrbChainCheck.text"));
        jrbChainCheck.setToolTipText(res.getString("DVerifyCertificate.jrbChainCheck.tooltip"));

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(jrbCrlCheckDistPoint);
        buttonGroup.add(jrbCrlCheckFile);
        buttonGroup.add(jrbOcspAiaCheck);
        buttonGroup.add(jrbOcspUrlCheck);
        buttonGroup.add(jrbChainCheck);
        jrbCrlCheckDistPoint.setSelected(true);

        jcbSelectKeyStore = new JCheckBox(res.getString("DVerifyCertificate.jcbSelectKeyStore.text"));

        jcbKeyStore = new JComboBox<>(getKeystoreNames());
        jcbKeyStore.setToolTipText(res.getString("DVerifyCertificate.jcbKeyStore.tooltip"));
        jcbKeyStore.setEnabled(false);

        jbLoadKeystore = new JButton();
        jbLoadKeystore.setIcon(new ImageIcon(getClass().getResource("images/open.png")));
        jbLoadKeystore.setToolTipText(res.getString("DVerifyCertificate.jbLoadKeystore.tooltip"));
        jbLoadKeystore.setEnabled(false);

        jbOk = new JButton(res.getString("DVerifyCertificate.jbOk.text"));
        jbCancel = new JButton(res.getString("DVerifyCertificate.jbCancel.text"));
        jpButtons = PlatformUtil.createDialogButtonPanel(jbOk, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]unrel[]", "[]rel[]"));
        MiGUtil.addSeparator(pane, res.getString("DVerifyCertificate.jlCheckStatus.text"));
        pane.add(jrbCrlCheckDistPoint, "gapleft indent, wrap");
        pane.add(jrbCrlCheckFile, "gapleft indent, split 3");
        pane.add(jtfCrlFile, "growx");
        pane.add(jbLoadCrl, "wrap");
        pane.add(jrbOcspAiaCheck, "gapleft indent, wrap");
        pane.add(jrbOcspUrlCheck, "gapleft indent, split 3");
        pane.add(jtfOcspUrl, "growx, left, wrap");
        pane.add(new JLabel(res.getString("DVerifyCertificate.jlOcspDigestAlgorithm.text")), "gapleft indent, split 3, right");
        pane.add(jcbOcspDigestAlgorithm, "right");
        pane.add(jcbOcspIncludeNonce, "right, wrap");
        pane.add(jrbChainCheck, "gapleft indent, spanx, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jcbSelectKeyStore, "left, spanx, wrap");
        pane.add(new JLabel(res.getString("DVerifyCertificate.jlKeyStore.text")), "gapleft indent, split 3");
        pane.add(jcbKeyStore, "growx");
        pane.add(jbLoadKeystore, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "right, spanx");

        jrbCrlCheckDistPoint.addActionListener(evt -> updateVerifyControls());
        jrbCrlCheckFile.addActionListener(evt -> updateVerifyControls());
        jrbOcspAiaCheck.addActionListener(evt -> updateVerifyControls());
        jrbOcspUrlCheck.addActionListener(evt -> updateVerifyControls());
        jrbChainCheck.addActionListener(evt -> updateVerifyControls());
        jcbSelectKeyStore.addItemListener(evt -> updateVerifyControls());

        jbLoadCrl.addActionListener(evt -> {
            browsePressed();
        });

        jbOk.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DVerifyCertificate.this);
                okPressed();
            } finally {
                CursorUtil.setCursorFree(DVerifyCertificate.this);
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

        jbLoadKeystore.addActionListener(evt -> {
            OpenAction openAction = new OpenAction(kseFrame);
            openAction.actionPerformed(evt);
            updateVerifyControls();
            pack();
        });

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });
        setTitle(MessageFormat.format(res.getString("DVerifyCertificate.Title"), certificateAlias));

        setResizable(false);

        pack();
    }

    private void updateVerifyControls() {

        if (jrbCrlCheckFile.isSelected()) {
            jtfCrlFile.setEditable(true);
            jtfCrlFile.requestFocus();
            jbLoadCrl.setEnabled(true);
            jtfOcspUrl.setEditable(false);
        } else if (jrbOcspUrlCheck.isSelected()) {
            jtfCrlFile.setEditable(false);
            jbLoadCrl.setEnabled(false);
            jtfOcspUrl.setEditable(true);
            jtfOcspUrl.requestFocus();
        } else {
            jtfCrlFile.setEditable(false);
            jbLoadCrl.setEnabled(false);
            jtfOcspUrl.setEditable(false);
        }
        jcbKeyStore.setModel(getKeystoreNames());
        if (jcbSelectKeyStore.isSelected()) {
            jcbKeyStore.setEnabled(true);
            jbLoadKeystore.setEnabled(true);
        } else {
            jcbKeyStore.setEnabled(false);
            jbLoadKeystore.setEnabled(false);
        }
        if (jrbOcspUrlCheck.isSelected()) {
            jcbOcspDigestAlgorithm.setEnabled(true);
            jcbOcspIncludeNonce.setEnabled(true);
        } else {
            jcbOcspDigestAlgorithm.setEnabled(false);
            jcbOcspIncludeNonce.setEnabled(false);
        }
    }

    public boolean isVerifySelected() {
        return verifySelected;
    }

    public VerifyOptions getVerifyOption() {
        return verifyOption;
    }

    private void okPressed() {
        String title = MessageFormat.format(res.getString("DVerifyCertificate.Title"), certificateAlias);
        if (jrbCrlCheckDistPoint.isSelected()) {
            verifyOption = VerifyOptions.CRL_DIST;
        } else if (jrbCrlCheckFile.isSelected()) {
            if (jtfCrlFile.getText().isEmpty()) {
                JOptionPane.showMessageDialog(this, res.getString("DVerifyCertificate.ChooseCRLFile.Title"), title,
                                              JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            verifyOption = VerifyOptions.CRL_FILE;
            fileCrl = jtfCrlFile.getText();
        } else if (jrbOcspAiaCheck.isSelected()) {
            verifyOption = VerifyOptions.OCSP_AIA;
        } else if (jrbOcspUrlCheck.isSelected()) {
            if (jtfOcspUrl.getText().isEmpty()) {
                JOptionPane.showMessageDialog(this, res.getString("DVerifyCertificate.ReqOcspUrl.Title"), title,
                                              JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            verifyOption = VerifyOptions.OCSP_URL;
            ocspUrl = jtfOcspUrl.getText();
        } else {
            verifyOption = VerifyOptions.CHAIN;
        }
        if (jcbSelectKeyStore.isSelected()) {
            if (jcbKeyStore.getSelectedItem() == null) {
                JOptionPane.showMessageDialog(this,
                                              res.getString("DVerifyCertificate.ChooseCACertificatesKeyStore.Title"),
                                              title, JOptionPane.INFORMATION_MESSAGE);
                return;
            }
        }
        verifySelected = true;
        closeDialog();
    }

    public String getCrlFile() {
        return fileCrl;
    }

    public String getOcspUrl() {
        return ocspUrl;
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getCrlFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("DVerifyCertificate.ChooseCRLFile.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("DVerifyCertificate.ChooseCRLFile.button"));

        int rtnValue = chooser.showOpenDialog(this);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfCrlFile.setText(chosenFile.getAbsolutePath());
        }
    }

    public KeyStoreHistory getKeyStore() {
        if (jcbSelectKeyStore.isSelected()) {
            return (KeyStoreHistory) jcbKeyStore.getSelectedItem();
        } else {
            return null;
        }
    }

    private ComboBoxModel<KeyStoreHistory> getKeystoreNames() {
        KeyStoreHistory[] keyStoreHistories;
        if (kseFrame == null) {
            keyStoreHistories = new KeyStoreHistory[0];
        } else {
            keyStoreHistories = kseFrame.getKeyStoreHistories();
        }

        return new DefaultComboBoxModel<>(keyStoreHistories);
    }

    public OcspDigestAlgorithm getOcspDigestAlgorithm() {
        return (OcspDigestAlgorithm) jcbOcspDigestAlgorithm.getSelectedItem();
    }

    public boolean isOcspIncludeNonceSelected() {
        return jcbOcspIncludeNonce.isSelected();
    }

    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DVerifyCertificate(new javax.swing.JFrame(), "Test", null));
    }
}
