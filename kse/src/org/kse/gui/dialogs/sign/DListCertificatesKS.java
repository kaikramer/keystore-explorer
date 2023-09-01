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

package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.security.cert.X509Certificate;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.OpenAction;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.history.KeyStoreHistory;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that display a list of certificate from keystore
 */
public class DListCertificatesKS extends JEscDialog {

    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
    private static final String CANCEL_KEY = "CANCEL_KEY";

    private KseFrame kseFrame;

    private JLabel jlKeyStore;
    private JComboBox<KeyStoreHistory> jcbKeyStore;
    private JButton jbLoadKeystore;
    private JListCertificates jListCertificates;
    private JButton jbOK;
    private JButton jbCancel;

    private X509Certificate cert;

    /**
     * Creates a new DListCertificatesKS
     *
     * @param parent   The parent frame
     * @param kseFrame KeyStore Explorer application frame
     */
    public DListCertificatesKS(JFrame parent, KseFrame kseFrame) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        setTitle(res.getString("DListCertificatesKS.Title"));
        this.kseFrame = kseFrame;
        this.cert = null;
        initComponents();
    }

    private void initComponents() {

        jlKeyStore = new JLabel(res.getString("DListCertificatesKS.jlKeyStore.text"));
        jcbKeyStore = new JComboBox<>(getKeystoreNames());
        jcbKeyStore.setToolTipText(res.getString("DListCertificatesKS.jcbKeyStore.tooltip"));
        jcbKeyStore.setPreferredSize(new Dimension(200, 20));

        jbLoadKeystore = new JButton();
        jbLoadKeystore.setIcon(new ImageIcon(getClass().getResource("images/open.png")));
        jbLoadKeystore.setToolTipText(res.getString("DListCertificatesKS.jbLoadKeystore.tooltip"));

        jListCertificates = new JListCertificates();

        jbOK = new JButton(res.getString("DListCertificatesKS.jbOK.text"));
        jbCancel = new JButton(res.getString("DListCertificatesKS.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog", "[left]rel[]", "[]"));

        pane.add(jlKeyStore, "split");
        pane.add(jcbKeyStore);
        pane.add(jbLoadKeystore, "wrap");
        pane.add(jListCertificates, "spanx, push, grow, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jpButtons, "right, spanx");

        jcbKeyStore.addActionListener(evt -> {
            updateCertificateControls();
        });

        jbLoadKeystore.addActionListener(this::updateKeyStoreList);

        // allow to close dialog with enter key
        KeyStroke enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0);
        jListCertificates.getJtListCerts()
                         .getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                         .put(enter, "Enter");
        jListCertificates.getJtListCerts().getActionMap().put("Enter", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                okPressed();
            }
        });

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());

        populate();

        setMinimumSize(new Dimension(400, 200));
        setResizable(true);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void updateKeyStoreList(ActionEvent evt) {
        OpenAction openAction = new OpenAction(kseFrame);
        openAction.actionPerformed(evt);

        populate();

        if (openAction.hasNewKeyStoreBeenAdded()) {
            KeyStoreHistory[] keyStoreHistories = kseFrame.getKeyStoreHistories();
            jcbKeyStore.setSelectedItem(keyStoreHistories[keyStoreHistories.length - 1]);
        }

        pack();
    }

    private void populate() {
        jcbKeyStore.setModel(getKeystoreNames());
        updateCertificateControls();
    }

    private void updateCertificateControls() {
        jListCertificates.load((KeyStoreHistory) jcbKeyStore.getSelectedItem());
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    private void okPressed() {
        X509Certificate selectedCert = jListCertificates.getSelectedCert();
        if (selectedCert == null) {
            JOptionPane.showMessageDialog(this, res.getString("DListCertificatesKS.SelectCertificate.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
            return;
        }
        cert = selectedCert;
        closeDialog();
    }

    public X509Certificate getCertificate() {
        return cert;
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

    public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException {
        DialogViewer.run(new DListCertificatesKS(new JFrame(), null));
    }
}
