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
package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import org.kse.gui.preferences.ApplicationSettings;
import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.history.KeyStoreHistory;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used for SSL connection details (host and port) to examine.
 */
public class DExamineSsl extends JEscDialog {
    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");
    private transient ApplicationSettings applicationSettings = ApplicationSettings.getInstance();

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlSslHost;
    private JComboBox<String> jcbSslHost;
    private JLabel jlSslPort;
    private JComboBox<String> jcbSslPort;
    private JPanel jpButtons;
    private JButton jbOK;
    private JButton jbCancel;

    private String sslHost;
    private int sslPort = -1;

    private KseFrame kseFrame;
    private boolean cancelled = true;

    /**
     * Creates new DExamineSsl dialog.
     *
     * @param parent Parent frame
     */
    public DExamineSsl(JFrame parent, KseFrame kseFrame) {
        super(parent, res.getString("DExamineSsl.Title"), Dialog.ModalityType.DOCUMENT_MODAL);
        this.kseFrame = kseFrame;
        initComponents();
    }

    private void initComponents() {
        jlSslHost = new JLabel(res.getString("DExamineSsl.jlSslHost.text"));

        jcbSslHost = new JComboBox<>();
        jcbSslHost.setEditable(true);
        jcbSslHost.setPrototypeDisplayValue("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        jcbSslHost.setToolTipText(res.getString("DExamineSsl.jtfSslHost.tooltip"));
        jcbSslHost.setModel(new DefaultComboBoxModel<>(getSslHosts()));

        jlSslPort = new JLabel(res.getString("DExamineSsl.jlSslPort.text"));

        jcbSslPort = new JComboBox<>();
        jcbSslPort.setEditable(true);
        jcbSslPort.setToolTipText(res.getString("DExamineSsl.jtfSslPort.tooltip"));
        jcbSslPort.setModel(new DefaultComboBoxModel<>(getSslPorts()));

        jbOK = new JButton(res.getString("DExamineSsl.jbOK.text"));

        jbCancel = new JButton(res.getString("DExamineSsl.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[indent]unrel[right]unrel[grow]", ""));
        MiGUtil.addSeparator(pane, res.getString("DExamineSsl.jlConnSettings.text"));
        pane.add(jlSslHost, "skip");
        pane.add(jcbSslHost, "sgx, growx, wrap");
        pane.add(jlSslPort, "skip");
        pane.add(jcbSslPort, "sgx, growx, wrap para");
        pane.add(jpButtons, "right, spanx");

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

        getRootPane().setDefaultButton(jbOK);

        setResizable(false);

        pack();
    }

    private ComboBoxModel<KeyStoreHistory> getKeystoreNames() {
        KeyStoreHistory[] keyStoreHistories = kseFrame.getKeyStoreHistories();
        return new DefaultComboBoxModel<>(keyStoreHistories);
    }

    /**
     * Get selected SSL hostname.
     *
     * @return Hostname or null of dialog cancelled by user
     */
    public String getSslHost() {
        return sslHost;
    }

    /**
     * Get selected SSL port number.
     *
     * @return Port number or -1 if dialog cancelled by user
     */
    public int getSslPort() {
        return sslPort;
    }

    /**
     * Was the dialog cancelled?
     *
     * @return True if it was cancelled
     */
    public boolean wasCancelled() {
        return cancelled;
    }

    private String[] getSslHosts() {
        String sslHosts = applicationSettings.getSslHosts();
        return sslHosts.split(";");
    }

    private String[] getSslPorts() {
        String sslPorts = applicationSettings.getSslPorts();
        return sslPorts.split(";");
    }

    private void okPressed() {
        String sslHost = ((String) jcbSslHost.getSelectedItem()).trim();

        if (sslHost.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExamineSsl.SslHostReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        String sslPortStr = ((String) jcbSslPort.getSelectedItem()).trim();

        if (sslPortStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExamineSsl.SslPortReq.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }

        int sslPort = 0;

        try {
            sslPort = Integer.parseInt(sslPortStr);

            if (sslPort < 1) {
                JOptionPane.showMessageDialog(this, res.getString("DExamineSsl.PositiveIntegerSslPortReq.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, res.getString("DExamineSsl.PositiveIntegerSslPortReq.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        this.sslHost = sslHost;
        this.sslPort = sslPort;

        // save host/port in preferences
        applicationSettings.addSslHost(sslHost);
        applicationSettings.addSslPort(sslPortStr);

        cancelled = false;
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
        DialogViewer.run(new DExamineSsl(new javax.swing.JFrame(), new KseFrame()));
    }
}
