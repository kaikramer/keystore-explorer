/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import net.miginfocom.swing.MigLayout;
import net.sf.keystore_explorer.ApplicationSettings;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.MiGUtil;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.actions.OpenAction;
import net.sf.keystore_explorer.utilities.history.KeyStoreHistory;

/**
 * Dialog used for SSL connection details (host and port) to examine.
 *
 */
public class DExamineSsl extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");
	private ApplicationSettings applicationSettings = ApplicationSettings.getInstance();

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlSslHost;
	private JComboBox<String> jcbSslHost;
	private JLabel jlSslPort;
	private JComboBox<String> jcbSslPort;
	private JCheckBox jcbClientAuth;
	private JComboBox<KeyStoreHistory> jcbKeyStore;
	private JComboBox<String> jcbAlias;
	private JButton jbLoadKeystore;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private String sslHost;
	private int sslPort = -1;

	private KseFrame kseFrame;

	/**
	 * Creates new DExamineSsl dialog.
	 *
	 * @param parent
	 *            Parent frame
	 */
	public DExamineSsl(JFrame parent, KseFrame kseFrame) {
		super(parent, res.getString("DExamineSsl.Title"), Dialog.ModalityType.APPLICATION_MODAL);
	    this.kseFrame = kseFrame;
		initComponents();
	}

	private void initComponents() {
		getContentPane().setLayout(new BorderLayout());

		jlSslHost = new JLabel(res.getString("DExamineSsl.jlSslHost.text"));

		jcbSslHost = new JComboBox<String>();
		jcbSslHost.setEditable(true);
		jcbSslHost.setPrototypeDisplayValue("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		jcbSslHost.setToolTipText(res.getString("DExamineSsl.jtfSslHost.tooltip"));
//		jtfSslHost.setSelectionStart(0);
//		jtfSslHost.setSelectionEnd(jtfSslHost.getText().length());
		jcbSslHost.setModel(new DefaultComboBoxModel<String>(getSslHosts()));

		jlSslPort = new JLabel(res.getString("DExamineSsl.jlSslPort.text"));

		jcbSslPort = new JComboBox<String>();
		jcbSslPort.setEditable(true);
		jcbSslPort.setToolTipText(res.getString("DExamineSsl.jtfSslPort.tooltip"));
		jcbSslPort.setModel(new DefaultComboBoxModel<String>(getSslPorts()));

		jcbClientAuth = new JCheckBox("Enable Client Authentication");

		jcbKeyStore = new JComboBox<KeyStoreHistory>(getKeystoreNames());
		//jcbAlias = new JComboBox<String>(getAliases((String) jcbKeyStore.getSelectedItem()));

		jbLoadKeystore = new JButton();
		jbLoadKeystore.setIcon(new ImageIcon(getClass().getResource("images/open.png")));

		jbOK = new JButton(res.getString("DExamineSsl.jbOK.text"));

		jbCancel = new JButton(res.getString("DExamineSsl.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[para]unrel[right]unrel[]", "[]unrel[]"));
        MiGUtil.addSeparator(pane, "Connection Settings");
        pane.add(jlSslHost, "skip");
        pane.add(jcbSslHost, "sgx, wrap");
        pane.add(jlSslPort, "skip");
        pane.add(jcbSslPort, "sgx, wrap para");
        MiGUtil.addSeparator(pane, "Client Authentication");
        pane.add(jcbClientAuth, "left, spanx, wrap");
        pane.add(new JLabel("KeyStore:"), "skip");
        pane.add(jcbKeyStore, "sgx");
        pane.add(jbLoadKeystore, "wrap para");
        //pane.add(new JLabel("Alias:"), "skip");
        //pane.add(jcbAlias, "sgx, wrap para");
        pane.add(new JSeparator(), "spanx, growx, wrap para");
        pane.add(jpButtons, "right, spanx");

        jcbClientAuth.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                updateClientAuthComponents();
            }
        });

        jbLoadKeystore.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OpenAction openAction = new OpenAction(kseFrame);
                openAction.actionPerformed(evt);
                updateClientAuthComponents();
            }
        });

        jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        jbCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		updateClientAuthComponents();

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private ComboBoxModel<KeyStoreHistory> getKeystoreNames() {
	    KeyStoreHistory[] keyStoreHistories = kseFrame.getKeyStoreHistories();
//        String[] keyStoreNames = new String[keyStoreHistories.length];
//        for (int i = 0; i < keyStoreHistories.length; i++) {
//            keyStoreNames[i] = keyStoreHistories[i].getName();
//        }
        return new DefaultComboBoxModel<KeyStoreHistory>(keyStoreHistories);
    }

    private ComboBoxModel<String> getAliases(String keyStoreName) {
        KeyStoreHistory[] keyStoreHistories = kseFrame.getKeyStoreHistories();
        for (int i = 0; i < keyStoreHistories.length; i++) {
            if (keyStoreHistories[i].getName().equals(keyStoreName)) {
                KeyStore keyStore = keyStoreHistories[i].getCurrentState().getKeyStore();
                List<String> aliasNames = new ArrayList<String>();
                Enumeration<?> en = null;
                try {
                    en = keyStore.aliases();
                    while ( en.hasMoreElements()) {
                        String aliasName = (String) en.nextElement();
                        aliasNames.add(aliasName);
                    }
                } catch (KeyStoreException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                return new DefaultComboBoxModel<String>(aliasNames.toArray(new String[0]));
            }
        }
        return new DefaultComboBoxModel<String>();
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
	 * User wants to use SSL client authentication?
	 *
	 * @return True if user wants to use SSL client authentication
	 */
	public boolean useClientAuth() {
	    return jcbClientAuth.isSelected();
	}

	/**
	 * Get selected key store
	 *
	 * @return KeyStore (wrapped in a history object)
	 */
	public KeyStoreHistory getKeyStore() {
	    return (KeyStoreHistory) jcbKeyStore.getSelectedItem();
	}

    private String[] getSslHosts() {
        String sslHosts = applicationSettings.getSslHosts();
        String[] hosts = sslHosts.split(";");
        return hosts;
    }

    private void setSslHosts(String newSslHost) {

        // add new ssl host at first position of the list
        StringBuilder sb = new StringBuilder(newSslHost);
        String sslHosts = applicationSettings.getSslHosts();
        String[] hosts = sslHosts.split(";");
        for (int i = 0; i < hosts.length; i++) {

            // save maximum of 10 host names
            if (i >= 10) {
                break;
            }

            String host = hosts[i];

            // if saved ssl host list already contains new host, do nothing
            if (host.equals(newSslHost)) {
                return;
            }

            sb.append(";");
            sb.append(host);
        }

        applicationSettings.setSslHosts(sb.toString());
    }

    private String[] getSslPorts() {
        String sslPorts = applicationSettings.getSslPorts();
        String[] ports = sslPorts.split(";");
        return ports;
    }

    private void updateClientAuthComponents() {
	    jcbKeyStore.setEnabled(jcbClientAuth.isSelected());
	    //jcbAlias.setEnabled(jcbClientAuth.isSelected());
	    jbLoadKeystore.setEnabled(jcbClientAuth.isSelected());

	    jcbKeyStore.setModel(getKeystoreNames());
    }

    private void okPressed() {
		String sslHost = ((String) jcbSslHost.getSelectedItem()).trim();

		if (sslHost.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DExamineSsl.SslHostReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		String sslPortStr = ((String) jcbSslPort.getSelectedItem()).trim();

		if (sslPortStr.length() == 0) {
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
		setSslHosts(sslHost);

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
