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
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;

/**
 * Dialog used for SSL connection details (host and port) to examine.
 * 
 */
public class DExamineSsl extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpSslDetails;
	private JLabel jlSslHost;
	private JTextField jtfSslHost;
	private JLabel jlSslPort;
	private JTextField jtfSslPort;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;
	private String sslHost;
	private int sslPort = -1;

	/**
	 * Creates new DExamineSsl dialog.
	 * 
	 * @param parent
	 *            Parent frame
	 */
	public DExamineSsl(JFrame parent) {
		super(parent, res.getString("DExamineSsl.Title"), Dialog.ModalityType.APPLICATION_MODAL);
		initComponents();
	}

	private void initComponents() {
		getContentPane().setLayout(new BorderLayout());

		jlSslHost = new JLabel(res.getString("DExamineSsl.jlSslHost.text"));

		GridBagConstraints gbc_jlSslHost = new GridBagConstraints();
		gbc_jlSslHost.gridx = 0;
		gbc_jlSslHost.gridy = 0;
		gbc_jlSslHost.gridwidth = 1;
		gbc_jlSslHost.gridheight = 1;
		gbc_jlSslHost.insets = new Insets(5, 5, 5, 5);
		gbc_jlSslHost.anchor = GridBagConstraints.EAST;

		jtfSslHost = new JTextField(20);
		jtfSslHost.setToolTipText(res.getString("DExamineSsl.jtfSslHost.tooltip"));
		jtfSslHost.setSelectionStart(0);
		jtfSslHost.setSelectionEnd(jtfSslHost.getText().length());

		GridBagConstraints gbc_jtfSslHost = new GridBagConstraints();
		gbc_jtfSslHost.gridx = 1;
		gbc_jtfSslHost.gridy = 0;
		gbc_jtfSslHost.gridwidth = 1;
		gbc_jtfSslHost.gridheight = 1;
		gbc_jtfSslHost.insets = new Insets(5, 5, 5, 5);
		gbc_jtfSslHost.anchor = GridBagConstraints.WEST;

		jlSslPort = new JLabel(res.getString("DExamineSsl.jlSslPort.text"));

		GridBagConstraints gbc_jlSslPort = new GridBagConstraints();
		gbc_jlSslPort.gridx = 0;
		gbc_jlSslPort.gridy = 1;
		gbc_jlSslPort.gridwidth = 1;
		gbc_jlSslPort.gridheight = 1;
		gbc_jlSslPort.insets = new Insets(5, 5, 5, 5);
		gbc_jlSslPort.anchor = GridBagConstraints.EAST;

		jtfSslPort = new JTextField(4);
		jtfSslPort.setToolTipText(res.getString("DExamineSsl.jtfSslPort.tooltip"));
		jtfSslPort.setText(res.getString("DExamineSsl.jtfSslPort.text"));

		GridBagConstraints gbc_jtfSslPort = new GridBagConstraints();
		gbc_jtfSslPort.gridx = 1;
		gbc_jtfSslPort.gridy = 1;
		gbc_jtfSslPort.gridwidth = 1;
		gbc_jtfSslPort.gridheight = 1;
		gbc_jtfSslPort.insets = new Insets(5, 5, 5, 5);
		gbc_jtfSslPort.anchor = GridBagConstraints.WEST;

		jbOK = new JButton(res.getString("DExamineSsl.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DExamineSsl.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpSslDetails = new JPanel(new GridBagLayout());
		jpSslDetails.add(jlSslHost, gbc_jlSslHost);
		jpSslDetails.add(jtfSslHost, gbc_jtfSslHost);
		jpSslDetails.add(jlSslPort, gbc_jlSslPort);
		jpSslDetails.add(jtfSslPort, gbc_jtfSslPort);
		jpSslDetails.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().add(jpSslDetails, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
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

	private void okPressed() {
		String sslHost = jtfSslHost.getText().trim();

		if (sslHost.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DExamineSsl.SslHostReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		String sslPortStr = jtfSslPort.getText().trim();

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
