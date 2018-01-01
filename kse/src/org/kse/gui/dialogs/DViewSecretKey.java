/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Displays the details of a secret key.
 *
 */
public class DViewSecretKey extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpSecretKey;
	private JLabel jlAlgorithm;
	private JTextField jtfAlgorithm;
	private JLabel jlKeySize;
	private JTextField jtfKeySize;
	private JLabel jlFormat;
	private JTextField jtfFormat;
	private JLabel jlEncoded;
	private JTextField jtfEncoded;
	private JPanel jpButtons;
	private JButton jbOK;

	private SecretKey secretKey;

	/**
	 * Creates a new DViewSecretKey dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param secretKey
	 *            Secret key to display
	 * @throws CryptoException
	 *             A problem was encountered getting the secret key's details
	 */
	public DViewSecretKey(JFrame parent, String title, SecretKey secretKey) throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.secretKey = secretKey;
		initComponents();
	}

	/**
	 * Creates new DViewSecretKey dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param modality
	 *            Dialog modality
	 * @param secretKey
	 *            Secret key to display
	 * @throws CryptoException
	 *             A problem was encountered getting the secret key's details
	 */
	public DViewSecretKey(JDialog parent, String title, Dialog.ModalityType modality, SecretKey secretKey)
			throws CryptoException {
		super(parent, title, modality);
		this.secretKey = secretKey;
		initComponents();
	}

	private void initComponents() throws CryptoException {
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 1;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcTf = new GridBagConstraints();
		gbcTf.gridx = 1;
		gbcTf.gridwidth = 1;
		gbcTf.gridheight = 1;
		gbcTf.insets = new Insets(5, 5, 5, 5);
		gbcTf.anchor = GridBagConstraints.WEST;

		jlAlgorithm = new JLabel(res.getString("DViewSecretKey.jlAlgorithm.text"));
		GridBagConstraints gbc_jlAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlAlgorithm.gridy = 0;

		jtfAlgorithm = new JTextField(10);
		jtfAlgorithm.setEditable(false);
		jtfAlgorithm.setToolTipText(res.getString("DViewSecretKey.jtfAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfAlgorithm.gridy = 0;

		jlKeySize = new JLabel(res.getString("DViewSecretKey.jlKeySize.text"));
		GridBagConstraints gbc_jlKeySize = (GridBagConstraints) gbcLbl.clone();
		gbc_jlKeySize.gridy = 1;

		jtfKeySize = new JTextField(10);
		jtfKeySize.setEditable(false);
		jtfKeySize.setToolTipText(res.getString("DViewSecretKey.jtfKeySize.tooltip"));
		GridBagConstraints gbc_jtfKeySize = (GridBagConstraints) gbcTf.clone();
		gbc_jtfKeySize.gridy = 1;

		jlFormat = new JLabel(res.getString("DViewSecretKey.jlFormat.text"));
		GridBagConstraints gbc_jlFormat = (GridBagConstraints) gbcLbl.clone();
		gbc_jlFormat.gridy = 2;

		jtfFormat = new JTextField(10);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewSecretKey.jtfFormat.tooltip"));
		GridBagConstraints gbc_jtfFormat = (GridBagConstraints) gbcTf.clone();
		gbc_jtfFormat.gridy = 2;

		jlEncoded = new JLabel(res.getString("DViewSecretKey.jlEncoded.text"));
		GridBagConstraints gbc_jlEncoded = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEncoded.gridy = 3;

		jtfEncoded = new JTextField(20);
		jtfEncoded.setEditable(false);
		jtfEncoded.setToolTipText(res.getString("DViewSecretKey.jtfEncoded.tooltip"));
		GridBagConstraints gbc_jtfEncoded = (GridBagConstraints) gbcTf.clone();
		gbc_jtfEncoded.gridy = 3;

		jpSecretKey = new JPanel(new GridBagLayout());
		jpSecretKey.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpSecretKey.add(jlAlgorithm, gbc_jlAlgorithm);
		jpSecretKey.add(jtfAlgorithm, gbc_jtfAlgorithm);
		jpSecretKey.add(jlKeySize, gbc_jlKeySize);
		jpSecretKey.add(jtfKeySize, gbc_jtfKeySize);
		jpSecretKey.add(jlFormat, gbc_jlFormat);
		jpSecretKey.add(jtfFormat, gbc_jtfFormat);
		jpSecretKey.add(jlEncoded, gbc_jlEncoded);
		jpSecretKey.add(jtfEncoded, gbc_jtfEncoded);

		jbOK = new JButton(res.getString("DViewSecretKey.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().add(jpSecretKey, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setResizable(false);

		populateDialog();

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				jbOK.requestFocus();
			}
		});
	}

	private void populateDialog() throws CryptoException {
		KeyInfo keyInfo = SecretKeyUtil.getKeyInfo(secretKey);

		String algorithm = keyInfo.getAlgorithm();

		// Try and get friendly algorithm name
		SecretKeyType secretKeyType = SecretKeyType.resolveJce(algorithm);

		if (secretKeyType != null) {
			algorithm = secretKeyType.friendly();
		}

		jtfAlgorithm.setText(algorithm);

		Integer keyLength = keyInfo.getSize();

		if (keyLength != null) {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewSecretKey.jtfKeySize.text"), "" + keyLength));
		} else {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewSecretKey.jtfKeySize.text"), "?"));
		}

		jtfFormat.setText(secretKey.getFormat());

		jtfEncoded.setText("0x" + new BigInteger(1, secretKey.getEncoded()).toString(16).toUpperCase());
		jtfEncoded.setCaretPosition(0);
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
