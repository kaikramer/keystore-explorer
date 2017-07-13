/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

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
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.asn1.Asn1Exception;

/**
 * Displays the details of a public key with the option to display its fields if
 * it is of a supported type (RSA or DSA).
 *
 */
public class DViewPublicKey extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpPublicKey;
	private JLabel jlAlgorithm;
	private JTextField jtfAlgorithm;
	private JLabel jlKeySize;
	private JTextField jtfKeySize;
	private JLabel jlFormat;
	private JTextField jtfFormat;
	private JLabel jlEncoded;
	private JTextField jtfEncoded;
	private JPanel jpButtons;
	private JButton jbFields;
	private JButton jbAsn1;
	private JButton jbOK;

	private PublicKey publicKey;

	/**
	 * Creates a new DViewPublicKey dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param publicKey
	 *            Public key to display
	 * @throws CryptoException
	 *             A problem was encountered getting the public key's details
	 */
	public DViewPublicKey(JFrame parent, String title, PublicKey publicKey) throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.publicKey = publicKey;
		initComponents();
	}

	/**
	 * Creates new DViewPublicKey dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param publicKey
	 *            Public key to display
	 * @throws CryptoException
	 *             A problem was encountered getting the public key's details
	 */
	public DViewPublicKey(JDialog parent, String title, PublicKey publicKey)
			throws CryptoException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.publicKey = publicKey;
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

		jlAlgorithm = new JLabel(res.getString("DViewPublicKey.jlAlgorithm.text"));
		GridBagConstraints gbc_jlAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlAlgorithm.gridy = 0;

		jtfAlgorithm = new JTextField(10);
		jtfAlgorithm.setEditable(false);
		jtfAlgorithm.setToolTipText(res.getString("DViewPublicKey.jtfAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfAlgorithm.gridy = 0;

		jlKeySize = new JLabel(res.getString("DViewPublicKey.jlKeySize.text"));
		GridBagConstraints gbc_jlKeySize = (GridBagConstraints) gbcLbl.clone();
		gbc_jlKeySize.gridy = 1;

		jtfKeySize = new JTextField(10);
		jtfKeySize.setEditable(false);
		jtfKeySize.setToolTipText(res.getString("DViewPublicKey.jtfKeySize.tooltip"));
		GridBagConstraints gbc_jtfKeySize = (GridBagConstraints) gbcTf.clone();
		gbc_jtfKeySize.gridy = 1;

		jlFormat = new JLabel(res.getString("DViewPublicKey.jlFormat.text"));
		GridBagConstraints gbc_jlFormat = (GridBagConstraints) gbcLbl.clone();
		gbc_jlFormat.gridy = 2;

		jtfFormat = new JTextField(10);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewPublicKey.jtfFormat.tooltip"));
		GridBagConstraints gbc_jtfFormat = (GridBagConstraints) gbcTf.clone();
		gbc_jtfFormat.gridy = 2;

		jlEncoded = new JLabel(res.getString("DViewPublicKey.jlEncoded.text"));
		GridBagConstraints gbc_jlEncoded = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEncoded.gridy = 3;

		jtfEncoded = new JTextField(20);
		jtfEncoded.setEditable(false);
		jtfEncoded.setToolTipText(res.getString("DViewPublicKey.jtfEncoded.tooltip"));
		GridBagConstraints gbc_jtfEncoded = (GridBagConstraints) gbcTf.clone();
		gbc_jtfEncoded.gridy = 3;

		jpPublicKey = new JPanel(new GridBagLayout());
		jpPublicKey.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpPublicKey.add(jlAlgorithm, gbc_jlAlgorithm);
		jpPublicKey.add(jtfAlgorithm, gbc_jtfAlgorithm);
		jpPublicKey.add(jlKeySize, gbc_jlKeySize);
		jpPublicKey.add(jtfKeySize, gbc_jtfKeySize);
		jpPublicKey.add(jlFormat, gbc_jlFormat);
		jpPublicKey.add(jtfFormat, gbc_jtfFormat);
		jpPublicKey.add(jlEncoded, gbc_jlEncoded);
		jpPublicKey.add(jtfEncoded, gbc_jtfEncoded);

		jbOK = new JButton(res.getString("DViewPublicKey.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbFields = new JButton(res.getString("DViewPublicKey.jbFields.text"));
		PlatformUtil.setMnemonic(jbFields, res.getString("DViewPublicKey.jbFields.mnemonic").charAt(0));
		jbFields.setToolTipText(res.getString("DViewPublicKey.jbFields.tooltip"));
		jbFields.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewPublicKey.this);
					fieldsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewPublicKey.this);
				}
			}
		});

		jbAsn1 = new JButton(res.getString("DViewPublicKey.jbAsn1.text"));

		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewPublicKey.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewPublicKey.jbAsn1.tooltip"));
		jbAsn1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewPublicKey.this);
					asn1DumpPressed();
				} finally {
					CursorUtil.setCursorFree(DViewPublicKey.this);
				}
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, new JButton[] { jbFields, jbAsn1 }, false);

		getContentPane().add(jpPublicKey, BorderLayout.CENTER);
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
		KeyInfo keyInfo = KeyPairUtil.getKeyInfo(publicKey);

		jtfAlgorithm.setText(keyInfo.getAlgorithm());

		Integer keyLength = keyInfo.getSize();

		if (keyLength != null) {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewPublicKey.jtfKeySize.text"), "" + keyLength));
		} else {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewPublicKey.jtfKeySize.text"), "?"));
		}

		jtfFormat.setText(publicKey.getFormat());

		jtfEncoded.setText("0x" + new BigInteger(1, publicKey.getEncoded()).toString(16).toUpperCase());
		jtfEncoded.setCaretPosition(0);

		if ((publicKey instanceof RSAPublicKey) || (publicKey instanceof DSAPublicKey)) {
			jbFields.setEnabled(true);
		} else {
			jbFields.setEnabled(false);
		}
	}

	private void fieldsPressed() {
		if (publicKey instanceof RSAPublicKey) {
			RSAPublicKey rsaPub = (RSAPublicKey) publicKey;

			DViewAsymmetricKeyFields dViewAsymmetricKeyFields = new DViewAsymmetricKeyFields(this,
					res.getString("DViewPublicKey.RsaFields.Title"), rsaPub);
			dViewAsymmetricKeyFields.setLocationRelativeTo(this);
			dViewAsymmetricKeyFields.setVisible(true);
		} else if (publicKey instanceof DSAPublicKey) {
			DSAPublicKey dsaPub = (DSAPublicKey) publicKey;

			DViewAsymmetricKeyFields dViewAsymmetricKeyFields = new DViewAsymmetricKeyFields(this,
					res.getString("DViewPublicKey.DsaFields.Title"), dsaPub);
			dViewAsymmetricKeyFields.setLocationRelativeTo(this);
			dViewAsymmetricKeyFields.setVisible(true);
		}
	}

	private void asn1DumpPressed() {
		try {
			DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, publicKey);
			dViewAsn1Dump.setLocationRelativeTo(this);
			dViewAsn1Dump.setVisible(true);
		} catch (Asn1Exception ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		} catch (IOException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
