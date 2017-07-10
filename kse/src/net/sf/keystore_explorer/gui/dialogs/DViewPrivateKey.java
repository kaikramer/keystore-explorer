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
package net.sf.keystore_explorer.gui.dialogs;

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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
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

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.KeyInfo;
import net.sf.keystore_explorer.crypto.keypair.KeyPairUtil;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.asn1.Asn1Exception;

/**
 * Displays the details of a private key with the option to display its fields
 * if it is of a supported type (RSA or DSA).
 *
 */
public class DViewPrivateKey extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private JPanel jpPrivateKey;
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

	private PrivateKey privateKey;

	private Provider provider;

	/**
	 * Creates a new DViewPrivateKey dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param privateKey
	 *            Private key to display
	 * @throws CryptoException
	 *             A problem was encountered getting the private key's details
	 */
	public DViewPrivateKey(JFrame parent, String title, PrivateKey privateKey, Provider provider)
			throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.privateKey = privateKey;
		this.provider = provider;
		initComponents();
	}

	/**
	 * Creates new DViewPrivateKey dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param privateKey
	 *            Private key to display
	 * @throws CryptoException
	 *             A problem was encountered getting the private key's details
	 */
	public DViewPrivateKey(JDialog parent, String title, PrivateKey privateKey,
			Provider provider) throws CryptoException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.privateKey = privateKey;
		this.provider = provider;
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

		jlAlgorithm = new JLabel(res.getString("DViewPrivateKey.jlAlgorithm.text"));
		GridBagConstraints gbc_jlAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlAlgorithm.gridy = 0;

		jtfAlgorithm = new JTextField(10);
		jtfAlgorithm.setEditable(false);
		jtfAlgorithm.setToolTipText(res.getString("DViewPrivateKey.jtfAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfAlgorithm.gridy = 0;

		jlKeySize = new JLabel(res.getString("DViewPrivateKey.jlKeySize.text"));
		GridBagConstraints gbc_jlKeySize = (GridBagConstraints) gbcLbl.clone();
		gbc_jlKeySize.gridy = 1;

		jtfKeySize = new JTextField(10);
		jtfKeySize.setEditable(false);
		jtfKeySize.setToolTipText(res.getString("DViewPrivateKey.jtfKeySize.tooltip"));
		GridBagConstraints gbc_jtfKeySize = (GridBagConstraints) gbcTf.clone();
		gbc_jtfKeySize.gridy = 1;

		jlFormat = new JLabel(res.getString("DViewPrivateKey.jlFormat.text"));
		GridBagConstraints gbc_jlFormat = (GridBagConstraints) gbcLbl.clone();
		gbc_jlFormat.gridy = 2;

		jtfFormat = new JTextField(10);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewPrivateKey.jtfFormat.tooltip"));
		GridBagConstraints gbc_jtfFormat = (GridBagConstraints) gbcTf.clone();
		gbc_jtfFormat.gridy = 2;

		jlEncoded = new JLabel(res.getString("DViewPrivateKey.jlEncoded.text"));
		GridBagConstraints gbc_jlEncoded = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEncoded.gridy = 3;

		jtfEncoded = new JTextField(20);
		jtfEncoded.setEditable(false);
		jtfEncoded.setToolTipText(res.getString("DViewPrivateKey.jtfEncoded.tooltip"));
		GridBagConstraints gbc_jtfEncoded = (GridBagConstraints) gbcTf.clone();
		gbc_jtfEncoded.gridy = 3;

		jpPrivateKey = new JPanel(new GridBagLayout());
		jpPrivateKey.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpPrivateKey.add(jlAlgorithm, gbc_jlAlgorithm);
		jpPrivateKey.add(jtfAlgorithm, gbc_jtfAlgorithm);
		jpPrivateKey.add(jlKeySize, gbc_jlKeySize);
		jpPrivateKey.add(jtfKeySize, gbc_jtfKeySize);
		jpPrivateKey.add(jlFormat, gbc_jlFormat);
		jpPrivateKey.add(jtfFormat, gbc_jtfFormat);
		jpPrivateKey.add(jlEncoded, gbc_jlEncoded);
		jpPrivateKey.add(jtfEncoded, gbc_jtfEncoded);

		jbOK = new JButton(res.getString("DViewPrivateKey.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbFields = new JButton(res.getString("DViewPrivateKey.jbFields.text"));
		PlatformUtil.setMnemonic(jbFields, res.getString("DViewPrivateKey.jbFields.mnemonic").charAt(0));
		jbFields.setToolTipText(res.getString("DViewPrivateKey.jbFields.tooltip"));
		jbFields.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewPrivateKey.this);
					fieldsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewPrivateKey.this);
				}
			}
		});

		jbAsn1 = new JButton(res.getString("DViewPrivateKey.jbAsn1.text"));

		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewPrivateKey.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewPrivateKey.jbAsn1.tooltip"));
		jbAsn1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewPrivateKey.this);
					asn1DumpPressed();
				} finally {
					CursorUtil.setCursorFree(DViewPrivateKey.this);
				}
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, new JButton[] { jbFields, jbAsn1 }, false);

		getContentPane().add(jpPrivateKey, BorderLayout.CENTER);
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
		KeyInfo keyInfo = KeyPairUtil.getKeyInfo(privateKey);

		jtfAlgorithm.setText(keyInfo.getAlgorithm());

		Integer keyLength = keyInfo.getSize();

		if (keyLength != null) {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewPrivateKey.jtfKeySize.text"), "" + keyLength));
		} else {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewPrivateKey.jtfKeySize.text"), "?"));
		}

		jtfFormat.setText(privateKey.getFormat());

		jtfEncoded.setText("0x" + new BigInteger(1, privateKey.getEncoded()).toString(16).toUpperCase());
		jtfEncoded.setCaretPosition(0);

		if ((privateKey instanceof RSAPrivateKey) || (privateKey instanceof DSAPrivateKey)) {
			jbFields.setEnabled(true);
		} else {
			jbFields.setEnabled(false);
		}
	}

	private void fieldsPressed() {
		if (privateKey instanceof RSAPrivateKey) {
			RSAPrivateKey rsaPvk = (RSAPrivateKey) privateKey;

			DViewAsymmetricKeyFields dViewAsymmetricKeyFields = new DViewAsymmetricKeyFields(this,
					res.getString("DViewPrivateKey.RsaFields.Title"), rsaPvk);
			dViewAsymmetricKeyFields.setLocationRelativeTo(this);
			dViewAsymmetricKeyFields.setVisible(true);
		} else if (privateKey instanceof DSAPrivateKey) {
			DSAPrivateKey dsaPvk = (DSAPrivateKey) privateKey;

			DViewAsymmetricKeyFields dViewAsymmetricKeyFields = new DViewAsymmetricKeyFields(this,
					res.getString("DViewPrivateKey.DsaFields.Title"), dsaPvk);
			dViewAsymmetricKeyFields.setLocationRelativeTo(this);
			dViewAsymmetricKeyFields.setVisible(true);
		}
	}

	private void asn1DumpPressed() {
		try {
			DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, privateKey);
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
