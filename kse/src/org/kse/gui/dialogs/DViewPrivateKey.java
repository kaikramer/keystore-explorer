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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.asn1.Asn1Exception;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a private key with the option to display its fields
 * if it is of a supported type (RSA or DSA).
 *
 */
public class DViewPrivateKey extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JLabel jlAlgorithm;
	private JTextField jtfAlgorithm;
	private JLabel jlKeySize;
	private JTextField jtfKeySize;
	private JLabel jlFormat;
	private JTextField jtfFormat;
	private JLabel jlEncoded;
	private JTextField jtfEncoded;
	private JButton jbPem;
	private JButton jbFields;
	private JButton jbAsn1;
	private JButton jbOK;

	private PrivateKey privateKey;

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
		initComponents();
	}

	private void initComponents() throws CryptoException {

		jlAlgorithm = new JLabel(res.getString("DViewPrivateKey.jlAlgorithm.text"));

		jtfAlgorithm = new JTextField(10);
		jtfAlgorithm.setEditable(false);
		jtfAlgorithm.setToolTipText(res.getString("DViewPrivateKey.jtfAlgorithm.tooltip"));

		jlKeySize = new JLabel(res.getString("DViewPrivateKey.jlKeySize.text"));

		jtfKeySize = new JTextField(10);
		jtfKeySize.setEditable(false);
		jtfKeySize.setToolTipText(res.getString("DViewPrivateKey.jtfKeySize.tooltip"));

		jlFormat = new JLabel(res.getString("DViewPrivateKey.jlFormat.text"));

		jtfFormat = new JTextField(10);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewPrivateKey.jtfFormat.tooltip"));

		jlEncoded = new JLabel(res.getString("DViewPrivateKey.jlEncoded.text"));

		jtfEncoded = new JTextField(30);
		jtfEncoded.setEditable(false);
		jtfEncoded.setToolTipText(res.getString("DViewPrivateKey.jtfEncoded.tooltip"));

		jbPem = new JButton(res.getString("DViewPrivateKey.jbPem.text"));
		PlatformUtil.setMnemonic(jbPem, res.getString("DViewPrivateKey.jbPem.mnemonic").charAt(0));
		jbPem.setToolTipText(res.getString("DViewPrivateKey.jbPem.tooltip"));

		jbFields = new JButton(res.getString("DViewPrivateKey.jbFields.text"));
		PlatformUtil.setMnemonic(jbFields, res.getString("DViewPrivateKey.jbFields.mnemonic").charAt(0));
		jbFields.setToolTipText(res.getString("DViewPrivateKey.jbFields.tooltip"));
		
		jbAsn1 = new JButton(res.getString("DViewPrivateKey.jbAsn1.text"));
		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewPrivateKey.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewPrivateKey.jbAsn1.tooltip"));
		
		jbOK = new JButton(res.getString("DViewPrivateKey.jbOK.text"));

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		pane.add(jlAlgorithm, "");
		pane.add(jtfAlgorithm, "growx, wrap");
		pane.add(jlKeySize, "");
		pane.add(jtfKeySize, "growx, wrap");
		pane.add(jlFormat, "");
		pane.add(jtfFormat, "growx, wrap");
		pane.add(jlEncoded, "");
		pane.add(jtfEncoded, "growx, wrap");
		pane.add(jbPem, "spanx, split");
		pane.add(jbFields, "");
		pane.add(jbAsn1, "wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jbOK, "spanx, tag ok");

		// actions
		
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbPem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewPrivateKey.this);
					pemEncodingPressed();
				} finally {
					CursorUtil.setCursorFree(DViewPrivateKey.this);
				}
			}
		});

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
	
	private void pemEncodingPressed() {
		try {
			DViewPem dViewCsrPem = new DViewPem(this, res.getString("DViewPrivateKey.Pem.Title"),
					privateKey);
			dViewCsrPem.setLocationRelativeTo(this);
			dViewCsrPem.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
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
	
	// for quick testing
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		javax.swing.UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		java.awt.EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
					KeyPair keyPair = keyGen.genKeyPair();

					PrivateKey privKey = keyPair.getPrivate();
					DViewPrivateKey dialog = new DViewPrivateKey(new javax.swing.JFrame(), "Title", privKey, null);
					dialog.addWindowListener(new java.awt.event.WindowAdapter() {
						@Override
						public void windowClosing(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}
