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
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
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
 * Displays the details of a public key with the option to display its fields if
 * it is of a supported type (RSA or DSA).
 *
 */
public class DViewPublicKey extends JEscDialog {
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

		jlAlgorithm = new JLabel(res.getString("DViewPublicKey.jlAlgorithm.text"));

		jtfAlgorithm = new JTextField(10);
		jtfAlgorithm.setEditable(false);
		jtfAlgorithm.setToolTipText(res.getString("DViewPublicKey.jtfAlgorithm.tooltip"));

		jlKeySize = new JLabel(res.getString("DViewPublicKey.jlKeySize.text"));

		jtfKeySize = new JTextField(10);
		jtfKeySize.setEditable(false);
		jtfKeySize.setToolTipText(res.getString("DViewPublicKey.jtfKeySize.tooltip"));

		jlFormat = new JLabel(res.getString("DViewPublicKey.jlFormat.text"));

		jtfFormat = new JTextField(10);
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewPublicKey.jtfFormat.tooltip"));

		jlEncoded = new JLabel(res.getString("DViewPublicKey.jlEncoded.text"));

		jtfEncoded = new JTextField(30);
		jtfEncoded.setEditable(false);
		jtfEncoded.setToolTipText(res.getString("DViewPublicKey.jtfEncoded.tooltip"));

		jbPem = new JButton(res.getString("DViewPublicKey.jbPem.text"));
		PlatformUtil.setMnemonic(jbPem, res.getString("DViewPublicKey.jbPem.mnemonic").charAt(0));
		jbPem.setToolTipText(res.getString("DViewPublicKey.jbPem.tooltip"));

		jbFields = new JButton(res.getString("DViewPublicKey.jbFields.text"));
		PlatformUtil.setMnemonic(jbFields, res.getString("DViewPublicKey.jbFields.mnemonic").charAt(0));
		jbFields.setToolTipText(res.getString("DViewPublicKey.jbFields.tooltip"));

		jbAsn1 = new JButton(res.getString("DViewPublicKey.jbAsn1.text"));
		PlatformUtil.setMnemonic(jbAsn1, res.getString("DViewPublicKey.jbAsn1.mnemonic").charAt(0));
		jbAsn1.setToolTipText(res.getString("DViewPublicKey.jbAsn1.tooltip"));

		jbOK = new JButton(res.getString("DViewPublicKey.jbOK.text"));
		
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
					CursorUtil.setCursorBusy(DViewPublicKey.this);
					pemEncodingPressed();
				} finally {
					CursorUtil.setCursorFree(DViewPublicKey.this);
				}
			}
		});

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
	
	private void pemEncodingPressed() {
		try {
			DViewPem dViewCsrPem = new DViewPem(this, res.getString("DViewPublicKey.Pem.Title"), publicKey);
			dViewCsrPem.setLocationRelativeTo(this);
			dViewCsrPem.setVisible(true);
		} catch (CryptoException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
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
	
	// for quick testing
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		javax.swing.UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		java.awt.EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
					KeyPair keyPair = keyGen.genKeyPair();

					DViewPublicKey dialog = new DViewPublicKey(new javax.swing.JFrame(), "Title", keyPair.getPublic());
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
