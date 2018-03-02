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
package org.kse.gui.dialogs.importexport;

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
import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dialogs.DViewKeyPair;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;

/**
 * Dialog that allows the user to pick a PKCS #12 file to for import as a key
 * pair.
 *
 */
public class DImportKeyPairPkcs12 extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpKeyPair;
	private JLabel jlPassword;
	private JPasswordField jpfPassword;
	private JLabel jlPkcs12Path;
	private JTextField jtfPkcs12Path;
	private JButton jbBrowse;
	private JButton jbDetails;
	private JPanel jpButtons;
	private JButton jbImport;
	private JButton jbCancel;

	private PrivateKey privateKey;
	private X509Certificate[] certificateChain;

	/**
	 * Creates a new DImportKeyPairPkcs12 dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DImportKeyPairPkcs12(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents();
	}

	private void initComponents() {
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 3;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcEdCtrl = new GridBagConstraints();
		gbcEdCtrl.gridx = 3;
		gbcEdCtrl.gridwidth = 3;
		gbcEdCtrl.gridheight = 1;
		gbcEdCtrl.insets = new Insets(5, 5, 5, 5);
		gbcEdCtrl.anchor = GridBagConstraints.WEST;

		jlPassword = new JLabel(res.getString("DImportKeyPairPkcs12.jlPassword.text"));
		GridBagConstraints gbc_jlPassword = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPassword.gridy = 0;

		jpfPassword = new JPasswordField(15);
		jpfPassword.setToolTipText(res.getString("DImportKeyPairPkcs12.jpfPassword.tooltip"));
		GridBagConstraints gbc_jpfPassword = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jpfPassword.gridy = 0;

		jlPkcs12Path = new JLabel(res.getString("DImportKeyPairPkcs12.jlPkcs12Path.text"));
		GridBagConstraints gbc_jlPkcs12 = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPkcs12.gridy = 1;

		jtfPkcs12Path = new JTextField(30);
		jtfPkcs12Path.setToolTipText(res.getString("DImportKeyPairPkcs12.jtfPkcs12Path.tooltip"));
		GridBagConstraints gbc_jtfPkcs12Path = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfPkcs12Path.gridy = 1;
		gbc_jtfPkcs12Path.gridwidth = 6;

		jbBrowse = new JButton(res.getString("DImportKeyPairPkcs12.jbBrowse.text"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DImportKeyPairPkcs12.jbBrowse.mnemonic").charAt(0));
		jbBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs12.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs12.this);
				}
			}
		});
		jbBrowse.setToolTipText(res.getString("DImportKeyPairPkcs12.jbBrowse.tooltip"));
		GridBagConstraints gbc_jbPkcs12Browse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbPkcs12Browse.gridy = 1;
		gbc_jbPkcs12Browse.gridx = 9;

		jbDetails = new JButton(res.getString("DImportKeyPairPkcs12.jbDetails.text"));
		PlatformUtil.setMnemonic(jbDetails, res.getString("DImportKeyPairPkcs12.jbDetails.mnemonic").charAt(0));
		jbDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs12.this);
					detailsPressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs12.this);
				}
			}
		});
		jbDetails.setToolTipText(res.getString("DImportKeyPairPkcs12.jbDetails.tooltip"));
		GridBagConstraints gbc_jbKeyPairDetails = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbKeyPairDetails.gridy = 1;
		gbc_jbKeyPairDetails.gridx = 12;

		jpKeyPair = new JPanel(new GridBagLayout());
		jpKeyPair.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()),
				new EmptyBorder(5, 5, 5, 5)));

		jpKeyPair.add(jlPassword, gbc_jlPassword);
		jpKeyPair.add(jpfPassword, gbc_jpfPassword);
		jpKeyPair.add(jlPkcs12Path, gbc_jlPkcs12);
		jpKeyPair.add(jtfPkcs12Path, gbc_jtfPkcs12Path);
		jpKeyPair.add(jbBrowse, gbc_jbPkcs12Browse);
		jpKeyPair.add(jbDetails, gbc_jbKeyPairDetails);

		jbImport = new JButton(res.getString("DImportKeyPairPkcs12.jbImport.text"));
		PlatformUtil.setMnemonic(jbImport, res.getString("DImportKeyPairPkcs12.jbImport.mnemonic").charAt(0));
		jbImport.setToolTipText(res.getString("DImportKeyPairPkcs12.jbImport.tooltip"));
		jbImport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs12.this);
					importPressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs12.this);
				}
			}
		});

		jbCancel = new JButton(res.getString("DImportKeyPairPkcs12.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbImport, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpKeyPair, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setTitle(res.getString("DImportKeyPairPkcs12.Title"));
		setResizable(false);

		getRootPane().setDefaultButton(jbImport);

		pack();
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser();

		File currentFile = new File(jtfPkcs12Path.getText());

		if ((currentFile.getParentFile() != null) && (currentFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DImportKeyPairPkcs12.ChooseKeyPair.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DImportKeyPairPkcs12.KeyPairFileChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfPkcs12Path.setText(chosenFile.toString());
			jtfPkcs12Path.setCaretPosition(0);
		}
	}

	private void detailsPressed() {
		String path = new File(jtfPkcs12Path.getText()).getName();

		Keypair keypair = loadKeyPair();

		if (keypair != null) {
			DViewKeyPair dViewKeyPair = new DViewKeyPair(this, MessageFormat.format(
					res.getString("DImportKeyPairPkcs12.ViewKeyPairDetails.Title"), path),
					keypair.getPrivateKey(), keypair.getCertificateChain(), new BouncyCastleProvider());
			dViewKeyPair.setLocationRelativeTo(this);
			dViewKeyPair.setVisible(true);
		}
	}

	private Keypair loadKeyPair() {
		String pkcs12Path = jtfPkcs12Path.getText().trim();

		if (pkcs12Path.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DImportKeyPairPkcs12.KeyPairRequired.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		}

		File pkcs12File = new File(pkcs12Path);

		try {
			Password pkcs12Password = new Password(jpfPassword.getPassword());

			KeyStore pkcs12 = KeyStoreUtil.load(pkcs12File, pkcs12Password, KeyStoreType.PKCS12);

			// Find a key pair in the PKCS #12 KeyStore
			PrivateKey privKey = null;
			ArrayList<Certificate> certsList = new ArrayList<Certificate>();

			// Look for key pair entries first
			for (Enumeration<?> aliases = pkcs12.aliases(); aliases.hasMoreElements();) {
				String alias = (String) aliases.nextElement();

				if (pkcs12.isKeyEntry(alias)) {
					privKey = (PrivateKey) pkcs12.getKey(alias, pkcs12Password.toCharArray());
					Certificate[] certs = pkcs12.getCertificateChain(alias);
					if ((certs != null) && (certs.length > 0)) {
						Collections.addAll(certsList, certs);
						break;
					}
				}
			}

			// No key pair entries found - look for a key entry and certificate
			// entries
			if ((privKey == null) || (certsList.size() == 0)) {
				for (Enumeration<?> aliases = pkcs12.aliases(); aliases.hasMoreElements();) {
					String alias = (String) aliases.nextElement();

					certsList.add(pkcs12.getCertificate(alias));
				}
			}

			if ((privKey == null) || (certsList.size() == 0)) {
				JOptionPane.showMessageDialog(this, MessageFormat.format(
						res.getString("DImportKeyPairPkcs12.NoKeyPairPkcs12File.message"), pkcs12File.getName()),
						getTitle(), JOptionPane.INFORMATION_MESSAGE);
				return null;
			}

			X509Certificate[] certs = X509CertUtil.convertCertificates(certsList.toArray(new Certificate[certsList
			                                                                                             .size()]));

			return new Keypair(privKey, certs);
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DImportKeyPairPkcs12.NoReadFile.message"), pkcs12File),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		} catch (Exception ex) {
			Problem problem = createLoadPkcs12Problem(ex, pkcs12File);

			DProblem dProblem = new DProblem(this, res.getString("DImportKeyPairPkcs12.ProblemLoadingPkcs12.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return null;
		}
	}

	private Problem createLoadPkcs12Problem(Exception exception, File pkcs12File) {
		String problemStr = MessageFormat.format(res.getString("DImportKeyPairPkcs12.NoLoadPkcs12.Problem"),
				pkcs12File.getName());

		String[] causes = new String[] { res.getString("DImportKeyPairPkcs12.PasswordIncorrectPkcs12.Cause"),
				res.getString("DImportKeyPairPkcs12.NotPkcs12.Cause"),
				res.getString("DImportKeyPairPkcs12.CorruptedPkcs12.Cause") };

		Problem problem = new Problem(problemStr, causes, exception);

		return problem;
	}

	/**
	 * Get the private part of the key pair chosen by the user for import.
	 *
	 * @return The private key or null if the user has not chosen a key pair
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Get the certificate chain part of the key pair chosen by the user for
	 * import.
	 *
	 * @return The certificate chain or null if the user has not chosen a key
	 *         pair
	 */
	public X509Certificate[] getCertificateChain() {
		return certificateChain;
	}

	private void importPressed() {
		try {
			Keypair keypair = loadKeyPair();

			if (keypair == null) {
				return;
			}

			if (!KeyPairUtil.validKeyPair(keypair.getPrivateKey(),
					X509CertUtil.orderX509CertChain(keypair.getCertificateChain())[0].getPublicKey())) {
				JOptionPane.showMessageDialog(this, res.getString("DImportKeyPairPkcs12.KeyPairInvalid.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			}

			privateKey = keypair.getPrivateKey();
			certificateChain = keypair.getCertificateChain();

			closeDialog();
		} catch (Exception ex) {
			DError.displayError(this, ex);
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private class Keypair {
		private PrivateKey privateKey;
		private X509Certificate[] certificateChain;

		public Keypair(PrivateKey privateKey, X509Certificate[] certificateChain) {
			this.privateKey = privateKey;
			this.certificateChain = certificateChain;
		}

		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		public X509Certificate[] getCertificateChain() {
			return certificateChain;
		}
	}
}
