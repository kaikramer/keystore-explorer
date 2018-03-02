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
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.privatekey.Pkcs8Util;
import org.kse.crypto.privatekey.PrivateKeyEncryptedException;
import org.kse.crypto.privatekey.PrivateKeyPbeNotSupportedException;
import org.kse.crypto.privatekey.PrivateKeyUnencryptedException;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dialogs.DViewCertificate;
import org.kse.gui.dialogs.DViewPrivateKey;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;

/**
 * Dialog that allows the user to pick a PKCS #8 Private Key file and a
 * certificate file to import as a key pair.
 *
 */
public class DImportKeyPairPkcs8 extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpKeyPair;
	private JLabel jlEncrypted;
	private JCheckBox jcbEncrypted;
	private JLabel jlPassword;
	private JPasswordField jpfPassword;
	private JLabel jlPrivateKey;
	private JTextField jtfPrivateKeyPath;
	private JButton jbPrivateKeyBrowse;
	private JButton jbPrivateKeyDetails;
	private JLabel jlCertificate;
	private JTextField jtfCertificatePath;
	private JButton jbCertificateBrowse;
	private JButton jbCertificateDetails;
	private JPanel jpButtons;
	private JButton jbImport;
	private JButton jbCancel;

	private PrivateKey privateKey;
	private Certificate[] certificateChain;

	/**
	 * Creates a new DImportKeyPairPkcs8 dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DImportKeyPairPkcs8(JFrame parent) {
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

		jlEncrypted = new JLabel(res.getString("DImportKeyPairPkcs8.jlEncrypted.text"));
		GridBagConstraints gbc_jlEncrypted = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEncrypted.gridy = 0;

		jcbEncrypted = new JCheckBox();
		jcbEncrypted.setSelected(true);
		jcbEncrypted.setToolTipText(res.getString("DImportKeyPairPkcs8.jcbEncrypted.tooltip"));
		GridBagConstraints gbc_jcbEncrypted = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbEncrypted.gridy = 0;

		jlPassword = new JLabel(res.getString("DImportKeyPairPkcs8.jlPassword.text"));
		GridBagConstraints gbc_jlPassword = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPassword.gridy = 1;

		jpfPassword = new JPasswordField(15);
		jpfPassword.setToolTipText(res.getString("DImportKeyPairPkcs8.jpfPassword.tooltip"));
		GridBagConstraints gbc_jpfPassword = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jpfPassword.gridy = 1;

		jlPrivateKey = new JLabel(res.getString("DImportKeyPairPkcs8.jlPrivateKey.text"));
		GridBagConstraints gbc_jlPrivateKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPrivateKey.gridy = 2;

		jtfPrivateKeyPath = new JTextField(30);
		jtfPrivateKeyPath.setToolTipText(res.getString("DImportKeyPairPkcs8.jtfPrivateKeyPath.tooltip"));
		GridBagConstraints gbc_jtfPrivateKeyPath = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfPrivateKeyPath.gridy = 2;
		gbc_jtfPrivateKeyPath.gridwidth = 6;

		jbPrivateKeyBrowse = new JButton(res.getString("DImportKeyPairPkcs8.jbPrivateKeyBrowse.text"));
		PlatformUtil.setMnemonic(jbPrivateKeyBrowse, res.getString("DImportKeyPairPkcs8.jbPrivateKeyBrowse.mnemonic")
				.charAt(0));
		jbPrivateKeyBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs8.this);
					privateKeyBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs8.this);
				}
			}
		});
		jbPrivateKeyBrowse.setToolTipText(res.getString("DImportKeyPairPkcs8.jbPrivateKeyBrowse.tooltip"));
		GridBagConstraints gbc_jbPrivateKeyBrowse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbPrivateKeyBrowse.gridy = 2;
		gbc_jbPrivateKeyBrowse.gridx = 9;

		jbPrivateKeyDetails = new JButton(res.getString("DImportKeyPairPkcs8.jbPrivateKeyDetails.text"));
		jbPrivateKeyDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs8.this);
					privateKeyDetailsPressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs8.this);
				}
			}
		});
		PlatformUtil.setMnemonic(jbPrivateKeyDetails, res.getString("DImportKeyPairPkcs8.jbPrivateKeyDetails.mnemonic")
				.charAt(0));
		jbPrivateKeyDetails.setToolTipText(res.getString("DImportKeyPairPkcs8.jbPrivateKeyDetails.tooltip"));
		GridBagConstraints gbc_jbPrivateKeyDetails = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbPrivateKeyDetails.gridy = 2;
		gbc_jbPrivateKeyDetails.gridx = 12;

		jlCertificate = new JLabel(res.getString("DImportKeyPairPkcs8.jlCertificate.text"));
		GridBagConstraints gbc_jlCertificate = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCertificate.gridy = 3;

		jtfCertificatePath = new JTextField(30);
		jtfCertificatePath.setToolTipText(res.getString("DImportKeyPairPkcs8.jtfCertificatePath.tooltip"));
		GridBagConstraints gbc_jtfCertificatePath = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfCertificatePath.gridy = 3;
		gbc_jtfCertificatePath.gridwidth = 6;

		jbCertificateBrowse = new JButton(res.getString("DImportKeyPairPkcs8.jbCertificateBrowse.text"));
		jbCertificateBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs8.this);
					certificateBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs8.this);
				}
			}
		});
		PlatformUtil.setMnemonic(jbCertificateBrowse, res.getString("DImportKeyPairPkcs8.jbCertificateBrowse.mnemonic")
				.charAt(0));
		jbCertificateBrowse.setToolTipText(res.getString("DImportKeyPairPkcs8.jbCertificateBrowse.tooltip"));
		GridBagConstraints gbc_jbCertificateBrowse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbCertificateBrowse.gridy = 3;
		gbc_jbCertificateBrowse.gridx = 9;

		jbCertificateDetails = new JButton(res.getString("DImportKeyPairPkcs8.jbCertificateDetails.text"));
		jbCertificateDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs8.this);
					certificateDetailsPressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs8.this);
				}
			}
		});
		PlatformUtil.setMnemonic(jbCertificateDetails,
				res.getString("DImportKeyPairPkcs8.jbCertificateDetails.mnemonic").charAt(0));
		jbCertificateDetails.setToolTipText(res.getString("DImportKeyPairPkcs8.jbCertificateDetails.tooltip"));
		GridBagConstraints gbc_jbCertificateDetails = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbCertificateDetails.gridy = 3;
		gbc_jbCertificateDetails.gridx = 12;

		jpKeyPair = new JPanel(new GridBagLayout());
		jpKeyPair.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()),
				new EmptyBorder(5, 5, 5, 5)));

		jpKeyPair.add(jlEncrypted, gbc_jlEncrypted);
		jpKeyPair.add(jcbEncrypted, gbc_jcbEncrypted);
		jpKeyPair.add(jlPassword, gbc_jlPassword);
		jpKeyPair.add(jpfPassword, gbc_jpfPassword);
		jpKeyPair.add(jlPrivateKey, gbc_jlPrivateKey);
		jpKeyPair.add(jtfPrivateKeyPath, gbc_jtfPrivateKeyPath);
		jpKeyPair.add(jbPrivateKeyBrowse, gbc_jbPrivateKeyBrowse);
		jpKeyPair.add(jbPrivateKeyDetails, gbc_jbPrivateKeyDetails);
		jpKeyPair.add(jlCertificate, gbc_jlCertificate);
		jpKeyPair.add(jtfCertificatePath, gbc_jtfCertificatePath);
		jpKeyPair.add(jbCertificateBrowse, gbc_jbCertificateBrowse);
		jpKeyPair.add(jbCertificateDetails, gbc_jbCertificateDetails);

		jcbEncrypted.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jcbEncrypted.isSelected()) {
					jpfPassword.setEnabled(true);
				} else {
					jpfPassword.setEnabled(false);
					jpfPassword.setText("");
				}
			}
		});

		jbImport = new JButton(res.getString("DImportKeyPairPkcs8.jbImport.text"));
		PlatformUtil.setMnemonic(jbImport, res.getString("DImportKeyPairPkcs8.jbImport.mnemonic").charAt(0));
		jbImport.setToolTipText(res.getString("DImportKeyPairPkcs8.jbImport.tooltip"));
		jbImport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DImportKeyPairPkcs8.this);
					importPressed();
				} finally {
					CursorUtil.setCursorFree(DImportKeyPairPkcs8.this);
				}
			}
		});

		jbCancel = new JButton(res.getString("DImportKeyPairPkcs8.jbCancel.text"));
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

		setTitle(res.getString("DImportKeyPairPkcs8.Title"));
		setResizable(false);

		getRootPane().setDefaultButton(jbImport);

		pack();
	}

	private void privateKeyBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getPkcs8FileChooser();

		File currentFile = new File(jtfPrivateKeyPath.getText());

		if ((currentFile.getParentFile() != null) && (currentFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DImportKeyPairPkcs8.ChoosePrivateKey.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DImportKeyPairPkcs8.PrivateKeyFileChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfPrivateKeyPath.setText(chosenFile.toString());
			jtfPrivateKeyPath.setCaretPosition(0);
		}
	}

	private void certificateBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getCertFileChooser();

		File currentFile = new File(jtfCertificatePath.getText());

		if ((currentFile.getParentFile() != null) && (currentFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DImportKeyPairPkcs8.ChooseCertificate.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DImportKeyPairPkcs8.CertificateFileChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfCertificatePath.setText(chosenFile.toString());
			jtfCertificatePath.setCaretPosition(0);
		}
	}

	private void privateKeyDetailsPressed() {
		try {
			String path = new File(jtfPrivateKeyPath.getText()).getName();

			PrivateKey privateKey = loadPrivateKey();

			if (privateKey != null) {
				DViewPrivateKey dViewPrivateKey = new DViewPrivateKey(this, MessageFormat.format(
						res.getString("DImportKeyPairPkcs8.ViewPrivateKeyDetails.Title"), path),
						privateKey, new BouncyCastleProvider());
				dViewPrivateKey.setLocationRelativeTo(this);
				dViewPrivateKey.setVisible(true);
			}
		} catch (CryptoException ex) {
			DError.displayError(this, ex);
		}
	}

	private PrivateKey loadPrivateKey() {
		String privateKeyPath = jtfPrivateKeyPath.getText().trim();

		if (privateKeyPath.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DImportKeyPairPkcs8.PrivateKeyRequired.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		}

		File privateKeyFile = new File(privateKeyPath);

		try {
			PrivateKey privateKey = null;

			if (!jcbEncrypted.isSelected()) {
				privateKey = Pkcs8Util.load(new FileInputStream(privateKeyFile));
			} else {
				Password password = new Password(jpfPassword.getPassword());

				privateKey = Pkcs8Util.loadEncrypted(new FileInputStream(privateKeyFile), password);
			}

			return privateKey;
		} catch (PrivateKeyEncryptedException ex) {
			JOptionPane.showMessageDialog(this, MessageFormat.format(
					res.getString("DImportKeyPairPkcs8.PrivateKeyEncrypted.message"), privateKeyFile), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			jcbEncrypted.setSelected(true);
			return null;
		} catch (PrivateKeyUnencryptedException ex) {
			JOptionPane.showMessageDialog(this, MessageFormat.format(
					res.getString("DImportKeyPairPkcs8.PrivateKeyNotEncrypted.message"), privateKeyFile), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			jcbEncrypted.setSelected(false);
			return null;
		} catch (PrivateKeyPbeNotSupportedException ex) {
			JOptionPane.showMessageDialog(
					this,
					MessageFormat.format(res.getString("DImportKeyPairPkcs8.PrivateKeyPbeNotSupported.message"),
							ex.getUnsupportedPbe()), getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DImportKeyPairPkcs8.NoReadFile.message"), privateKeyFile),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		} catch (Exception ex) {
			Problem problem = createLoadPkcs8Problem(ex, privateKeyFile);

			DProblem dProblem = new DProblem(this, res.getString("DImportKeyPairPkcs8.ProblemLoadingPkcs8.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return null;
		}
	}

	private Problem createLoadPkcs8Problem(Exception exception, File pkcs8File) {
		String problemStr = null;
		ArrayList<String> causeList = new ArrayList<String>();

		if (jcbEncrypted.isSelected()) {
			problemStr = MessageFormat.format(res.getString("DImportKeyPairPkcs8.NoLoadEncryptedPkcs8.Problem"),
					pkcs8File.getName());
			causeList.add(res.getString("DImportKeyPairPkcs8.PasswordIncorrectPkcs8.Cause"));
		} else {
			problemStr = MessageFormat.format(res.getString("DImportKeyPairPkcs8.NoLoadUnencryptedPkcs8.Problem"),
					pkcs8File.getName());
		}

		causeList.add(res.getString("DImportKeyPairPkcs8.NotPkcs8.Cause"));
		causeList.add(res.getString("DImportKeyPairPkcs8.CorruptedPkcs8.Cause"));

		String[] causes = causeList.toArray(new String[causeList.size()]);

		Problem problem = new Problem(problemStr, causes, exception);

		return problem;
	}

	private void certificateDetailsPressed() {
		try {
			X509Certificate[] certs = loadCertificates();

			if ((certs != null) && (certs.length != 0)) {
				String path = new File(jtfCertificatePath.getText()).getName();

				DViewCertificate dViewCertificate = new DViewCertificate(this, MessageFormat.format(
						res.getString("DImportKeyPairPkcs8.ViewCertificateDetails.Title"), path),
						certs, null, DViewCertificate.NONE);
				dViewCertificate.setLocationRelativeTo(this);
				dViewCertificate.setVisible(true);
			}
		} catch (CryptoException ex) {
			DError.displayError(this, ex);
		}
	}

	private X509Certificate[] loadCertificates() {
		String certificatePath = jtfCertificatePath.getText().trim();

		if (certificatePath.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DImportKeyPairPkcs8.CertificateRequired.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		}

		File certificateFile = new File(certificatePath);

		try {
			X509Certificate[] certs = X509CertUtil.loadCertificates(new FileInputStream(certificateFile));

			if (certs.length == 0) {
				JOptionPane.showMessageDialog(this, MessageFormat.format(
						res.getString("DImportKeyPairPkcs8.NoCertsFound.message"), certificateFile), getTitle(),
						JOptionPane.WARNING_MESSAGE);
			}

			return certs;
		} catch (FileNotFoundException ex) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DImportKeyPairPkcs8.NoReadFile.message"), certificateFile),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return null;
		} catch (Exception ex) {
			Problem problem = createLoadCertsProblem(ex, certificateFile);

			DProblem dProblem = new DProblem(this, res.getString("DImportKeyPairPkcs8.ProblemLoadingCerts.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return null;
		}
	}

	private Problem createLoadCertsProblem(Exception exception, File certsFile) {
		String problemStr = MessageFormat.format(res.getString("DImportKeyPairPkcs8.NoLoadCerts.Problem"),
				certsFile.getName());

		String[] causes = new String[] { res.getString("DImportKeyPairPkcs8.NotCerts.Cause"),
				res.getString("DImportKeyPairPkcs8.CorruptedCerts.Cause") };

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
	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	private void importPressed() {
		try {
			PrivateKey privateKey = loadPrivateKey();

			if (privateKey == null) {
				return;
			}

			X509Certificate[] certs = loadCertificates();

			if ((certs == null) || (certs.length == 0)) {
				return;
			}

			certs = X509CertUtil.orderX509CertChain(certs);

			if (!KeyPairUtil.validKeyPair(privateKey, certs[0].getPublicKey())) {
				JOptionPane.showMessageDialog(this, res.getString("DImportKeyPairPkcs8.KeyPairInvalid.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			}

			this.privateKey = privateKey;
			certificateChain = certs;

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
}
