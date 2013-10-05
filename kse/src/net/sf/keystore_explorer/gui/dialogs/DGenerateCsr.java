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

import static net.sf.keystore_explorer.crypto.csr.CsrType.PKCS10;
import static net.sf.keystore_explorer.crypto.csr.CsrType.SPKAC;

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
import java.security.PrivateKey;
import java.text.MessageFormat;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.KeyInfo;
import net.sf.keystore_explorer.crypto.csr.CsrType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairUtil;
import net.sf.keystore_explorer.crypto.signing.SignatureType;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;

/**
 * Dialog used to choose parameters for CSR generation.
 * 
 */
public class DGenerateCsr extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpCsr;
	private JLabel jlFormat;
	private JRadioButton jrbPkcs10;
	private JRadioButton jrbSpkac;
	private JLabel jlSignatureAlgorithm;
	private JComboBox jcbSignatureAlgorithm;
	private JLabel jlChallenge;
	private JTextField jtfChallenge;
	private JLabel jlCsrFile;
	private JTextField jtfCsrFile;
	private JButton jbBrowse;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private boolean generateSelected = false;
	private PrivateKey privateKey;
	private KeyPairType keyPairType;
	private CsrType format;
	private SignatureType signatureAlgorithm;
	private String challenge;
	private File csrFile;

	/**
	 * Creates a new DGenerateCsr dialog.
	 * 
	 * @param parent
	 *            The parent frame
	 * @param privateKey
	 *            Private key
	 * @param keyPairType
	 *            Key pair algorithm
	 * @throws CryptoException
	 *             A problem was encountered with the supplied private key
	 */
	public DGenerateCsr(JFrame parent, PrivateKey privateKey, KeyPairType keyPairType) throws CryptoException {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		this.privateKey = privateKey;
		this.keyPairType = keyPairType;
		setTitle(res.getString("DGenerateCsr.Title"));
		initComponents();
	}

	private void initComponents() throws CryptoException {
		jlFormat = new JLabel(res.getString("DGenerateCsr.jlFormat.text"));

		GridBagConstraints gbc_jlFormat = new GridBagConstraints();
		gbc_jlFormat.gridx = 0;
		gbc_jlFormat.gridy = 0;
		gbc_jlFormat.gridwidth = 1;
		gbc_jlFormat.gridheight = 1;
		gbc_jlFormat.insets = new Insets(5, 5, 5, 5);
		gbc_jlFormat.anchor = GridBagConstraints.EAST;

		jrbPkcs10 = new JRadioButton(res.getString("DGenerateCsr.jrbPkcs10.text"), false);
		PlatformUtil.setMnemonic(jrbPkcs10, res.getString("DGenerateCsr.jrbPkcs10.mnemonic").charAt(0));
		jrbPkcs10.setToolTipText(res.getString("DGenerateCsr.jrbPkcs10.tooltip"));

		GridBagConstraints gbc_jrbPkcs10 = new GridBagConstraints();
		gbc_jrbPkcs10.gridx = 1;
		gbc_jrbPkcs10.gridy = 0;
		gbc_jrbPkcs10.gridwidth = 1;
		gbc_jrbPkcs10.gridheight = 1;
		gbc_jrbPkcs10.insets = new Insets(5, 5, 5, 5);
		gbc_jrbPkcs10.anchor = GridBagConstraints.WEST;

		jrbSpkac = new JRadioButton(res.getString("DGenerateCsr.jrbSpkac.text"), true);
		PlatformUtil.setMnemonic(jrbSpkac, res.getString("DGenerateCsr.jrbSpkac.mnemonic").charAt(0));
		jrbSpkac.setToolTipText(res.getString("DGenerateCsr.jrbSpkac.tooltip"));

		GridBagConstraints gbc_jrbSpkac = new GridBagConstraints();
		gbc_jrbSpkac.gridx = 2;
		gbc_jrbSpkac.gridy = 0;
		gbc_jrbSpkac.gridwidth = 1;
		gbc_jrbSpkac.gridheight = 1;
		gbc_jrbSpkac.insets = new Insets(5, 5, 5, 5);
		gbc_jrbSpkac.anchor = GridBagConstraints.WEST;

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbPkcs10);
		buttonGroup.add(jrbSpkac);

		jrbPkcs10.setSelected(true);

		jlSignatureAlgorithm = new JLabel(res.getString("DGenerateCsr.jlSignatureAlgorithm.text"));

		GridBagConstraints gbc_jlSignatureAlgorithm = new GridBagConstraints();
		gbc_jlSignatureAlgorithm.gridx = 0;
		gbc_jlSignatureAlgorithm.gridy = 1;
		gbc_jlSignatureAlgorithm.gridwidth = 1;
		gbc_jlSignatureAlgorithm.gridheight = 1;
		gbc_jlSignatureAlgorithm.insets = new Insets(5, 5, 5, 5);
		gbc_jlSignatureAlgorithm.anchor = GridBagConstraints.EAST;

		jcbSignatureAlgorithm = new JComboBox();
		jcbSignatureAlgorithm.setMaximumRowCount(10);
		jcbSignatureAlgorithm.setToolTipText(res.getString("DGenerateCsr.jcbSignatureAlgorithm.tooltip"));
		populateSigAlgs();

		GridBagConstraints gbc_jcbSignatureAlgorithm = new GridBagConstraints();
		gbc_jcbSignatureAlgorithm.gridx = 1;
		gbc_jcbSignatureAlgorithm.gridy = 1;
		gbc_jcbSignatureAlgorithm.gridwidth = 2;
		gbc_jcbSignatureAlgorithm.gridheight = 1;
		gbc_jcbSignatureAlgorithm.insets = new Insets(5, 5, 5, 5);
		gbc_jcbSignatureAlgorithm.anchor = GridBagConstraints.WEST;

		jlChallenge = new JLabel(res.getString("DGenerateCsr.jlChallenge.text"));

		GridBagConstraints gbc_jlChallenge = new GridBagConstraints();
		gbc_jlChallenge.gridx = 0;
		gbc_jlChallenge.gridy = 2;
		gbc_jlChallenge.gridwidth = 1;
		gbc_jlChallenge.gridheight = 1;
		gbc_jlChallenge.insets = new Insets(5, 5, 5, 5);
		gbc_jlChallenge.anchor = GridBagConstraints.EAST;

		jtfChallenge = new JTextField(15);
		jtfChallenge.setToolTipText(res.getString("DGenerateCsr.jtfChallenge.tooltip"));
		populateSigAlgs();

		GridBagConstraints gbc_jtfChallenge = new GridBagConstraints();
		gbc_jtfChallenge.gridx = 1;
		gbc_jtfChallenge.gridy = 2;
		gbc_jtfChallenge.gridwidth = 2;
		gbc_jtfChallenge.gridheight = 1;
		gbc_jtfChallenge.insets = new Insets(5, 5, 5, 5);
		gbc_jtfChallenge.anchor = GridBagConstraints.WEST;

		jlCsrFile = new JLabel(res.getString("DGenerateCsr.jlCsrFile.text"));

		GridBagConstraints gbc_jlCsrFile = new GridBagConstraints();
		gbc_jlCsrFile.gridx = 0;
		gbc_jlCsrFile.gridy = 3;
		gbc_jlCsrFile.gridwidth = 1;
		gbc_jlCsrFile.gridheight = 1;
		gbc_jlCsrFile.insets = new Insets(5, 5, 5, 5);
		gbc_jlCsrFile.anchor = GridBagConstraints.EAST;

		jtfCsrFile = new JTextField(30);
		jtfCsrFile.setToolTipText(res.getString("DGenerateCsr.jtfCsrFile.tooltip"));

		GridBagConstraints gbc_jtfCsrFile = new GridBagConstraints();
		gbc_jtfCsrFile.gridx = 1;
		gbc_jtfCsrFile.gridy = 3;
		gbc_jtfCsrFile.gridwidth = 3;
		gbc_jtfCsrFile.gridheight = 1;
		gbc_jtfCsrFile.insets = new Insets(5, 5, 5, 5);
		gbc_jtfCsrFile.anchor = GridBagConstraints.WEST;

		jbBrowse = new JButton(res.getString("DGenerateCsr.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DGenerateCsr.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DGenerateCsr.jbBrowse.mnemonic").charAt(0));

		jbBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DGenerateCsr.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DGenerateCsr.this);
				}
			}
		});

		GridBagConstraints gbc_jbBrowse = new GridBagConstraints();
		gbc_jbBrowse.gridx = 4;
		gbc_jbBrowse.gridy = 3;
		gbc_jbBrowse.gridwidth = 1;
		gbc_jbBrowse.gridheight = 1;
		gbc_jbBrowse.insets = new Insets(5, 5, 5, 5);
		gbc_jbBrowse.anchor = GridBagConstraints.WEST;

		jpCsr = new JPanel(new GridBagLayout());
		jpCsr.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpCsr.add(jlFormat, gbc_jlFormat);
		jpCsr.add(jrbPkcs10, gbc_jrbPkcs10);
		jpCsr.add(jrbSpkac, gbc_jrbSpkac);
		jpCsr.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpCsr.add(jcbSignatureAlgorithm, gbc_jcbSignatureAlgorithm);
		jpCsr.add(jlChallenge, gbc_jlChallenge);
		jpCsr.add(jtfChallenge, gbc_jtfChallenge);
		jpCsr.add(jlCsrFile, gbc_jlCsrFile);
		jpCsr.add(jtfCsrFile, gbc_jtfCsrFile);
		jpCsr.add(jbBrowse, gbc_jbBrowse);

		jbOK = new JButton(res.getString("DGenerateCsr.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGenerateCsr.jbCancel.text"));
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

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpCsr, BorderLayout.CENTER);
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

	private void populateSigAlgs() throws CryptoException {
		List<SignatureType> sigAlgs;

		if (keyPairType == KeyPairType.RSA) {
			KeyInfo keyInfo = KeyPairUtil.getKeyInfo(this.privateKey);
			sigAlgs = SignatureType.rsaSignatureTypes(keyInfo.getSize());
		} else {
			sigAlgs = SignatureType.dsaSignatureTypes();
		}

		jcbSignatureAlgorithm.removeAllItems();

		for (SignatureType sigAlg : sigAlgs) {
			jcbSignatureAlgorithm.addItem(sigAlg);
		}

		if (sigAlgs.contains(SignatureType.SHA256_RSA)) {
			jcbSignatureAlgorithm.setSelectedItem(SignatureType.SHA256_RSA);
		} else {
			jcbSignatureAlgorithm.setSelectedIndex(0);
		}
	}

	private void browsePressed() {
		JFileChooser chooser = null;

		if (jrbPkcs10.isSelected()) {
			chooser = FileChooserFactory.getPkcs10FileChooser();
		} else {
			chooser = FileChooserFactory.getSpkacFileChooser();
		}

		File currentExportFile = new File(jtfCsrFile.getText().trim());

		if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DGenerateCsr.ChooseCsrFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DGenerateCsr.ChooseCsrFile.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfCsrFile.setText(chosenFile.toString());
			jtfCsrFile.setCaretPosition(0);
		}
	}

	/**
	 * Has the user chosen to generate CSR?
	 * 
	 * @return True if they have
	 */
	public boolean generateSelected() {
		return generateSelected;
	}

	/**
	 * Get the selected format.
	 * 
	 * @return CSR format or null if dialog cancelled
	 */
	public CsrType getFormat() {
		return format;
	}

	/**
	 * Get the selected signature type.
	 * 
	 * @return Signature algorithm or null if dialog cancelled
	 */
	public SignatureType getSignatureType() {
		return signatureAlgorithm;
	}

	/**
	 * Get chosen challenge.
	 * 
	 * @return Challenge or null if dialog cancelled
	 */
	public String getChallenge() {
		return challenge;
	}

	/**
	 * Get chosen CSR file.
	 * 
	 * @return CSR file or null if dialog cancelled
	 */
	public File getCsrFile() {
		return csrFile;
	}

	private void okPressed() {
		if (jrbPkcs10.isSelected()) {
			format = PKCS10;
		} else {
			format = SPKAC;
		}

		signatureAlgorithm = (SignatureType) jcbSignatureAlgorithm.getItemAt(jcbSignatureAlgorithm.getSelectedIndex());

		challenge = jtfChallenge.getText();

		if (challenge.length() == 0) {
			if (format == SPKAC) // Challenge is mandatory for SPKAC
			{
				JOptionPane.showMessageDialog(this, res.getString("DGenerateCsr.ChallengeRequiredForSpkac.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			} else
			// Challenge is optional for PKCS #10
			{
				challenge = null;
			}
		}

		String csrFileStr = jtfCsrFile.getText().trim();

		if (csrFileStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DGenerateCsr.CsrFileRequired.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		File csrFile = new File(csrFileStr);

		if (csrFile.isFile()) {
			String message = MessageFormat.format(res.getString("DGenerateCsr.OverWriteCsrFile.message"), csrFile);

			int selected = JOptionPane.showConfirmDialog(this, message, getTitle(), JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return;
			}
		}

		this.csrFile = csrFile;

		generateSelected = true;

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
