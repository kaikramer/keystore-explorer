/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs.sign;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;

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
import java.io.IOException;
import java.security.PrivateKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.jar.JarFile;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.keystore_explorer.crypto.CryptoException;
import net.sf.keystore_explorer.crypto.digest.DigestType;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.crypto.signing.JarSigner;
import net.sf.keystore_explorer.crypto.signing.SignatureType;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.dialogs.DialogHelper;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;
import net.sf.keystore_explorer.utilities.io.FileNameUtil;

/**
 * Dialog that displays the presents JAR signing options.
 *
 */
public class DSignJar extends JEscDialog {
	private static ResourceBundle res = ResourceBundle
			.getBundle("net/sf/keystore_explorer/gui/dialogs/sign/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlInputJar;
	private JTextField jtfInputJar;
	private JButton jbInputJarBrowse;
	private JLabel jlSignDirectly;
	private JCheckBox jcbSignDirectly;
	private JLabel jlOutputJar;
	private JTextField jtfOutputJar;
	private JButton jbOutputJarBrowse;
	private JLabel jlSignatureName;
	private JTextField jtfSignatureName;
	private JLabel jlSignatureAlgorithm;
	private JComboBox jcbSignatureAlgorithm;
	private JLabel jlDigestAlgorithm;
	private JComboBox jcbDigestAlgorithm;
	private JPanel jpOptions;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PrivateKey signPrivateKey;
	private KeyPairType signKeyPairType;
	private File inputJarFile;
	private File outputJarFile;
	private String signatureName;
	private SignatureType signatureType;
	private DigestType digestType;


	/**
	 * Creates a new DSignJar dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param signPrivateKey
	 *            Signing key pair's private key
	 * @param signKeyPairType
	 *            Signing key pair's type
	 * @param signatureName
	 *            Default signature name
	 * @throws CryptoException
	 *             A crypto problem was encountered constructing the dialog
	 */
	public DSignJar(JFrame parent, PrivateKey signPrivateKey, KeyPairType signKeyPairType, String signatureName)
			throws CryptoException {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		this.signPrivateKey = signPrivateKey;
		this.signKeyPairType = signKeyPairType;
		setTitle(res.getString("DSignJar.Title"));
		initComponents(signatureName);
	}

	private void initComponents(String signatureName) throws CryptoException {
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 1;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;
		gbcLbl.weightx = 0;

		GridBagConstraints gbcCtrl = new GridBagConstraints();
		gbcCtrl.gridx = 1;
		gbcCtrl.gridwidth = 1;
		gbcCtrl.gridheight = 1;
		gbcCtrl.insets = new Insets(5, 5, 5, 5);
		gbcCtrl.anchor = GridBagConstraints.WEST;
		gbcCtrl.fill = GridBagConstraints.NONE;
		gbcCtrl.weightx = 1;

		GridBagConstraints gbcBrws = new GridBagConstraints();
		gbcBrws.gridx = 2;
		gbcBrws.gridwidth = 1;
		gbcBrws.gridheight = 1;
		gbcBrws.insets = new Insets(5, 5, 5, 5);
		gbcBrws.anchor = GridBagConstraints.WEST;
		gbcBrws.fill = GridBagConstraints.NONE;
		gbcBrws.weightx = 1;

		jlInputJar = new JLabel(res.getString("DSignJar.jlInputJar.text"));
		GridBagConstraints gbc_jlInputJar = (GridBagConstraints) gbcLbl.clone();
		gbc_jlInputJar.gridy = 0;

		jtfInputJar = new JTextField(30);
		jtfInputJar.setCaretPosition(0);
		jtfInputJar.setToolTipText(res.getString("DSignJar.jtfInputJar.tooltip"));
		GridBagConstraints gbc_jtfInputJar = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfInputJar.gridy = 0;

		jbInputJarBrowse = new JButton(res.getString("DSignJar.jbInputJarBrowse.text"));
		PlatformUtil.setMnemonic(jbInputJarBrowse, res.getString("DSignJar.jbInputJarBrowse.mnemonic").charAt(0));
		jbInputJarBrowse.setToolTipText(res.getString("DSignJar.jbInputJarBrowse.tooltip"));
		jbInputJarBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignJar.this);
					inputJarBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignJar.this);
				}
			}
		});
		GridBagConstraints gbc_jbInputJarBrowse = (GridBagConstraints) gbcBrws.clone();
		gbc_jbInputJarBrowse.gridy = 0;

		jlSignDirectly = new JLabel(res.getString("DSignJar.jlSignDirectly.text"));
		GridBagConstraints gbc_jlSignDirectly = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignDirectly.gridy = 1;

		jcbSignDirectly = new JCheckBox();
		jcbSignDirectly.setSelected(true);
		jcbSignDirectly.setToolTipText(res.getString("DSignJar.jcbSignDirectly.tooltip"));
		GridBagConstraints gbc_jcbSignDirectly = (GridBagConstraints) gbcCtrl.clone();
		gbc_jcbSignDirectly.gridy = 1;

		jcbSignDirectly.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				jtfOutputJar.setEnabled(!jcbSignDirectly.isSelected());
				jbOutputJarBrowse.setEnabled(!jcbSignDirectly.isSelected());
			}
		});

		jlOutputJar = new JLabel(res.getString("DSignJar.jlOutputJar.text"));
		GridBagConstraints gbc_jlOutputJar = (GridBagConstraints) gbcLbl.clone();
		gbc_jlOutputJar.gridy = 2;

		jtfOutputJar = new JTextField(30);
		jtfOutputJar.setEnabled(false);
		jtfOutputJar.setCaretPosition(0);
		jtfOutputJar.setToolTipText(res.getString("DSignJar.jtfOutputJar.tooltip"));
		GridBagConstraints gbc_jtfOutputJar = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfOutputJar.gridy = 2;

		jbOutputJarBrowse = new JButton(res.getString("DSignJar.jbOutputJarBrowse.text"));
		PlatformUtil.setMnemonic(jbOutputJarBrowse, res.getString("DSignJar.jbOutputJarBrowse.mnemonic").charAt(0));
		jbOutputJarBrowse.setToolTipText(res.getString("DSignJar.jbOutputJarBrowse.tooltip"));
		jbOutputJarBrowse.setEnabled(false);
		jbOutputJarBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignJar.this);
					outputJarBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignJar.this);
				}
			}
		});
		GridBagConstraints gbc_jbOutputJarBrowse = (GridBagConstraints) gbcBrws.clone();
		gbc_jbOutputJarBrowse.gridy = 2;

		jlSignatureName = new JLabel(res.getString("DSignJar.jlSignatureName.text"));
		GridBagConstraints gbc_jlSignatureName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureName.gridy = 3;

		jtfSignatureName = new JTextField(convertSignatureName(signatureName), 15);
		jtfSignatureName.setCaretPosition(0);
		jtfSignatureName.setToolTipText(res.getString("DSignJar.jtfSignatureName.tooltip"));
		GridBagConstraints gbc_jtfSignatureName = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfSignatureName.gridy = 3;

		jlSignatureAlgorithm = new JLabel(res.getString("DSignJar.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 4;

		jcbSignatureAlgorithm = new JComboBox();
		DialogHelper.populateSigAlgs(signKeyPairType, this.signPrivateKey, jcbSignatureAlgorithm);
		jcbSignatureAlgorithm.setToolTipText(res.getString("DSignJar.jcbSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jcbSignatureAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jcbSignatureAlgorithm.gridy = 4;

		jlDigestAlgorithm = new JLabel(res.getString("DSignJar.jlDigestAlgorithm.text"));
		GridBagConstraints gbc_jlDigestAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlDigestAlgorithm.gridy = 5;

		jcbDigestAlgorithm = new JComboBox();
		populateDigestAlgs();
		jcbDigestAlgorithm.setToolTipText(res.getString("DSignJar.jcbDigestAlgorithm.tooltip"));
		GridBagConstraints gbc_jcbDigestAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jcbDigestAlgorithm.gridy = 5;

		jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpOptions.add(jlInputJar, gbc_jlInputJar);
		jpOptions.add(jtfInputJar, gbc_jtfInputJar);
		jpOptions.add(jbInputJarBrowse, gbc_jbInputJarBrowse);
		jpOptions.add(jlSignDirectly, gbc_jlSignDirectly);
		jpOptions.add(jcbSignDirectly, gbc_jcbSignDirectly);
		jpOptions.add(jlOutputJar, gbc_jlOutputJar);
		jpOptions.add(jtfOutputJar, gbc_jtfOutputJar);
		jpOptions.add(jbOutputJarBrowse, gbc_jbOutputJarBrowse);
		jpOptions.add(jlSignatureName, gbc_jlSignatureName);
		jpOptions.add(jtfSignatureName, gbc_jtfSignatureName);
		jpOptions.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpOptions.add(jcbSignatureAlgorithm, gbc_jcbSignatureAlgorithm);
		jpOptions.add(jlDigestAlgorithm, gbc_jlDigestAlgorithm);
		jpOptions.add(jcbDigestAlgorithm, gbc_jcbDigestAlgorithm);

		jbOK = new JButton(res.getString("DSignJar.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DSignJar.jbCancel.text"));
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
		getContentPane().add(jpOptions, BorderLayout.NORTH);
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

	private String convertSignatureName(String signatureName) {
		/*
		 * Convert the supplied signature name to make it valid for use with
		 * signing, i.e. any characters that are not 'a-z', 'A-Z', '0-9', '_' or
		 * '-' are converted to '_'
		 */
		StringBuffer sb = new StringBuffer(signatureName.length());

		for (int i = 0; i < signatureName.length(); i++) {
			char c = signatureName.charAt(i);

			if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_') {
				c = '_';
			}
			sb.append(c);
		}

		return sb.toString();
	}

	private void populateDigestAlgs() {
		jcbDigestAlgorithm.removeAllItems();

		jcbDigestAlgorithm.addItem(DigestType.MD2);
		jcbDigestAlgorithm.addItem(DigestType.MD5);
		jcbDigestAlgorithm.addItem(DigestType.SHA1);
		jcbDigestAlgorithm.addItem(DigestType.SHA224);
		jcbDigestAlgorithm.addItem(DigestType.SHA256);
		jcbDigestAlgorithm.addItem(DigestType.SHA384);
		jcbDigestAlgorithm.addItem(DigestType.SHA512);

		jcbDigestAlgorithm.setSelectedItem(DigestType.SHA1);
	}

	/**
	 * Get chosen input JAR file.
	 *
	 * @return Input JAR file
	 */
	public File getInputJar() {
		return inputJarFile;
	}

	/**
	 * Get chosen output JAR file.
	 *
	 * @return Output JAR file
	 */
	public File getOutputJar() {
		return outputJarFile;
	}

	/**
	 * Get chosen signature name.
	 *
	 * @return Signature name or null if dialog cancelled
	 */
	public String getSignatureName() {
		return signatureName;
	}

	/**
	 * Get chosen signature type.
	 *
	 * @return Signature type or null if dialog cancelled
	 */
	public SignatureType getSignatureType() {
		return signatureType;
	}

	/**
	 * Get chosen digest type.
	 *
	 * @return Digest type or null if dialog cancelled
	 */
	public DigestType getDigestType() {
		return digestType;
	}

	private boolean verifySignatureName(String signatureName) {
		/*
		 * Verify that the supplied signature name is valid for use in the
		 * signing of a JAR file, ie contains only alphanumeric characters and
		 * the characters '-' or '_'
		 */
		for (int i = 0; i < signatureName.length(); i++) {
			char c = signatureName.charAt(i);

			if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_') {
				return false;
			}
		}

		return true;
	}

	private void okPressed() {
		String inputJar = jtfInputJar.getText().trim();

		if (inputJar.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignJar.InputJarRequired.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		File inputJarFile = new File(inputJar);

		if (!inputJarFile.isFile()) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DSignJar.InputJarNotFile.message"), inputJarFile), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		try {
			new JarFile(inputJarFile);
		} catch (IOException ex) {
			String problemStr = MessageFormat.format(res.getString("DSignJar.NoOpenJar.Problem"),
					inputJarFile.getName());

			String[] causes = new String[] { res.getString("DSignJar.NotJar.Cause"),
					res.getString("DSignJar.CorruptedJar.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(this, res.getString("DSignJar.ProblemOpeningJar.Title"),
					APPLICATION_MODAL, problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return;
		}

		boolean signDirectly = jcbSignDirectly.isSelected();

		File outputJarFile;
		if (signDirectly) {
			outputJarFile = inputJarFile;
		} else {
			String outputJar = jtfOutputJar.getText().trim();

			if (outputJar.length() == 0) {
				JOptionPane.showMessageDialog(this, res.getString("DSignJar.OutputJarRequired.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			outputJarFile = new File(outputJar);
		}

		String signatureName = jtfSignatureName.getText().trim();

		if (signatureName.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignJar.ValReqSignatureName.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		if (!verifySignatureName(signatureName)) {
			JOptionPane.showMessageDialog(this, res.getString("DSignJar.ValJarSignatureName.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		if (!signDirectly) {
			if (outputJarFile.isFile()) {
				String message = MessageFormat.format(res.getString("DSignJar.OverWriteOutputJarFile.message"),
						outputJarFile);

				int selected = JOptionPane.showConfirmDialog(this, message, getTitle(), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}
		}

		try {
			if (JarSigner.hasSignature(new File(inputJar), signatureName)) {
				String message = MessageFormat.format(res.getString("DSignJar.SignatureOverwrite.message"),
						signatureName);
				int selected = JOptionPane.showConfirmDialog(this, message, getTitle(), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}
		} catch (IOException ex) {
			DError.displayError(this, ex);
			return;
		}

		this.inputJarFile = inputJarFile;
		this.outputJarFile = outputJarFile;
		this.signatureName = signatureName;
		signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
		digestType = (DigestType) jcbDigestAlgorithm.getSelectedItem();

		closeDialog();
	}

	private void inputJarBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();

		File currentFile = new File(jtfInputJar.getText().trim());

		if ((currentFile.getParentFile() != null) && (currentFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
			chooser.setSelectedFile(currentFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignJar.ChooseInputJar.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DSignJar.InputJarChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfInputJar.setText(chosenFile.toString());
			jtfInputJar.setCaretPosition(0);
			populateOutputJarFileName(chosenFile);
		}
	}

    private void populateOutputJarFileName(File chosenFile) {
        String fileBaseName = FileNameUtil.removeExtension(chosenFile.getName());
        if (fileBaseName != null) {
            String outFileName = fileBaseName + "_signed.jar";
            File outFile = new File(chosenFile.getParentFile(), outFileName);
            jtfOutputJar.setText(outFile.getPath());
        }
    }

	private void outputJarBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();

		File currentFile = new File(jtfOutputJar.getText());

		if ((currentFile.getParentFile() != null) && (currentFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
			chooser.setSelectedFile(currentFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignJar.ChooseOutputJar.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DSignJar.OutputJarChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfOutputJar.setText(chosenFile.toString());
			jtfOutputJar.setCaretPosition(0);
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
