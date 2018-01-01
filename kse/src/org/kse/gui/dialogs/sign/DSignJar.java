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
package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.jar.JarFile;

import javax.swing.AbstractAction;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UIManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.JarSigner;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dialogs.DialogHelper;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.io.FileNameUtil;
import org.kse.utilities.io.IOUtils;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that displays the presents JAR signing options.
 *
 */
public class DSignJar extends JEscDialog {
	private static final long serialVersionUID = -5095469699284737624L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/sign/resources");

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
	private JComboBox<SignatureType> jcbSignatureAlgorithm;
	private JLabel jlDigestAlgorithm;
	private JComboBox<DigestType> jcbDigestAlgorithm;
	private JLabel jlAddTimestamp;
	private JCheckBox jcbAddTimestamp;
	private JLabel jlTimestampServerUrl;
	private JComboBox<String> jcbTimestampServerUrl;
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
	private String tsaUrl;

	private Provider provider;


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
	public DSignJar(JFrame parent, PrivateKey signPrivateKey, KeyPairType signKeyPairType, String signatureName,
			Provider provider) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.signPrivateKey = signPrivateKey;
		this.signKeyPairType = signKeyPairType;
		this.provider = provider;
		setTitle(res.getString("DSignJar.Title"));
		initComponents(signatureName);
	}

	private void initComponents(String signatureName) throws CryptoException {

		jlInputJar = new JLabel(res.getString("DSignJar.jlInputJar.text"));
		jtfInputJar = new JTextField(30);
		jtfInputJar.setCaretPosition(0);
		jtfInputJar.setToolTipText(res.getString("DSignJar.jtfInputJar.tooltip"));

		jbInputJarBrowse = new JButton(res.getString("DSignJar.jbInputJarBrowse.text"));
		PlatformUtil.setMnemonic(jbInputJarBrowse, res.getString("DSignJar.jbInputJarBrowse.mnemonic").charAt(0));
		jbInputJarBrowse.setToolTipText(res.getString("DSignJar.jbInputJarBrowse.tooltip"));

		jlSignDirectly = new JLabel(res.getString("DSignJar.jlSignDirectly.text"));
		jcbSignDirectly = new JCheckBox();
		jcbSignDirectly.setSelected(true);
		jcbSignDirectly.setToolTipText(res.getString("DSignJar.jcbSignDirectly.tooltip"));

		jlOutputJar = new JLabel(res.getString("DSignJar.jlOutputJar.text"));
		jtfOutputJar = new JTextField(30);
		jtfOutputJar.setEnabled(false);
		jtfOutputJar.setCaretPosition(0);
		jtfOutputJar.setToolTipText(res.getString("DSignJar.jtfOutputJar.tooltip"));

		jbOutputJarBrowse = new JButton(res.getString("DSignJar.jbOutputJarBrowse.text"));
		PlatformUtil.setMnemonic(jbOutputJarBrowse, res.getString("DSignJar.jbOutputJarBrowse.mnemonic").charAt(0));
		jbOutputJarBrowse.setToolTipText(res.getString("DSignJar.jbOutputJarBrowse.tooltip"));
		jbOutputJarBrowse.setEnabled(false);

		jlSignatureName = new JLabel(res.getString("DSignJar.jlSignatureName.text"));
		jtfSignatureName = new JTextField(convertSignatureName(signatureName), 15);
		jtfSignatureName.setCaretPosition(0);
		jtfSignatureName.setToolTipText(res.getString("DSignJar.jtfSignatureName.tooltip"));

		jlSignatureAlgorithm = new JLabel(res.getString("DSignJar.jlSignatureAlgorithm.text"));
		jcbSignatureAlgorithm = new JComboBox<SignatureType>();
		DialogHelper.populateSigAlgs(signKeyPairType, this.signPrivateKey, provider, jcbSignatureAlgorithm);
		jcbSignatureAlgorithm.setToolTipText(res.getString("DSignJar.jcbSignatureAlgorithm.tooltip"));

		jlDigestAlgorithm = new JLabel(res.getString("DSignJar.jlDigestAlgorithm.text"));
		jcbDigestAlgorithm = new JComboBox<DigestType>();
		populateDigestAlgs();
		jcbDigestAlgorithm.setToolTipText(res.getString("DSignJar.jcbDigestAlgorithm.tooltip"));

		jlAddTimestamp = new JLabel(res.getString("DSignJar.jlAddTimestamp.text"));
		jcbAddTimestamp = new JCheckBox();
		jcbAddTimestamp.setSelected(false);
		jcbAddTimestamp.setToolTipText(res.getString("DSignJar.jcbAddTimestamp.tooltip"));

		jlTimestampServerUrl = new JLabel(res.getString("DSignJar.jlTimestampServerUrl.text"));
		jcbTimestampServerUrl = new JComboBox<String>();
		jcbTimestampServerUrl.setEditable(true);
		jcbTimestampServerUrl.setEnabled(false);
		jcbTimestampServerUrl.setToolTipText(res.getString("DSignJar.jcbTimestampServerUrl.tooltip"));
		jcbTimestampServerUrl.setModel(new DefaultComboBoxModel<String>(getTsaUrls()));

		jbOK = new JButton(res.getString("DSignJar.jbOK.text"));

		jbCancel = new JButton(res.getString("DSignJar.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[para]unrel[right]unrel[]", "[]unrel[]"));
		MiGUtil.addSeparator(pane, res.getString("DSignJar.jlFiles.text"));
		pane.add(jlInputJar, "skip");
		pane.add(jtfInputJar, "sgx");
		pane.add(jbInputJarBrowse, "wrap");
		pane.add(jlSignDirectly, "skip");
		pane.add(jcbSignDirectly, "wrap");
		pane.add(jlOutputJar, "skip");
		pane.add(jtfOutputJar, "sgx");
		pane.add(jbOutputJarBrowse, "wrap para");
		MiGUtil.addSeparator(pane, res.getString("DSignJar.jlSignature.text"));
		pane.add(jlSignatureName, "skip");
		pane.add(jtfSignatureName, "sgx, wrap");
		pane.add(jlSignatureAlgorithm, "skip");
		pane.add(jcbSignatureAlgorithm, "sgx, wrap");
		pane.add(jlDigestAlgorithm, "skip");
		pane.add(jcbDigestAlgorithm, "sgx, wrap para");
		MiGUtil.addSeparator(pane, res.getString("DSignJar.jlTimestamp.text"));
		pane.add(jlAddTimestamp, "skip");
		pane.add(jcbAddTimestamp, "wrap");
		pane.add(jlTimestampServerUrl, "skip");
		pane.add(jcbTimestampServerUrl, "sgx, wrap para");
		pane.add(new JSeparator(), "spanx, growx, wrap para");
		pane.add(jpButtons, "right, spanx");

		// actions
		jbInputJarBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignJar.this);
					inputJarBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignJar.this);
				}
			}
		});

		jcbSignDirectly.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				jtfOutputJar.setEnabled(!jcbSignDirectly.isSelected());
				jbOutputJarBrowse.setEnabled(!jcbSignDirectly.isSelected());
			}
		});

		jbOutputJarBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignJar.this);
					outputJarBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignJar.this);
				}
			}
		});

		jcbAddTimestamp.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				jcbTimestampServerUrl.setEnabled(jcbAddTimestamp.isSelected());
			}
		});


		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
		setLocationRelativeTo(null);
	}

	private String[] getTsaUrls() {
		return new String[] { "https://timestamp.geotrust.com/tsa", "http://tsa.starfieldtech.com",
				"http://www.startssl.com/timestamp", "http://timestamp.globalsign.com/scripts/timstamp.dll",
		"http://timestamp.comodoca.com/rfc3161"};
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

	/**
	 * Get chosen TSA URL.
	 *
	 * @return TSA URL or null if dialog cancelled
	 */
	public String getTimestampingServerUrl() {
		return tsaUrl;
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

		JarFile jarFile = null;
		try {
			jarFile = new JarFile(inputJarFile);
		} catch (IOException ex) {
			String problemStr = MessageFormat.format(res.getString("DSignJar.NoOpenJar.Problem"),
					inputJarFile.getName());

			String[] causes = new String[] { res.getString("DSignJar.NotJar.Cause"),
					res.getString("DSignJar.CorruptedJar.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(this, res.getString("DSignJar.ProblemOpeningJar.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return;
		} finally {
			IOUtils.closeQuietly(jarFile);
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

		if (!signDirectly && outputJarFile.isFile()) {
			String message = MessageFormat.format(res.getString("DSignJar.OverWriteOutputJarFile.message"),
					outputJarFile);

			int selected = JOptionPane.showConfirmDialog(this, message, getTitle(), JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return;
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

		if (jcbAddTimestamp.isSelected() && jcbTimestampServerUrl.getSelectedItem().toString().isEmpty()) {
			JOptionPane.showMessageDialog(this, res.getString("DSignJar.EmptyTimestampUrl.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		this.inputJarFile = inputJarFile;
		this.outputJarFile = outputJarFile;
		this.signatureName = signatureName;
		signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
		digestType = (DigestType) jcbDigestAlgorithm.getSelectedItem();
		if (jcbAddTimestamp.isSelected()) {
			tsaUrl = jcbTimestampServerUrl.getSelectedItem().toString();
		}

		closeDialog();
	}

	private void inputJarBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();

		File currentFile = new File(jtfInputJar.getText().trim());

		if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
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

		if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
			chooser.setSelectedFile(currentFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignJar.ChooseOutputJar.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
				: chooser.showDialog(this, res.getString("DSignJar.OutputJarChooser.button"));
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

	// for quick UI testing
	public static void main(String[] args) throws Exception {
		UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		Security.addProvider(new BouncyCastleProvider());

		java.awt.EventQueue.invokeLater(new Runnable() {

			@Override
			public void run() {
				try {
					KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyPairType.RSA.jce(), "BC");
					kpg.initialize(1024, new SecureRandom());
					KeyPair kp = kpg.generateKeyPair();
					DSignJar dialog = new DSignJar(new JFrame(), kp.getPrivate(), KeyPairType.RSA, "signature name", null);
					dialog.addWindowListener(new java.awt.event.WindowAdapter() {
						@Override
						public void windowClosing(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
						@Override
						public void windowDeactivated(WindowEvent e) {
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
