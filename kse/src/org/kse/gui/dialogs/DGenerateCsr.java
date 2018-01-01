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

import static org.kse.crypto.csr.CsrType.PKCS10;
import static org.kse.crypto.csr.CsrType.SPKAC;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.crypto.CryptoException;
import org.kse.crypto.csr.CsrType;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.io.FileNameUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to choose parameters for CSR generation.
 *
 */
public class DGenerateCsr extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlFormat;
	private JRadioButton jrbPkcs10;
	private JRadioButton jrbSpkac;
	private JLabel jlSignatureAlgorithm;
	private JComboBox<SignatureType> jcbSignatureAlgorithm;
	private JLabel jlChallenge;
	private JTextField jtfChallenge;
	private JLabel jlUnstructuredName;
	private JTextField jtfUnstructuredName;
	private JLabel jlExtensions;
	private JCheckBox jcbExtensions;
	private JLabel jlCsrFile;
	private JTextField jtfCsrFile;
	private JButton jbBrowse;
	private JButton jbOK;
	private JButton jbCancel;

	private boolean generateSelected = false;
	private String alias;
	private PrivateKey privateKey;
	private KeyPairType keyPairType;
	private Provider provider;
	private CsrType format;
	private SignatureType signatureAlgorithm;
	private String challenge;
	private String unstructuredName;
	private boolean addExtensionsWanted;
	private File csrFile;

	private String path;

	/**
	 * Creates a new DGenerateCsr dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param privateKey
	 *            Private key
	 * @param keyPairType
	 *            Key pair algorithm
	 * @param path
	 *             Path to keystore file
	 * @throws CryptoException
	 *             A problem was encountered with the supplied private key
	 */
	public DGenerateCsr(JFrame parent, String alias, PrivateKey privateKey, KeyPairType keyPairType, String path,
			Provider provider) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.alias = alias;
		this.privateKey = privateKey;
		this.keyPairType = keyPairType;
		this.path = path;
		this.provider = provider;
		setTitle(res.getString("DGenerateCsr.Title"));
		initComponents();
	}

	private void initComponents() throws CryptoException {
		jlFormat = new JLabel(res.getString("DGenerateCsr.jlFormat.text"));

		jrbPkcs10 = new JRadioButton(res.getString("DGenerateCsr.jrbPkcs10.text"), false);
		PlatformUtil.setMnemonic(jrbPkcs10, res.getString("DGenerateCsr.jrbPkcs10.mnemonic").charAt(0));
		jrbPkcs10.setToolTipText(res.getString("DGenerateCsr.jrbPkcs10.tooltip"));

		jrbSpkac = new JRadioButton(res.getString("DGenerateCsr.jrbSpkac.text"), true);
		PlatformUtil.setMnemonic(jrbSpkac, res.getString("DGenerateCsr.jrbSpkac.mnemonic").charAt(0));
		jrbSpkac.setToolTipText(res.getString("DGenerateCsr.jrbSpkac.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbPkcs10);
		buttonGroup.add(jrbSpkac);

		jrbPkcs10.setSelected(true);

		jlSignatureAlgorithm = new JLabel(res.getString("DGenerateCsr.jlSignatureAlgorithm.text"));

		jcbSignatureAlgorithm = new JComboBox<SignatureType>();
		jcbSignatureAlgorithm.setMaximumRowCount(10);
		jcbSignatureAlgorithm.setToolTipText(res.getString("DGenerateCsr.jcbSignatureAlgorithm.tooltip"));
		DialogHelper.populateSigAlgs(keyPairType, privateKey, provider, jcbSignatureAlgorithm);

		jlChallenge = new JLabel(res.getString("DGenerateCsr.jlChallenge.text"));

		jtfChallenge = new JTextField(15);
		jtfChallenge.setToolTipText(res.getString("DGenerateCsr.jtfChallenge.tooltip"));

		jlUnstructuredName = new JLabel(res.getString("DGenerateCsr.jlUnstructuredName.text"));

		jtfUnstructuredName = new JTextField(30);
		jtfUnstructuredName.setToolTipText(res.getString("DGenerateCsr.jtfUnstructuredName.tooltip"));

		jlExtensions = new JLabel(res.getString("DGenerateCsr.jlExtensions.text"));

		jcbExtensions = new JCheckBox(res.getString("DGenerateCsr.jcbExtensions.text"));
		jcbExtensions.setToolTipText(res.getString("DGenerateCsr.jcbExtensions.tooltip"));

		jlCsrFile = new JLabel(res.getString("DGenerateCsr.jlCsrFile.text"));

		jtfCsrFile = new JTextField(30);
		jtfCsrFile.setToolTipText(res.getString("DGenerateCsr.jtfCsrFile.tooltip"));
		populateCsrFileName();

		jbBrowse = new JButton(res.getString("DGenerateCsr.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DGenerateCsr.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DGenerateCsr.jbBrowse.mnemonic").charAt(0));

		jbOK = new JButton(res.getString("DGenerateCsr.jbOK.text"));
		jbCancel = new JButton(res.getString("DGenerateCsr.jbCancel.text"));

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		pane.add(jlFormat, "");
		pane.add(jrbPkcs10, "split 2");
		pane.add(jrbSpkac, "wrap");
		pane.add(jlSignatureAlgorithm, "");
		pane.add(jcbSignatureAlgorithm, "wrap");
		pane.add(jlChallenge, "");
		pane.add(jtfChallenge, "wrap");
		pane.add(jlUnstructuredName, "");
		pane.add(jtfUnstructuredName, "wrap");
		// pane.add(jlExtensions, "");
		pane.add(jcbExtensions, "skip, wrap");
		pane.add(jlCsrFile, "");
		pane.add(jtfCsrFile, "");
		pane.add(jbBrowse, "wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
		pane.add(jbCancel, "spanx, split 2, tag cancel");
		pane.add(jbOK, "tag ok");

		// actions
		jrbPkcs10.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				// unstructured name and extensions are Pkcs10-only
				if (jrbPkcs10.isSelected()) {
					jlUnstructuredName.setEnabled(true);
					jtfUnstructuredName.setEnabled(true);
					jlExtensions.setEnabled(true);
					jcbExtensions.setEnabled(true);
				} else {
					jlUnstructuredName.setEnabled(false);
					jtfUnstructuredName.setEnabled(false);
					jlExtensions.setEnabled(false);
					jcbExtensions.setEnabled(false);
				}
			}
		});

		jbBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DGenerateCsr.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DGenerateCsr.this);
				}
			}
		});

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

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

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populateCsrFileName() {
		String sanitizedAlias = FileNameUtil.cleanFileName(alias);
		File csrFile = new File(path, sanitizedAlias + ".csr");
		jtfCsrFile.setText(csrFile.getPath());
	}

	private void browsePressed() {
		JFileChooser chooser = null;

		if (jrbPkcs10.isSelected()) {
			chooser = FileChooserFactory.getPkcs10FileChooser();
		} else {
			chooser = FileChooserFactory.getSpkacFileChooser();
		}

		File currentExportFile = new File(jtfCsrFile.getText().trim());

		if (currentExportFile.getParentFile() != null && currentExportFile.getParentFile().exists()) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
			chooser.setSelectedFile(currentExportFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DGenerateCsr.ChooseCsrFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
				: chooser.showDialog(this, res.getString("DGenerateCsr.ChooseCsrFile.button"));
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
	 * Get unstructured name.
	 *
	 * @return unstructuredName or null if dialog cancelled
	 */
	public String getUnstructuredName() {
		return unstructuredName;
	}

	/**
	 * Add extensions to request?
	 *
	 * @return true if user wants to add extensions
	 */
	public boolean isAddExtensionsWanted() {
		return addExtensionsWanted;
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
			if (format == SPKAC) {
				// Challenge is mandatory for SPKAC
				JOptionPane.showMessageDialog(this, res.getString("DGenerateCsr.ChallengeRequiredForSpkac.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			} else {
				// Challenge is optional for PKCS #10
				challenge = null;
			}
		}

		unstructuredName = jtfUnstructuredName.getText();
		if (unstructuredName.length() == 0) {
			unstructuredName = null;
		}

		addExtensionsWanted = jcbExtensions.isSelected();

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

	// for quick testing
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		javax.swing.UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		java.awt.EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
					PrivateKey privateKey = keyGen.genKeyPair().getPrivate();
					DGenerateCsr dialog = new DGenerateCsr(new javax.swing.JFrame(), "alias (test)", privateKey,
							KeyPairType.RSA, "", new BouncyCastleProvider());
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
