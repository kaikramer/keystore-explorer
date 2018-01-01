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
import java.text.MessageFormat;
import java.util.ResourceBundle;

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
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.kse.crypto.Password;
import org.kse.crypto.privatekey.OpenSslPbeType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.password.JPasswordQualityField;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.utilities.io.FileNameUtil;

/**
 * Dialog used to display options to export a private key from a KeyStore entry
 * as OpenSSL.
 *
 */
public class DExportPrivateKeyOpenSsl extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpOptions;
	private JLabel jlEncrypt;
	private JCheckBox jcbEncrypt;
	private JLabel jlPbeAlg;
	private JComboBox<OpenSslPbeType> jcbPbeAlg;
	private JLabel jlPassword;
	private JComponent jpfPassword;
	private JLabel jlConfirmPassword;
	private JPasswordField jpfConfirmPassword;
	private JLabel jlExportPem;
	private JCheckBox jcbExportPem;
	private JLabel jlExportFile;
	private JTextField jtfExportFile;
	private JButton jbBrowse;
	private JPanel jpButtons;
	private JButton jbExport;
	private JButton jbCancel;

	private String entryAlias;
	private PasswordQualityConfig passwordQualityConfig;
	private boolean exportSelected = false;
	private File exportFile;
	private boolean encrypt;
	private OpenSslPbeType pbeAlgorithm;
	private Password exportPassword;
	private boolean pemEncode;

	/**
	 * Creates a new DExportPrivateKeyOpenSsl dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param entryAlias
	 *            The KeyStore entry to export private key from
	 * @param passwordQualityConfig
	 *            Password quality configuration
	 */
	public DExportPrivateKeyOpenSsl(JFrame parent, String entryAlias, PasswordQualityConfig passwordQualityConfig) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.entryAlias = entryAlias;
		this.passwordQualityConfig = passwordQualityConfig;
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

		jlEncrypt = new JLabel(res.getString("DExportPrivateKeyOpenSsl.jlEncrypt.text"));
		GridBagConstraints gbc_jlEncrypt = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEncrypt.gridy = 0;

		jcbEncrypt = new JCheckBox();
		jcbEncrypt.setSelected(true);
		jcbEncrypt.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jcbEncrypt.tooltip"));
		GridBagConstraints gbc_jcbEncrypt = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbEncrypt.gridy = 0;

		jcbEncrypt.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent evt) {
				if (jcbEncrypt.isSelected()) {
					jcbExportPem.setSelected(true);
					jcbExportPem.setEnabled(false);
				} else {
					jcbExportPem.setEnabled(true);
				}
			}
		});

		jlPbeAlg = new JLabel(res.getString("DExportPrivateKeyOpenSsl.jlPbeAlg.text"));
		GridBagConstraints gbc_jlPbeAlg = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPbeAlg.gridy = 1;

		jcbPbeAlg = new JComboBox<OpenSslPbeType>();
		populatePbeAlgs();
		jcbPbeAlg.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jcbPbeAlg.tooltip"));
		jcbPbeAlg.setSelectedIndex(0);
		GridBagConstraints gbc_jcbPbeAlg = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbPbeAlg.gridy = 1;

		jlPassword = new JLabel(res.getString("DExportPrivateKeyOpenSsl.jlPassword.text"));
		GridBagConstraints gbc_jlPassword = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPassword.gridy = 2;

		if (passwordQualityConfig.getEnabled()) {
			if (passwordQualityConfig.getEnforced()) {
				jpfPassword = new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
			} else {
				jpfPassword = new JPasswordQualityField(15);
			}
		} else {
			jpfPassword = new JPasswordField(15);
		}

		jpfPassword.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jpqfPassword.tooltip"));
		GridBagConstraints gbc_jpfPassword = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jpfPassword.gridy = 2;

		jlConfirmPassword = new JLabel(res.getString("DExportPrivateKeyOpenSsl.jlConfirmPassword.text"));
		GridBagConstraints gbc_jlConfirmPassword = (GridBagConstraints) gbcLbl.clone();
		gbc_jlConfirmPassword.gridy = 3;

		jpfConfirmPassword = new JPasswordField(15);
		jpfConfirmPassword.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jpfConfirmPassword.tooltip"));
		GridBagConstraints gbc_jpfConfirmPassword = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jpfConfirmPassword.gridy = 3;

		jlExportPem = new JLabel(res.getString("DExportPrivateKeyOpenSsl.jlExportPem.text"));
		GridBagConstraints gbc_jlExportPem = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportPem.gridy = 4;

		jcbExportPem = new JCheckBox();
		jcbExportPem.setSelected(true);
		jcbExportPem.setEnabled(false); // Itinitla export setting is with
		// encryption - must be pem
		// export
		jcbExportPem.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jcbExportPem.tooltip"));
		GridBagConstraints gbc_jcbExportPem = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbExportPem.gridy = 4;

		jlExportFile = new JLabel(res.getString("DExportPrivateKeyOpenSsl.jlExportFile.text"));
		GridBagConstraints gbc_jlExportFile = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportFile.gridy = 5;

		jtfExportFile = new JTextField(30);
		jtfExportFile.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jtfExportFile.tooltip"));
		GridBagConstraints gbc_jtfExportFile = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfExportFile.gridy = 5;
		gbc_jtfExportFile.gridwidth = 6;

		jbBrowse = new JButton(res.getString("DExportPrivateKeyOpenSsl.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportPrivateKeyOpenSsl.jbBrowse.mnemonic").charAt(0));
		GridBagConstraints gbc_jbBrowse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbBrowse.gridy = 5;
		gbc_jbBrowse.gridx = 9;

		jbBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DExportPrivateKeyOpenSsl.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DExportPrivateKeyOpenSsl.this);
				}
			}
		});

		jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()),
				new EmptyBorder(5, 5, 5, 5)));

		jpOptions.add(jlEncrypt, gbc_jlEncrypt);
		jpOptions.add(jcbEncrypt, gbc_jcbEncrypt);

		jpOptions.add(jlPbeAlg, gbc_jlPbeAlg);
		jpOptions.add(jcbPbeAlg, gbc_jcbPbeAlg);

		jpOptions.add(jlPassword, gbc_jlPassword);
		jpOptions.add(jpfPassword, gbc_jpfPassword);

		jpOptions.add(jlConfirmPassword, gbc_jlConfirmPassword);
		jpOptions.add(jpfConfirmPassword, gbc_jpfConfirmPassword);

		jpOptions.add(jlExportPem, gbc_jlExportPem);
		jpOptions.add(jcbExportPem, gbc_jcbExportPem);

		jpOptions.add(jlExportFile, gbc_jlExportFile);
		jpOptions.add(jtfExportFile, gbc_jtfExportFile);
		jpOptions.add(jbBrowse, gbc_jbBrowse);

		jcbEncrypt.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jcbEncrypt.isSelected()) {
					jcbPbeAlg.setEnabled(true);
					jpfPassword.setEnabled(true);
					jpfConfirmPassword.setEnabled(true);
				} else {
					jcbPbeAlg.setEnabled(false);
					jpfPassword.setEnabled(false);
					if (jpfPassword instanceof JPasswordQualityField) {
						((JPasswordQualityField) jpfPassword).setText("");
					} else {
						((JPasswordField) jpfPassword).setText("");
					}
					jpfConfirmPassword.setEnabled(false);
					jpfConfirmPassword.setText("");
				}
			}
		});

		jbExport = new JButton(res.getString("DExportPrivateKeyOpenSsl.jbExport.text"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DExportPrivateKeyOpenSsl.jbExport.mnemonic").charAt(0));
		jbExport.setToolTipText(res.getString("DExportPrivateKeyOpenSsl.jbExport.tooltip"));
		jbExport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DExportPrivateKeyOpenSsl.this);
					exportPressed();
				} finally {
					CursorUtil.setCursorFree(DExportPrivateKeyOpenSsl.this);
				}
			}
		});

		jbCancel = new JButton(res.getString("DExportPrivateKeyOpenSsl.jbCancel.text"));
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

		jpButtons = PlatformUtil.createDialogButtonPanel(jbExport, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpOptions, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setTitle(MessageFormat.format(res.getString("DExportPrivateKeyOpenSsl.Title"), entryAlias));
		setResizable(false);

		getRootPane().setDefaultButton(jbExport);

		populateExportFileName();

		pack();
	}

	private void populateExportFileName() {
		File currentDirectory = CurrentDirectory.get();
		String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
		File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.OPENSSL_PVK_EXT);
		jtfExportFile.setText(csrFile.getPath());
	}

	/**
	 * Has the user chosen to export?
	 *
	 * @return True if they have
	 */
	public boolean exportSelected() {
		return exportSelected;
	}

	/**
	 * Get chosen export file.
	 *
	 * @return Export file
	 */
	public File getExportFile() {
		return exportFile;
	}

	/**
	 * Encrypt exported private key?
	 *
	 * @return True if encryption selected
	 */
	public boolean encrypt() {
		return encrypt;
	}

	/**
	 * Get PBE algorithm used for encryption.
	 *
	 * @return PBE algorithm
	 */
	public OpenSslPbeType getPbeAlgorithm() {
		return pbeAlgorithm;
	}

	/**
	 * Get export encryption password.
	 *
	 * @return Export password
	 */
	public Password getExportPassword() {
		return exportPassword;
	}

	/**
	 * Was the option to PEM encode selected?
	 *
	 * @return True if it was
	 */
	public boolean pemEncode() {
		return pemEncode;
	}

	private void populatePbeAlgs() {
		OpenSslPbeType pbeAlgs[] = OpenSslPbeType.values();

		for (int i = 0; i < pbeAlgs.length; i++) {
			jcbPbeAlg.addItem(pbeAlgs[i]);
		}

		jcbPbeAlg.setSelectedIndex(0);
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getOpenSslPvkFileChooser();

		File currentExportFile = new File(jtfExportFile.getText().trim());

		if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
			chooser.setSelectedFile(currentExportFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DExportPrivateKeyOpenSsl.ChooseExportFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
		        : chooser.showDialog(this, res.getString("DExportPrivateKeyOpenSsl.ChooseExportFile.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfExportFile.setText(chosenFile.toString());
			jtfExportFile.setCaretPosition(0);
		}
	}

	private void exportPressed() {
		encrypt = jcbEncrypt.isSelected();

		if (encrypt) {
			pbeAlgorithm = (OpenSslPbeType) jcbPbeAlg.getSelectedItem();

			Password firstPassword;

			if (jpfPassword instanceof JPasswordQualityField) {
				char[] firstPasswordChars = ((JPasswordQualityField) jpfPassword).getPassword();

				if (firstPasswordChars == null) {
					JOptionPane.showMessageDialog(this,
							res.getString("DExportPrivateKeyOpenSsl.MinimumPasswordQualityNotMet.message"),
							res.getString("DExportPrivateKeyOpenSsl.Simple.Title"), JOptionPane.WARNING_MESSAGE);
					return;
				}

				firstPassword = new Password(firstPasswordChars);
			} else {
				firstPassword = new Password(((JPasswordField) jpfPassword).getPassword());
			}

			Password confirmPassword = new Password(jpfConfirmPassword.getPassword());

			if (firstPassword.equals(confirmPassword)) {
				exportPassword = firstPassword;
			} else {
				JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyOpenSsl.PasswordsNoMatch.message"),
						res.getString("DExportPrivateKeyOpenSsl.Simple.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}
		}

		pemEncode = jcbExportPem.isSelected();

		String exportFileChars = jtfExportFile.getText().trim();

		if (exportFileChars.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyOpenSsl.ExportFileRequired.message"),
					res.getString("DExportPrivateKeyOpenSsl.Simple.Title"), JOptionPane.WARNING_MESSAGE);
			return;
		}

		File exportFile = new File(exportFileChars);

		if (exportFile.isFile()) {
			String message = MessageFormat.format(
					res.getString("DExportPrivateKeyOpenSsl.OverWriteExportFile.message"), exportFile);

			int selected = JOptionPane.showConfirmDialog(this, message,
					res.getString("DExportPrivateKeyOpenSsl.Simple.Title"), JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return;
			}
		}

		this.exportFile = exportFile;

		exportSelected = true;

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
