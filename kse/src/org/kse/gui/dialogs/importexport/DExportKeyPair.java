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
import java.text.MessageFormat;
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

import org.kse.crypto.Password;
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
 * Dialog used to display options to export a key pair from a KeyStore entry.
 *
 */
public class DExportKeyPair extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpOptions;
	private JLabel jlPassword;
	private JComponent jpfPassword;
	private JLabel jlConfirmPassword;
	private JPasswordField jpfConfirmPassword;
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
	private Password exportPassword;

	/**
	 * Creates a new DExportKeyPair dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param entryAlias
	 *            The KeyStore entry to export key pair from
	 * @param passwordQualityConfig
	 *            Password quality configuration
	 */
	public DExportKeyPair(JFrame parent, String entryAlias, PasswordQualityConfig passwordQualityConfig) {
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

		jlPassword = new JLabel(res.getString("DExportKeyPair.jlPassword.text"));
		GridBagConstraints gbc_jlPassword = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPassword.gridy = 0;

		if (passwordQualityConfig.getEnabled()) {
			if (passwordQualityConfig.getEnforced()) {
				jpfPassword = new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
			} else {
				jpfPassword = new JPasswordQualityField(15);
			}
		} else {
			jpfPassword = new JPasswordField(15);
		}

		jpfPassword.setToolTipText(res.getString("DExportKeyPair.jpqfPassword.tooltip"));
		GridBagConstraints gbc_jpfPassword = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jpfPassword.gridy = 0;

		jlConfirmPassword = new JLabel(res.getString("DExportKeyPair.jlConfirmPassword.text"));
		GridBagConstraints gbc_jlConfirmPassword = (GridBagConstraints) gbcLbl.clone();
		gbc_jlConfirmPassword.gridy = 1;

		jpfConfirmPassword = new JPasswordField(15);
		jpfConfirmPassword.setToolTipText(res.getString("DExportKeyPair.jpfConfirmPassword.tooltip"));
		GridBagConstraints gbc_jpfConfirmPassword = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jpfConfirmPassword.gridy = 1;

		jlExportFile = new JLabel(res.getString("DExportKeyPair.jlExportFile.text"));
		GridBagConstraints gbc_jlExportFile = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportFile.gridy = 2;

		jtfExportFile = new JTextField(30);
		jtfExportFile.setToolTipText(res.getString("DExportKeyPair.jtfExportFile.tooltip"));
		GridBagConstraints gbc_jtfExportFile = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfExportFile.gridy = 2;
		gbc_jtfExportFile.gridwidth = 6;

		jbBrowse = new JButton(res.getString("DExportKeyPair.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DExportKeyPair.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportKeyPair.jbBrowse.mnemonic").charAt(0));
		GridBagConstraints gbc_jbBrowse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbBrowse.gridy = 2;
		gbc_jbBrowse.gridx = 9;

		jbBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DExportKeyPair.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DExportKeyPair.this);
				}
			}
		});

		jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()),
				new EmptyBorder(5, 5, 5, 5)));

		jpOptions.add(jlPassword, gbc_jlPassword);
		jpOptions.add(jpfPassword, gbc_jpfPassword);

		jpOptions.add(jlConfirmPassword, gbc_jlConfirmPassword);
		jpOptions.add(jpfConfirmPassword, gbc_jpfConfirmPassword);

		jpOptions.add(jlExportFile, gbc_jlExportFile);
		jpOptions.add(jtfExportFile, gbc_jtfExportFile);
		jpOptions.add(jbBrowse, gbc_jbBrowse);

		jbExport = new JButton(res.getString("DExportKeyPair.jbExport.text"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DExportKeyPair.jbExport.mnemonic").charAt(0));
		jbExport.setToolTipText(res.getString("DExportKeyPair.jbExport.tooltip"));
		jbExport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DExportKeyPair.this);
					exportPressed();
				} finally {
					CursorUtil.setCursorFree(DExportKeyPair.this);
				}
			}
		});

		jbCancel = new JButton(res.getString("DExportKeyPair.jbCancel.text"));
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

		setTitle(MessageFormat.format(res.getString("DExportKeyPair.Title"), entryAlias));
		setResizable(false);

		getRootPane().setDefaultButton(jbExport);

		populateExportFileName();

		pack();
	}

	private void populateExportFileName() {
		File currentDirectory = CurrentDirectory.get();
		String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
		File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.PKCS12_KEYSTORE_EXT_2);
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
	 * Get export password.
	 *
	 * @return Export password
	 */
	public Password getExportPassword() {
		return exportPassword;
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser();

		File currentExportFile = new File(jtfExportFile.getText().trim());

		if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
			chooser.setSelectedFile(currentExportFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DExportKeyPair.ChooseExportFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
		        : chooser.showDialog(this, res.getString("DExportKeyPair.ChooseExportFile.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfExportFile.setText(chosenFile.toString());
			jtfExportFile.setCaretPosition(0);
		}
	}

	private void exportPressed() {
		Password firstPassword;

		if (jpfPassword instanceof JPasswordQualityField) {
			char[] firstPasswordChars = ((JPasswordQualityField) jpfPassword).getPassword();

			if (firstPasswordChars == null) {
				JOptionPane.showMessageDialog(this,
						res.getString("DExportKeyPair.MinimumPasswordQualityNotMet.message"),
						res.getString("DExportKeyPair.Simple.Title"), JOptionPane.WARNING_MESSAGE);
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
			JOptionPane.showMessageDialog(this, res.getString("DExportKeyPair.PasswordsNoMatch.message"),
					res.getString("DExportKeyPair.Simple.Title"), JOptionPane.WARNING_MESSAGE);
			return;
		}

		String exportFileStr = jtfExportFile.getText().trim();

		if (exportFileStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DExportKeyPair.ExportFileRequired.message"),
					res.getString("DExportKeyPair.Simple.Title"), JOptionPane.WARNING_MESSAGE);
			return;
		}

		File exportFile = new File(exportFileStr);

		if (exportFile.isFile()) {
			String message = MessageFormat.format(res.getString("DExportKeyPair.OverWriteExportFile.message"),
					exportFile);

			int selected = JOptionPane.showConfirmDialog(this, message, res.getString("DExportKeyPair.Simple.Title"),
					JOptionPane.YES_NO_OPTION);
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
