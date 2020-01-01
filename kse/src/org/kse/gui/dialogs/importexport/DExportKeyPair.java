/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.crypto.Password;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.password.JPasswordQualityField;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export a key pair from a KeyStore entry.
 *
 */
public class DExportKeyPair extends JEscDialog {
	private static final long serialVersionUID = 1L;

	public enum ExportFormat { PKCS12, PEM };

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlFormat;
	private JRadioButton jrbFormatPkcs12;
	private JRadioButton jrbFormatPEM;
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
	private ExportFormat exportFormat = ExportFormat.PKCS12;

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

		jlFormat = new JLabel(res.getString("DExportKeyPair.jlFormat.text"));

		jrbFormatPkcs12 = new JRadioButton(res.getString("DExportKeyPair.jrbFormatPkcs12.text"));
		jrbFormatPkcs12.setToolTipText(res.getString("DExportKeyPair.jrbFormatPkcs12.tooltip"));

		jrbFormatPEM = new JRadioButton(res.getString("DExportKeyPair.jrbFormatPEM.text"));
		jrbFormatPEM.setToolTipText(res.getString("DExportKeyPair.jrbFormatPEM.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbFormatPkcs12);
		buttonGroup.add(jrbFormatPEM);
		jrbFormatPkcs12.setSelected(true);

		jlPassword = new JLabel(res.getString("DExportKeyPair.jlPassword.text"));

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

		jlConfirmPassword = new JLabel(res.getString("DExportKeyPair.jlConfirmPassword.text"));

		jpfConfirmPassword = new JPasswordField(15);
		jpfConfirmPassword.setToolTipText(res.getString("DExportKeyPair.jpfConfirmPassword.tooltip"));

		jlExportFile = new JLabel(res.getString("DExportKeyPair.jlExportFile.text"));

		jtfExportFile = new JTextField(30);
		jtfExportFile.setToolTipText(res.getString("DExportKeyPair.jtfExportFile.tooltip"));

		jbBrowse = new JButton(res.getString("DExportKeyPair.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DExportKeyPair.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportKeyPair.jbBrowse.mnemonic").charAt(0));

		jbExport = new JButton(res.getString("DExportKeyPair.jbExport.text"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DExportKeyPair.jbExport.mnemonic").charAt(0));
		jbExport.setToolTipText(res.getString("DExportKeyPair.jbExport.tooltip"));

		jbCancel = new JButton(res.getString("DExportKeyPair.jbCancel.text"));

		jpButtons = PlatformUtil.createDialogButtonPanel(jbExport, jbCancel);

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("fill", "[right]unrel[]", "unrel[]unrel[]"));
		pane.add(jlFormat, "");
		pane.add(jrbFormatPkcs12, "split 2");
		pane.add(jrbFormatPEM, "wrap");
		pane.add(jlPassword, "");
		pane.add(jpfPassword, "wrap");
		pane.add(jlConfirmPassword, "");
		pane.add(jpfConfirmPassword, "wrap");
		pane.add(jlExportFile, "");
		pane.add(jtfExportFile, "");
		pane.add(jbBrowse, "wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jpButtons, "right, spanx");

		jrbFormatPkcs12.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbFormatPkcs12.isSelected()) {
					updateFileExtension(FileChooserFactory.PKCS12_KEYSTORE_EXT_2);
				}
			}
		});

		jrbFormatPEM.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbFormatPEM.isSelected()) {
					updateFileExtension(FileChooserFactory.PEM_EXT);
				}
			}
		});

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

		setTitle(MessageFormat.format(res.getString("DExportKeyPair.Title"), entryAlias));
		setResizable(false);

		getRootPane().setDefaultButton(jbExport);

		populateExportFileName();

		pack();
	}

	private void updateFileExtension(String newExt) {
		String currentFileName = jtfExportFile.getText();
		String newFileName = FileNameUtil.removeExtension(currentFileName) + "." + newExt;
		jtfExportFile.setText(newFileName);
	}

	private void populateExportFileName() {
		File currentDirectory = CurrentDirectory.get();
		String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
		File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.PKCS12_KEYSTORE_EXT_2);
		jtfExportFile.setText(csrFile.getPath());
	}

	public ExportFormat getExportFormat() {
		return exportFormat;
	}

	/**
	 * Has the user chosen to export?
	 *
	 * @return True if they have
	 */
	public boolean isExportSelected() {
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

		if (jrbFormatPkcs12.isSelected()) {
			exportFormat = ExportFormat.PKCS12;
		} else {
			exportFormat = ExportFormat.PEM;
		}

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

	// for quick testing
	public static void main(String[] args) throws Exception {
		PasswordQualityConfig pwdQualityConf = new PasswordQualityConfig(false, false, 0);
		DExportKeyPair dialog = new DExportKeyPair(new javax.swing.JFrame(), "alias (test)", pwdQualityConf);
		DialogViewer.run(dialog);
	}
}
