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
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.io.FileNameUtil;

/**
 * Dialog used to display options to export certificate(s) from a KeyStore
 * entry.
 *
 */
public class DExportCertificates extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpOptions;
	private JLabel jlExportLength;
	private JRadioButton jrbExportHead;
	private JRadioButton jrbExportChain;
	private JLabel jlExportFormat;
	private JRadioButton jrbExportX509;
	private JRadioButton jrbExportPkcs7;
	private JRadioButton jrbExportPkiPath;
	private JRadioButton jrbExportSpc;
	private JLabel jlExportPem;
	private JCheckBox jcbExportPem;
	private JLabel jlExportFile;
	private JTextField jtfExportFile;
	private JButton jbBrowse;
	private JPanel jpButtons;
	private JButton jbExport;
	private JButton jbCancel;

	private String entryAlias;
	private boolean chain;
	private boolean exportSelected = false;
	private File exportFile;
	private boolean exportChain;
	private boolean formatX509;
	private boolean formatPkcs7;
	private boolean formatPkiPath;
	private boolean formatSpc;
	private boolean pemEncode;

	/**
	 * Creates a new DExportCertificate dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param entryAlias
	 *            The KeyStore entry to export certificate(s) from
	 * @param chain
	 *            Exporting a chain?
	 */
	public DExportCertificates(JFrame parent, String entryAlias, boolean chain) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.entryAlias = entryAlias;
		this.chain = chain;
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

		jlExportLength = new JLabel(res.getString("DExportCertificates.jlExportLength.text"));
		GridBagConstraints gbc_jlExportLength = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportLength.gridy = 0;

		jrbExportHead = new JRadioButton(res.getString("DExportCertificates.jrbExportHead.text"));
		jrbExportHead.setToolTipText(res.getString("DExportCertificates.jrbExportHead.tooltip"));
		PlatformUtil.setMnemonic(jrbExportHead, res.getString("DExportCertificates.jrbExportHead.mnemonic").charAt(0));
		GridBagConstraints gbc_jrbExportHead = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jrbExportHead.gridy = 0;

		jrbExportChain = new JRadioButton(res.getString("DExportCertificates.jrbExportChain.text"));
		jrbExportChain.setToolTipText(res.getString("DExportCertificates.jrbExportChain.tooltip"));
		PlatformUtil
		.setMnemonic(jrbExportChain, res.getString("DExportCertificates.jrbExportChain.mnemonic").charAt(0));
		GridBagConstraints gbc_jrbExportChain = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jrbExportChain.gridy = 0;
		gbc_jrbExportChain.gridx = 6;

		ButtonGroup bgExportLength = new ButtonGroup();
		bgExportLength.add(jrbExportHead);
		bgExportLength.add(jrbExportChain);
		jrbExportHead.setSelected(true);

		jlExportFormat = new JLabel(res.getString("DExportCertificates.jlExportFormat.text"));
		GridBagConstraints gbc_jlExportFormat = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportFormat.gridy = 1;

		jrbExportX509 = new JRadioButton(res.getString("DExportCertificates.jrbExportX509.text"));
		jrbExportX509.setToolTipText(res.getString("DExportCertificates.jrbExportX509.tooltip"));
		PlatformUtil.setMnemonic(jrbExportX509, res.getString("DExportCertificates.jrbExportX509.mnemonic").charAt(0));
		GridBagConstraints gbc_jrbExportX509 = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jrbExportX509.gridy = 1;

		jrbExportPkcs7 = new JRadioButton(res.getString("DExportCertificates.jrbExportPkcs7.text"));
		jrbExportPkcs7.setToolTipText(res.getString("DExportCertificates.jrbExportPkcs7.tooltip"));
		PlatformUtil
		.setMnemonic(jrbExportPkcs7, res.getString("DExportCertificates.jrbExportPkcs7.mnemonic").charAt(0));
		GridBagConstraints gbc_jrbExportPkcs7 = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jrbExportPkcs7.gridy = 1;
		gbc_jrbExportPkcs7.gridx = 6;

		jrbExportPkiPath = new JRadioButton(res.getString("DExportCertificates.jrbExportPkiPath.text"));
		jrbExportPkiPath.setToolTipText(res.getString("DExportCertificates.jrbExportPkiPath.tooltip"));
		PlatformUtil.setMnemonic(jrbExportPkiPath, res.getString("DExportCertificates.jrbExportPkiPath.mnemonic")
				.charAt(0));
		GridBagConstraints gbc_jrbExportPkiPath = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jrbExportPkiPath.gridy = 1;
		gbc_jrbExportPkiPath.gridx = 9;

		jrbExportSpc = new JRadioButton(res.getString("DExportCertificates.jrbExportSpc.text"));
		jrbExportSpc.setToolTipText(res.getString("DExportCertificates.jrbExportSpc.tooltip"));
		PlatformUtil.setMnemonic(jrbExportSpc, res.getString("DExportCertificates.jrbExportSpc.mnemonic").charAt(0));
		GridBagConstraints gbc_jrbExportSpc = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jrbExportSpc.gridy = 1;
		gbc_jrbExportSpc.gridx = 12;

		ButtonGroup bgExportFormat = new ButtonGroup();
		bgExportFormat.add(jrbExportX509);
		bgExportFormat.add(jrbExportPkcs7);
		bgExportFormat.add(jrbExportPkiPath);
		bgExportFormat.add(jrbExportSpc);
		jrbExportX509.setSelected(true);

		jlExportPem = new JLabel(res.getString("DExportCertificates.jlExportPem.text"));
		GridBagConstraints gbc_jlExportPem = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportPem.gridy = 2;

		jcbExportPem = new JCheckBox();
		jcbExportPem.setSelected(true);
		jcbExportPem.setToolTipText(res.getString("DExportCertificates.jcbExportPem.tooltip"));
		GridBagConstraints gbc_jcbExportPem = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbExportPem.gridy = 2;

		jlExportFile = new JLabel(res.getString("DExportCertificates.jlExportFile.text"));
		GridBagConstraints gbc_jlExportFile = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportFile.gridy = 3;

		jtfExportFile = new JTextField(30);
		jtfExportFile.setToolTipText(res.getString("DExportCertificates.jtfExportFile.tooltip"));
		GridBagConstraints gbc_jtfExportFile = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfExportFile.gridy = 3;
		gbc_jtfExportFile.gridwidth = 12;
		gbc_jtfExportFile.fill = GridBagConstraints.HORIZONTAL;

		jbBrowse = new JButton(res.getString("DExportCertificates.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DExportCertificates.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportCertificates.jbBrowse.mnemonic").charAt(0));
		GridBagConstraints gbc_jbBrowse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbBrowse.gridy = 3;
		gbc_jbBrowse.gridx = 15;

		jbBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DExportCertificates.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DExportCertificates.this);
				}
			}
		});

		jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()),
				new EmptyBorder(5, 5, 5, 5)));

		if (chain) {
			jpOptions.add(jlExportLength, gbc_jlExportLength);
			jpOptions.add(jrbExportHead, gbc_jrbExportHead);
			jpOptions.add(jrbExportChain, gbc_jrbExportChain);
		} else {
			gbc_jlExportFormat.gridy = gbc_jlExportFormat.gridy - 1;
			gbc_jrbExportX509.gridy = gbc_jrbExportX509.gridy - 1;
			gbc_jrbExportPkcs7.gridy = gbc_jrbExportPkcs7.gridy - 1;
			gbc_jrbExportPkiPath.gridy = gbc_jrbExportPkiPath.gridy - 1;
			gbc_jrbExportSpc.gridy = gbc_jrbExportSpc.gridy - 1;
			gbc_jlExportPem.gridy = gbc_jlExportPem.gridy - 1;
			gbc_jcbExportPem.gridy = gbc_jcbExportPem.gridy - 1;
			gbc_jlExportFile.gridy = gbc_jlExportFile.gridy - 1;
			gbc_jtfExportFile.gridy = gbc_jtfExportFile.gridy - 1;
			gbc_jbBrowse.gridy = gbc_jbBrowse.gridy - 1;
		}

		jpOptions.add(jlExportFormat, gbc_jlExportFormat);
		jpOptions.add(jrbExportX509, gbc_jrbExportX509);
		jpOptions.add(jrbExportPkcs7, gbc_jrbExportPkcs7);
		jpOptions.add(jrbExportPkiPath, gbc_jrbExportPkiPath);
		jpOptions.add(jrbExportSpc, gbc_jrbExportSpc);

		jpOptions.add(jlExportPem, gbc_jlExportPem);
		jpOptions.add(jcbExportPem, gbc_jcbExportPem);

		jpOptions.add(jlExportFile, gbc_jlExportFile);
		jpOptions.add(jtfExportFile, gbc_jtfExportFile);
		jpOptions.add(jbBrowse, gbc_jbBrowse);

		jrbExportChain.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbExportChain.isSelected() && jrbExportX509.isSelected()) {
					jcbExportPem.setEnabled(false);
					jcbExportPem.setSelected(true);
				} else {
					jcbExportPem.setEnabled(true);
				}
			}
		});

		jrbExportX509.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbExportX509.isSelected()) {
					updateFileExtension(FileChooserFactory.X509_EXT_1);

					if (jrbExportChain.isSelected()) {
						jcbExportPem.setEnabled(false);
						jcbExportPem.setSelected(true);
					} else {
						jcbExportPem.setEnabled(true);
					}
				}
			}
		});

		jrbExportPkcs7.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbExportPkcs7.isSelected()) {
					jcbExportPem.setEnabled(true);
					updateFileExtension(FileChooserFactory.PKCS7_EXT_1);
				}
			}
		});

		jrbExportSpc.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbExportSpc.isSelected()) {
					jcbExportPem.setEnabled(false);
					jcbExportPem.setSelected(false);
					updateFileExtension(FileChooserFactory.SPC_EXT);
				} else {
					jcbExportPem.setEnabled(true);
				}
			}
		});

		jrbExportPkiPath.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				if (jrbExportPkiPath.isSelected()) {
					jcbExportPem.setEnabled(false);
					jcbExportPem.setSelected(false);
					updateFileExtension(FileChooserFactory.PKI_PATH_EXT);
				} else {
					jcbExportPem.setEnabled(true);
				}
			}
		});

		jbExport = new JButton(res.getString("DExportCertificates.jbExport.text"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DExportCertificates.jbExport.mnemonic").charAt(0));
		jbExport.setToolTipText(res.getString("DExportCertificates.jbExport.tooltip"));
		jbExport.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DExportCertificates.this);
					exportPressed();
				} finally {
					CursorUtil.setCursorFree(DExportCertificates.this);
				}
			}
		});

		jbCancel = new JButton(res.getString("DExportCertificates.jbCancel.text"));
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

		if (chain) {
			setTitle(MessageFormat.format(res.getString("DExportCertificates.CertificateChain.Title"), entryAlias));
		} else {
			setTitle(MessageFormat.format(res.getString("DExportCertificates.Certificate.Title"), entryAlias));
		}

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
		File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.X509_EXT_1);
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
	 * Export head certificate only? Only applicable for key pair entries.
	 *
	 * @return True if it is
	 */
	public boolean exportHead() {
		return !exportChain;
	}

	/**
	 * Export entire certificate chain? Only applicable for key pair entries.
	 *
	 * @return True if it is
	 */
	public boolean exportChain() {
		return exportChain;
	}

	/**
	 * Was chosen export format X.509?
	 *
	 * @return True if it was
	 */
	public boolean exportFormatX509() {
		return formatX509;
	}

	/**
	 * Was chosen export format PKCS #7?
	 *
	 * @return True if it was
	 */
	public boolean exportFormatPkcs7() {
		return formatPkcs7;
	}

	/**
	 * Was chosen export format PKI Path?
	 *
	 * @return True if it was
	 */
	public boolean exportFormatPkiPath() {
		return formatPkiPath;
	}

	/**
	 * Was chosen export format SPC?
	 *
	 * @return True if it was
	 */
	public boolean exportFormatSpc() {
		return formatSpc;
	}

	/**
	 * Was the option to PEM encode selected?
	 *
	 * @return True if it was
	 */
	public boolean pemEncode() {
		return pemEncode;
	}

	private void browsePressed() {
		JFileChooser chooser = null;

		if (jrbExportX509.isSelected()) {
			chooser = FileChooserFactory.getX509FileChooser();
		} else if (jrbExportPkcs7.isSelected()) {
			chooser = FileChooserFactory.getPkcs7FileChooser();
		} else if (jrbExportPkiPath.isSelected()) {
			chooser = FileChooserFactory.getPkiPathFileChooser();
		} else {
			chooser = FileChooserFactory.getSpcFileChooser();
		}

		File currentExportFile = new File(jtfExportFile.getText().trim());

		if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
			chooser.setSelectedFile(currentExportFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DExportCertificates.ChooseExportFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
				: chooser.showDialog(this, res.getString("DExportCertificates.ChooseExportFile.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfExportFile.setText(chosenFile.toString());
			jtfExportFile.setCaretPosition(0);
		}
	}

	private void exportPressed() {
		String simpleTitle = res.getString("DExportCertificates.Certificate.Simple.Title");

		if (chain) {
			simpleTitle = res.getString("DExportCertificates.CertificateChain.Simple.Title");
		}

		String exportFileStr = jtfExportFile.getText().trim();

		if (exportFileStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DExportCertificates.ExportFileRequired.message"),
					simpleTitle, JOptionPane.WARNING_MESSAGE);
			return;
		}

		File exportFile = new File(exportFileStr);

		if (exportFile.isFile()) {
			String message = MessageFormat.format(res.getString("DExportCertificates.OverWriteExportFile.message"),
					exportFile);

			int selected = JOptionPane.showConfirmDialog(this, message, simpleTitle, JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return;
			}
		}

		this.exportFile = exportFile;

		exportChain = jrbExportChain.isSelected();
		formatX509 = jrbExportX509.isSelected();
		formatPkcs7 = jrbExportPkcs7.isSelected();
		formatPkiPath = jrbExportPkiPath.isSelected();
		formatSpc = jrbExportSpc.isSelected();
		pemEncode = jcbExportPem.isSelected();

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
		Security.addProvider(new BouncyCastleProvider());
		javax.swing.UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		java.awt.EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					DExportCertificates dialog = new DExportCertificates(new javax.swing.JFrame(), "alias (test)", true);
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
