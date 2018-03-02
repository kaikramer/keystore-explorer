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
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.jar.JarFile;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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

import org.kse.crypto.signing.MidletSigner;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.io.FileNameUtil;
import org.kse.utilities.io.IOUtils;

/**
 * Dialog that displays the presents MIDlet signing options.
 *
 */
public class DSignMidlet extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/sign/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlInputJad;
	private JTextField jtfInputJad;
	private JButton jbInputJadBrowse;
	private JLabel jlSignDirectly;
	private JCheckBox jcbSignDirectly;
	private JLabel jlOutputJad;
	private JTextField jtfOutputJad;
	private JButton jbOutputJadBrowse;
	private JLabel jlJar;
	private JTextField jtfJar;
	private JButton jbJarBrowse;
	private JPanel jpOptions;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private File inputJadFile;
	private File outputJadFile;
	private File jarFile;

	/**
	 * Creates a new DSignMidlet dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DSignMidlet(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DSignMidlet.Title"));
		initComponents();
	}

	private void initComponents() {
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

		jlInputJad = new JLabel(res.getString("DSignMidlet.jlInputJad.text"));
		GridBagConstraints gbc_jlInputJad = (GridBagConstraints) gbcLbl.clone();
		gbc_jlInputJad.gridy = 0;

		jtfInputJad = new JTextField(30);
		jtfInputJad.setCaretPosition(0);
		jtfInputJad.setToolTipText(res.getString("DSignMidlet.jtfInputJad.tooltip"));
		GridBagConstraints gbc_jtfInputJad = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfInputJad.gridy = 0;

		jbInputJadBrowse = new JButton(res.getString("DSignMidlet.jbInputJadBrowse.text"));
		PlatformUtil.setMnemonic(jbInputJadBrowse, res.getString("DSignMidlet.jbInputJadBrowse.mnemonic").charAt(0));
		jbInputJadBrowse.setToolTipText(res.getString("DSignMidlet.jbInputJadBrowse.tooltip"));
		jbInputJadBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignMidlet.this);
					inputJadBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignMidlet.this);
				}
			}
		});
		GridBagConstraints gbc_jbInputJadBrowse = (GridBagConstraints) gbcBrws.clone();
		gbc_jbInputJadBrowse.gridy = 0;

		jlSignDirectly = new JLabel(res.getString("DSignMidlet.jlSignDirectly.text"));
		GridBagConstraints gbc_jlSignDirectly = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignDirectly.gridy = 1;

		jcbSignDirectly = new JCheckBox();
		jcbSignDirectly.setSelected(true);
		jcbSignDirectly.setToolTipText(res.getString("DSignMidlet.jcbSignDirectly.tooltip"));
		GridBagConstraints gbc_jcbSignDirectly = (GridBagConstraints) gbcCtrl.clone();
		gbc_jcbSignDirectly.gridy = 1;

		jcbSignDirectly.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				jtfOutputJad.setEnabled(!jcbSignDirectly.isSelected());
				jbOutputJadBrowse.setEnabled(!jcbSignDirectly.isSelected());
			}
		});

		jlOutputJad = new JLabel(res.getString("DSignMidlet.jlOutputJad.text"));
		GridBagConstraints gbc_jlOutputJad = (GridBagConstraints) gbcLbl.clone();
		gbc_jlOutputJad.gridy = 2;

		jtfOutputJad = new JTextField(30);
		jtfOutputJad.setEnabled(false);
		jtfOutputJad.setCaretPosition(0);
		jtfOutputJad.setToolTipText(res.getString("DSignMidlet.jtfOutputJad.tooltip"));
		GridBagConstraints gbc_jtfOutputJad = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfOutputJad.gridy = 2;

		jbOutputJadBrowse = new JButton(res.getString("DSignMidlet.jbOutputJadBrowse.text"));
		PlatformUtil.setMnemonic(jbOutputJadBrowse, res.getString("DSignMidlet.jbOutputJadBrowse.mnemonic").charAt(0));
		jbOutputJadBrowse.setToolTipText(res.getString("DSignMidlet.jbOutputJadBrowse.tooltip"));
		jbOutputJadBrowse.setEnabled(false);
		jbOutputJadBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignMidlet.this);
					outputJadBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignMidlet.this);
				}
			}
		});
		GridBagConstraints gbc_jbOutputJadBrowse = (GridBagConstraints) gbcBrws.clone();
		gbc_jbOutputJadBrowse.gridy = 2;

		jlJar = new JLabel(res.getString("DSignMidlet.jlJar.text"));
		GridBagConstraints gbc_jlJar = (GridBagConstraints) gbcLbl.clone();
		gbc_jlJar.gridy = 3;

		jtfJar = new JTextField(30);
		jtfJar.setCaretPosition(0);
		jtfJar.setToolTipText(res.getString("DSignMidlet.jtfJar.tooltip"));
		GridBagConstraints gbc_jtfJar = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfJar.gridy = 3;

		jbJarBrowse = new JButton(res.getString("DSignMidlet.jbJarBrowse.text"));
		PlatformUtil.setMnemonic(jbJarBrowse, res.getString("DSignMidlet.jbJarBrowse.mnemonic").charAt(0));
		jbJarBrowse.setToolTipText(res.getString("DSignMidlet.jbJarBrowse.tooltip"));
		jbJarBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSignMidlet.this);
					jarBrowsePressed();
				} finally {
					CursorUtil.setCursorFree(DSignMidlet.this);
				}
			}
		});
		GridBagConstraints gbc_jbJarBrowse = (GridBagConstraints) gbcBrws.clone();
		gbc_jbJarBrowse.gridy = 3;

		jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpOptions.add(jlInputJad, gbc_jlInputJad);
		jpOptions.add(jtfInputJad, gbc_jtfInputJad);
		jpOptions.add(jbInputJadBrowse, gbc_jbInputJadBrowse);
		jpOptions.add(jlSignDirectly, gbc_jlSignDirectly);
		jpOptions.add(jcbSignDirectly, gbc_jcbSignDirectly);
		jpOptions.add(jlOutputJad, gbc_jlOutputJad);
		jpOptions.add(jtfOutputJad, gbc_jtfOutputJad);
		jpOptions.add(jbOutputJadBrowse, gbc_jbOutputJadBrowse);
		jpOptions.add(jlJar, gbc_jlJar);
		jpOptions.add(jtfJar, gbc_jtfJar);
		jpOptions.add(jbJarBrowse, gbc_jbJarBrowse);

		jbOK = new JButton(res.getString("DSignMidlet.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DSignMidlet.jbCancel.text"));
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

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpOptions, BorderLayout.NORTH);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

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

	/**
	 * Get chosen input MIDlet JAD file.
	 *
	 * @return Input MIDlet JAD file
	 */
	public File getInputJad() {
		return inputJadFile;
	}

	/**
	 * Get chosen output MIDlet JAD file.
	 *
	 * @return Output MIDlet JAD file
	 */
	public File getOutputJad() {
		return outputJadFile;
	}

	/**
	 * Get chosen MIDlet JAR file.
	 *
	 * @return MIDlet JAR file
	 */
	public File getJar() {
		return jarFile;
	}

	private void okPressed() {
		String inputJad = jtfInputJad.getText().trim();

		if (inputJad.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignMidlet.InputJadRequired.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		File inputJadFile = new File(inputJad);

		if (!inputJadFile.isFile()) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DSignMidlet.InputJadNotFile.message"), inputJadFile),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		try {
			MidletSigner.readJadFile(inputJadFile);
		} catch (IOException ex) {
			String problemStr = MessageFormat.format(res.getString("DSignMidlet.NoOpenJad.Problem"),
					inputJadFile.getName());

			String[] causes = new String[] { res.getString("DSignMidlet.NotJad.Cause"),
					res.getString("DSignMidlet.CorruptedJad.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(this, res.getString("DSignMidlet.ProblemOpeningJad.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return;
		}

		boolean signDirectly = jcbSignDirectly.isSelected();

		File outputJadFile;
		if (signDirectly) {
			outputJadFile = inputJadFile;
		} else {
			String outputJad = jtfOutputJad.getText().trim();

			if (outputJad.length() == 0) {
				JOptionPane.showMessageDialog(this, res.getString("DSignMidlet.OutputJadRequired.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			outputJadFile = new File(outputJad);
		}

		String jar = jtfJar.getText().trim();

		if (jar.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignMidlet.JarRequired.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		File jarFile = new File(jar);

		if (!jarFile.isFile()) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("DSignMidlet.JarNotFile.message"), jarFile), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		JarFile jarFileTest = null;
		try {
			jarFileTest = new JarFile(jarFile);
		} catch (IOException ex) {
			String problemStr = MessageFormat.format(res.getString("DSignMidlet.NoOpenJar.Problem"), jarFile.getName());

			String[] causes = new String[] { res.getString("DSignMidlet.NotJar.Cause"),
					res.getString("DSignMidlet.CorruptedJar.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(this, res.getString("DSignMidlet.ProblemOpeningJar.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return;
		} finally {
			IOUtils.closeQuietly(jarFileTest);
		}

		if (!signDirectly) {
			if (outputJadFile.isFile()) {
				String message = MessageFormat.format(res.getString("DSignMidlet.OverWriteOutputJadFile.message"),
						outputJadFile);

				int selected = JOptionPane.showConfirmDialog(this, message, getTitle(), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}
		}

		this.inputJadFile = inputJadFile;
		this.outputJadFile = outputJadFile;
		this.jarFile = jarFile;

		closeDialog();
	}

	private void inputJadBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getJadFileChooser();

		File currentFile = new File(jtfInputJad.getText());

		if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
			chooser.setSelectedFile(currentFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignMidlet.ChooseInputJad.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DSignMidlet.InputJadChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfInputJad.setText(chosenFile.toString());
			jtfInputJad.setCaretPosition(0);
			populateOutputJadFileName(chosenFile);
		}
	}

	private void populateOutputJadFileName(File chosenFile) {
		String fileBaseName = FileNameUtil.removeExtension(chosenFile.getName());
		if (fileBaseName != null) {
			String outFileName = fileBaseName + "_signed.jad";
			File outFile = new File(chosenFile.getParentFile(), outFileName);
			jtfOutputJad.setText(outFile.getPath());
		}
	}

	private void outputJadBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getJadFileChooser();

		File currentFile = new File(jtfOutputJad.getText());

		if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
			chooser.setSelectedFile(currentFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignMidlet.ChooseOutputJad.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
				: chooser.showDialog(this, res.getString("DSignMidlet.OutputJadChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfOutputJad.setText(chosenFile.toString());
			jtfOutputJad.setCaretPosition(0);
		}
	}

	private void jarBrowsePressed() {
		JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();

		File currentFile = new File(jtfJar.getText());

		if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
			chooser.setCurrentDirectory(currentFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DSignMidlet.ChooseJar.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DSignMidlet.JarChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfJar.setText(chosenFile.toString());
			jtfJar.setCaretPosition(0);
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
