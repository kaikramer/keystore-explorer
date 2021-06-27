package org.kse.gui.dialogs.importexport;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.text.MessageFormat;
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
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

/**
 * Dialog used to display options to export a CRL file.
 *
 */
public class DExportCrl extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpOptions;
	private JLabel jlExportPem;
	private JCheckBox jcbExportPem;
	private JLabel jlExportFile;
	private JTextField jtfExportFile;
	private JButton jbBrowse;
	private JPanel jpButtons;
	private JButton jbExport;
	private JButton jbCancel;

	private String entryAlias;
	private boolean exportSelected = false;
	private File exportFile;
	private boolean pemEncode;

	/**
	 * Creates a new DExportCrl dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param entryAlias
	 *            The entry alias
	 */
	public DExportCrl(JFrame parent, String entryAlias) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.entryAlias = entryAlias;
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

		jlExportPem = new JLabel(res.getString("DExportCrl.jlExportPem.text"));
		GridBagConstraints gbc_jlExportPem = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportPem.gridy = 4;

		jcbExportPem = new JCheckBox();
		jcbExportPem.setSelected(false);
		jcbExportPem.setToolTipText(res.getString("DExportCrl.jcbExportPem.tooltip"));
		GridBagConstraints gbc_jcbExportPem = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbExportPem.gridy = 4;

		jlExportFile = new JLabel(res.getString("DExportCrl.jlExportFile.text"));
		GridBagConstraints gbc_jlExportFile = (GridBagConstraints) gbcLbl.clone();
		gbc_jlExportFile.gridy = 5;

		jtfExportFile = new JTextField(30);
		jtfExportFile.setToolTipText(res.getString("DExportCrl.jtfExportFile.tooltip"));
		GridBagConstraints gbc_jtfExportFile = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfExportFile.gridy = 5;
		gbc_jtfExportFile.gridwidth = 6;

		jbBrowse = new JButton(res.getString("DExportCrl.jbBrowse.text"));
		jbBrowse.setToolTipText(res.getString("DExportCrl.jbBrowse.tooltip"));
		PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportCrl.jbBrowse.mnemonic").charAt(0));
		GridBagConstraints gbc_jbBrowse = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jbBrowse.gridy = 5;
		gbc_jbBrowse.gridx = 9;

		jbBrowse.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DExportCrl.this);
				browsePressed();
			} finally {
				CursorUtil.setCursorFree(DExportCrl.this);
			}
		});

		jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()),
				new EmptyBorder(5, 5, 5, 5)));

		jpOptions.add(jlExportPem, gbc_jlExportPem);
		jpOptions.add(jcbExportPem, gbc_jcbExportPem);

		jpOptions.add(jlExportFile, gbc_jlExportFile);
		jpOptions.add(jtfExportFile, gbc_jtfExportFile);
		jpOptions.add(jbBrowse, gbc_jbBrowse);

		jbExport = new JButton(res.getString("DExportCrl.jbExport.text"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DExportCrl.jbExport.mnemonic").charAt(0));
		jbExport.setToolTipText(res.getString("DExportCrl.jbExport.tooltip"));
		jbExport.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DExportCrl.this);
				exportPressed();
			} finally {
				CursorUtil.setCursorFree(DExportCrl.this);
			}
		});

		jbCancel = new JButton(res.getString("DExportCrl.jbCancel.text"));
		jbCancel.addActionListener(evt -> cancelPressed());
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbExport, jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpOptions, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setTitle(MessageFormat.format(res.getString("DExportCrl.Title"), entryAlias));
		setResizable(false);

		getRootPane().setDefaultButton(jbExport);

		populateExportFileName();

		pack();
	}

	private void populateExportFileName() {
		File currentDirectory = CurrentDirectory.get();
		String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
		File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.CRL_EXT);
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
	 * Was the option to PEM encode selected?
	 *
	 * @return True if it was
	 */
	public boolean pemEncode() {
		return pemEncode;
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getPublicKeyFileChooser();

		File currentExportFile = new File(jtfExportFile.getText().trim());

		if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentExportFile.getParentFile());
			chooser.setSelectedFile(currentExportFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DExportCrl.ChooseExportFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
				: chooser.showDialog(this, res.getString("DExportCrl.ChooseExportFile.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfExportFile.setText(chosenFile.toString());
			jtfExportFile.setCaretPosition(0);
		}
	}

	private void exportPressed() {
		pemEncode = jcbExportPem.isSelected();

		String exportFileStr = jtfExportFile.getText().trim();

		if (exportFileStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DExportCrl.ExportFileRequired.message"),
					res.getString("DExportCrl.Simple.Title"), JOptionPane.WARNING_MESSAGE);
			return;
		}

		File exportFile = new File(exportFileStr);

		if (exportFile.isFile()) {
			String message = MessageFormat.format(res.getString("DExportCrl.OverWriteExportFile.message"),
					exportFile);

			int selected = JOptionPane.showConfirmDialog(this, message,
					res.getString("DExportCrl.Simple.Title"), JOptionPane.YES_NO_OPTION);
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
	
	public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException {
		DialogViewer.run(new DExportCrl(new JFrame(), "test alias"));
	}
}
