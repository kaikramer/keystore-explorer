package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
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
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import net.miginfocom.swing.MigLayout;

public class DVerifyCertificate extends JEscDialog {

	private static final long serialVersionUID = 1L;

	public enum VerifyOptions {
		CRL, OCSP, CHAIN
	}

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private String certificateAlias;

	private JLabel jlFormat;
	private JRadioButton jrbCrlCheck;
	private JRadioButton jrbOcspCheck;
	private JRadioButton jrbChainCheck;
	private JPanel jpButtons;
	private JButton jbOk;
	private JButton jbCancel;
	private JLabel jlCacertFile;
	private JTextField jtfCaCertificatesFile;
	private JButton jbBrowse;

	private boolean verifySelected = false;
	private VerifyOptions verifyOption = VerifyOptions.CRL;
	private String caCertificateFile = "";
	private String caCertificatesFile;

	public DVerifyCertificate(JFrame parent, String certificateAlias, String caCertificatesFile) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.certificateAlias = certificateAlias;
		this.caCertificatesFile = caCertificatesFile;
		initComponents();
	}

	private void initComponents() {
		jlFormat = new JLabel(res.getString("DVerifyCertificate.jlFormat.text"));

		jrbCrlCheck = new JRadioButton(res.getString("DVerifyCertificate.jrbCrlCheck.text"));
		jrbCrlCheck.setToolTipText(res.getString("DVerifyCertificate.jrbCrlCheck.tooltip"));

		jrbOcspCheck = new JRadioButton(res.getString("DVerifyCertificate.jrbOcspCheck.text"));
		jrbOcspCheck.setToolTipText(res.getString("DVerifyCertificate.jrbOcspCheck.tooltip"));

		jrbChainCheck = new JRadioButton(res.getString("DVerifyCertificate.jrbChainCheck.text"));
		jrbChainCheck.setToolTipText(res.getString("DVerifyCertificate.jrbChainCheck.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbCrlCheck);
		buttonGroup.add(jrbOcspCheck);
		buttonGroup.add(jrbChainCheck);
		jrbCrlCheck.setSelected(true);

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("fill", "[right]unrel[]", "unrel[]unrel[]"));
		pane.add(jlFormat, "");
		pane.add(jrbCrlCheck, "split 3");
		pane.add(jrbOcspCheck, "");
		pane.add(jrbChainCheck, "wrap");

		jlCacertFile = new JLabel(res.getString("DVerifyCertificate.jlCacertFile.text"));
		jtfCaCertificatesFile = new JTextField(caCertificatesFile, 30);
		jtfCaCertificatesFile.setEditable(false);
		jbBrowse = new JButton(res.getString("DVerifyCertificate.jbBrowse.text"));
		jbBrowse.setEnabled(false);
		pane.add(jlCacertFile, "");
		pane.add(jtfCaCertificatesFile, "split 2");
		pane.add(jbBrowse, "wrap");

		jrbCrlCheck.addItemListener(evt -> updateVerifyControls());
		jrbOcspCheck.addItemListener(evt -> updateVerifyControls());
		jrbChainCheck.addItemListener(evt -> updateVerifyControls());

		jbOk = new JButton(res.getString("DVerifyCertificate.jbOk.text"));
		jbCancel = new JButton(res.getString("DVerifyCertificate.jbCancel.text"));

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOk, jbCancel);

		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jpButtons, "right, spanx");

		jbOk.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DVerifyCertificate.this);
				okPressed();
			} finally {
				CursorUtil.setCursorFree(DVerifyCertificate.this);
			}
		});

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

		jbBrowse.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DVerifyCertificate.this);
				browsePressed();
			} finally {
				CursorUtil.setCursorFree(DVerifyCertificate.this);
			}
		});

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});
		setTitle(MessageFormat.format(res.getString("DVerifyCertificate.Title"), certificateAlias));

		setResizable(false);

		pack();
	}

	private void updateVerifyControls() {
		if (jrbCrlCheck.isSelected() || jrbOcspCheck.isSelected()) {
			jtfCaCertificatesFile.setEditable(false);
			jbBrowse.setEnabled(false);
		} else {
			jtfCaCertificatesFile.setEditable(true);
			jbBrowse.setEnabled(true);
		}
	}

	public boolean isVerifySelected() {
		return verifySelected;
	}

	public VerifyOptions getVerifyOption() {
		return verifyOption;
	}

	private void okPressed() {
		if (jrbCrlCheck.isSelected()) {
			verifyOption = VerifyOptions.CRL;
		} else if (jrbOcspCheck.isSelected()) {
			verifyOption = VerifyOptions.OCSP;
		} else {
			verifyOption = VerifyOptions.CHAIN;
			caCertificateFile = jtfCaCertificatesFile.getText();
		}
		verifySelected = true;
		closeDialog();
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
		chooser.setDialogTitle(res.getString("DVerifyCertificate.ChooseCACertificatesKeyStore.Title"));
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText(res.getString("DVerifyCertificate.CaCertificatesKeyStoreFileChooser.button"));

		int rtnValue = chooser.showOpenDialog(this);
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfCaCertificatesFile.setText(chosenFile.toString());
			jtfCaCertificatesFile.setCaretPosition(0);			
		}
	}

	public String getCaCertificateFile() {
		return caCertificateFile;
	}
}
