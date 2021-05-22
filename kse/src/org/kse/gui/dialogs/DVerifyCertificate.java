package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.OpenAction;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.history.KeyStoreHistory;

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

	private JComboBox<KeyStoreHistory> jcbKeyStore;
	private JButton jbLoadKeystore;
	
	private boolean verifySelected = false;
	private VerifyOptions verifyOption = VerifyOptions.CRL;
	
	private KseFrame kseFrame;

	public DVerifyCertificate(JFrame parent, String certificateAlias, KseFrame kseFrame) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.certificateAlias = certificateAlias;
		this.kseFrame = kseFrame;
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

		jcbKeyStore = new JComboBox<>(getKeystoreNames());
		jcbKeyStore.setToolTipText(res.getString("DExamineSsl.jcbKeyStore.tooltip"));
		jcbKeyStore.setPreferredSize(new Dimension(200,20));
		jcbKeyStore.setEnabled(false);
		
		jbLoadKeystore = new JButton();
		jbLoadKeystore.setIcon(new ImageIcon(getClass().getResource("images/open.png")));
		jbLoadKeystore.setToolTipText(res.getString("DExamineSsl.jbLoadKeystore.tooltip"));		
		jbLoadKeystore.setEnabled(false);

		pane.add(new JLabel(res.getString("DExamineSsl.jlKeyStore.text")), "");
		pane.add(jcbKeyStore, "split 2");
		pane.add(jbLoadKeystore, "wrap");

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

		jbLoadKeystore.addActionListener(evt -> {
			OpenAction openAction = new OpenAction(kseFrame);
			openAction.actionPerformed(evt);
			updateVerifyControls();
			pack();
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

		jcbKeyStore.setModel(getKeystoreNames());		
		if (jrbCrlCheck.isSelected() || jrbOcspCheck.isSelected()) {
			jcbKeyStore.setEnabled(false);
			jbLoadKeystore.setEnabled(false);
		} else {
			jcbKeyStore.setEnabled(true);
			jbLoadKeystore.setEnabled(true);
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
			if (getKeyStore() == null) {
				JOptionPane.showMessageDialog(this, res.getString("DVerifyCertificate.ChooseCACertificatesKeyStore.Title"),
						res.getString("DVerifyCertificate.ChooseCACertificatesKeyStore.Title"),
						JOptionPane.INFORMATION_MESSAGE);
				return;
			}
			verifyOption = VerifyOptions.CHAIN;
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
		}
	}

	public KeyStoreHistory getKeyStore() {
		return (KeyStoreHistory) jcbKeyStore.getSelectedItem();
	}

	private ComboBoxModel<KeyStoreHistory> getKeystoreNames() {
		KeyStoreHistory[] keyStoreHistories;
		if (kseFrame == null) {
			keyStoreHistories = new KeyStoreHistory[0]; 
		}
		else {
			keyStoreHistories = kseFrame.getKeyStoreHistories();	
		}
		
		return new DefaultComboBoxModel<>(keyStoreHistories);
	}
	
	public static void main(String[] args) throws Exception {
		DialogViewer.run(new DVerifyCertificate(new javax.swing.JFrame(), "Verify Certificate", null));
	}
}
