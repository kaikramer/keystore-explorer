package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ResourceBundle;

import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.OpenAction;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.history.KeyStoreHistory;

import net.miginfocom.swing.MigLayout;

public class DListCertificatesKS extends JEscDialog {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JFrame parent;
	private KseFrame kseFrame;
	
	private JLabel jlKeyStore;
	private JComboBox<KeyStoreHistory> jcbKeyStore;
	private JButton jbLoadKeystore;
	private JListCertificates jListCertificates;
	private JButton jbOK;
	private JButton jbCancel;
	
	private X509Certificate cert;

	public DListCertificatesKS(JFrame parent, KseFrame kseFrame) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DListCertificatesKS.Title"));
		this.kseFrame = kseFrame;
		this.cert = null;
		initComponents();
	}

	private void initComponents() {

		jlKeyStore = new JLabel(res.getString("DListCertificatesKS.jlKeyStore.text"));
		jcbKeyStore = new JComboBox<>(getKeystoreNames());
		jcbKeyStore.setToolTipText(res.getString("DListCertificatesKS.jcbKeyStore.tooltip"));
		jcbKeyStore.setPreferredSize(new Dimension(200, 20));

		jbLoadKeystore = new JButton();
		jbLoadKeystore.setIcon(new ImageIcon(getClass().getResource("images/open.png")));
		jbLoadKeystore.setToolTipText(res.getString("DListCertificatesKS.jbLoadKeystore.tooltip"));

		jListCertificates = new JListCertificates(parent, kseFrame);

		jbOK = new JButton(res.getString("DListCertificatesKS.jbOK.text"));
		jbCancel = new JButton(res.getString("DListCertificatesKS.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("fill", "[right]unrel[]", "[]unrel[]"));

		pane.add(jlKeyStore);
		pane.add(jcbKeyStore);
		pane.add(jbLoadKeystore, "wrap");
		pane.add(jListCertificates, "spanx, growx, wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jpButtons, "right, spanx");

		jcbKeyStore.addActionListener(evt -> {
			updateCertificateControls();
		});

		jbLoadKeystore.addActionListener(evt -> {
			OpenAction openAction = new OpenAction(kseFrame);
			openAction.actionPerformed(evt);
			populate();
			pack();
		});

		jbOK.addActionListener(evt -> okPressed());
		jbCancel.addActionListener(evt -> cancelPressed());

		populate();

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate() {
		jcbKeyStore.setModel(getKeystoreNames());
		updateCertificateControls();
	}

	private void updateCertificateControls() {

		try {
			jListCertificates.load((KeyStoreHistory) jcbKeyStore.getSelectedItem());
		} catch (KeyStoreException e) {
			// ignore
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private void okPressed() {
		X509Certificate selCert = jListCertificates.getCertSelected();
		if (selCert == null) {
			JOptionPane.showMessageDialog(this, res.getString("DListCertificatesKS.SelectCertificate.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}
		cert = selCert;
		closeDialog();
	}

	public X509Certificate getCertificate() {
		return cert;
	}
	
	private ComboBoxModel<KeyStoreHistory> getKeystoreNames() {
		KeyStoreHistory[] keyStoreHistories;
		if (kseFrame == null) {
			keyStoreHistories = new KeyStoreHistory[0];
		} else {
			keyStoreHistories = kseFrame.getKeyStoreHistories();
		}

		return new DefaultComboBoxModel<>(keyStoreHistories);
	}

	public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException {
		DialogViewer.run(new DListCertificatesKS(new JFrame(), null));
	}
}
