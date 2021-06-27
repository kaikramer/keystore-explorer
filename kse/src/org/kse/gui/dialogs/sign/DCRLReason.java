package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.bouncycastle.asn1.x509.CRLReason;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.datetime.JDateTime;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that specifies the reason that a certificate is revoked
 *
 */
public class DCRLReason extends JEscDialog {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlSubject;
	private JDistinguishedName jdnSubject;
	private JLabel jlRevocationDate;
	private JDateTime jdtRevocationDate;
	private JLabel jlReason;
	private JRadioButton jrbUnspecified;
	private JRadioButton jrbKeyCompromise;
	private JRadioButton jrbCACompromise;
	private JRadioButton jrbAffiliationChanged;
	private JRadioButton jrbSuperseded;
	private JRadioButton jrbCessationOfOperation;
	private JRadioButton jrbCertificateHold;
	private JRadioButton jrbRemoveFromCR;
	private JRadioButton jrbPrivilegeWithdrawn;
	private JRadioButton jrbAACompromise;

	private JButton jbOK;
	private JButton jbCancel;

	private int reason;
	private boolean ok = false;
	private Date revocationDate;
	private X509Certificate cert;

	/**
	 * Creates a new DCRLReason
	 * 
	 * @param parent The parent frame
	 * @param cert   Certificate to revoke
	 */
	public DCRLReason(JFrame parent, X509Certificate cert) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DCRLReason.Title"));
		this.cert = cert;
		initComponents();
	}

	private void initComponents() {
		Date now = new Date();

		jlSubject = new JLabel(res.getString("DCRLReason.jlSubject.text"));
		jdnSubject = new JDistinguishedName(res.getString("DCRLReason.Subject.Title"), 40, false);

		jlRevocationDate = new JLabel(res.getString("DCRLReason.jlRevocationDate.text"));
		jdtRevocationDate = new JDateTime(res.getString("DCRLReason.jdtRevocationDate.text"), false);
		jdtRevocationDate.setDateTime(now);
		jdtRevocationDate.setToolTipText(res.getString("DCRLReason.jdtRevocationDate.tooltip"));

		jlReason = new JLabel(res.getString("DCRLReason.jlReason.text"));

		jrbUnspecified = new JRadioButton(res.getString("DCRLReason.jrbUnspecified.text"));
		jrbUnspecified.setToolTipText(res.getString("DCRLReason.jrbUnspecified.tooltip"));

		jrbKeyCompromise = new JRadioButton(res.getString("DCRLReason.jrbKeyCompromise.text"));
		jrbKeyCompromise.setToolTipText(res.getString("DCRLReason.jrbKeyCompromise.tooltip"));

		jrbCACompromise = new JRadioButton(res.getString("DCRLReason.jrbCACompromise.text"));
		jrbCACompromise.setToolTipText(res.getString("DCRLReason.jrbCACompromise.tooltip"));

		jrbAffiliationChanged = new JRadioButton(res.getString("DCRLReason.jrbAffiliationChanged.text"));
		jrbAffiliationChanged.setToolTipText(res.getString("DCRLReason.jrbAffiliationChanged.tooltip"));

		jrbSuperseded = new JRadioButton(res.getString("DCRLReason.jrbSuperseded.text"));
		jrbSuperseded.setToolTipText(res.getString("DCRLReason.jrbSuperseded.tooltip"));

		jrbCessationOfOperation = new JRadioButton(res.getString("DCRLReason.jrbCessationOfOperation.text"));
		jrbCessationOfOperation.setToolTipText(res.getString("DCRLReason.jrbCessationOfOperation.tooltip"));

		jrbCertificateHold = new JRadioButton(res.getString("DCRLReason.jrbCertificateHold.text"));
		jrbCertificateHold.setToolTipText(res.getString("DCRLReason.jrbCertificateHold.tooltip"));

		jrbRemoveFromCR = new JRadioButton(res.getString("DCRLReason.jrbRemoveFromCR.text"));
		jrbRemoveFromCR.setToolTipText(res.getString("DCRLReason.jrbRemoveFromCR.tooltip"));

		jrbPrivilegeWithdrawn = new JRadioButton(res.getString("DCRLReason.jrbPrivilegeWithdrawn.text"));
		jrbPrivilegeWithdrawn.setToolTipText(res.getString("DCRLReason.jrbPrivilegeWithdrawn.tooltip"));

		jrbAACompromise = new JRadioButton(res.getString("DCRLReason.jrbAACompromise.text"));
		jrbAACompromise.setToolTipText(res.getString("DCRLReason.jrbAACompromise.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbUnspecified);
		buttonGroup.add(jrbKeyCompromise);
		buttonGroup.add(jrbCACompromise);
		buttonGroup.add(jrbAffiliationChanged);
		buttonGroup.add(jrbSuperseded);
		buttonGroup.add(jrbCessationOfOperation);
		buttonGroup.add(jrbCertificateHold);
		buttonGroup.add(jrbRemoveFromCR);
		buttonGroup.add(jrbPrivilegeWithdrawn);
		buttonGroup.add(jrbAACompromise);

		jrbUnspecified.setSelected(true);

		jbOK = new JButton(res.getString("DCRLReason.jbOK.text"));
		jbCancel = new JButton(res.getString("DCRLReason.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("fill", "[right]unrel[][][]", "[]"));
		pane.add(jlSubject, "");
		pane.add(jdnSubject, "spanx, wrap unrel");
		pane.add(jlRevocationDate, "");
		pane.add(jdtRevocationDate, "spanx, wrap unrel");
		pane.add(jlReason, "top");
		pane.add(jrbUnspecified, "left");
		pane.add(jrbKeyCompromise);
		pane.add(jrbCACompromise, "wrap");
		pane.add(jrbAffiliationChanged, "skip, left");
		pane.add(jrbSuperseded);
		pane.add(jrbCessationOfOperation, "wrap");
		pane.add(jrbCertificateHold, "skip, left");
		pane.add(jrbRemoveFromCR);
		pane.add(jrbPrivilegeWithdrawn, "wrap");
		pane.add(jrbAACompromise, "skip, left, wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jpButtons, "right, spanx");

		jbOK.addActionListener(evt -> okPressed());
		jbCancel.addActionListener(evt -> cancelPressed());

		populate();

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate() {
		if (cert != null) {
			jdnSubject.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(cert.getSubjectX500Principal()));
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
		if (jrbUnspecified.isSelected()) {
			reason = CRLReason.unspecified;
		} else if (jrbKeyCompromise.isSelected()) {
			reason = CRLReason.keyCompromise;
		} else if (jrbCACompromise.isSelected()) {
			reason = CRLReason.cACompromise;
		} else if (jrbAffiliationChanged.isSelected()) {
			reason = CRLReason.affiliationChanged;
		} else if (jrbSuperseded.isSelected()) {
			reason = CRLReason.superseded;
		} else if (jrbCessationOfOperation.isSelected()) {
			reason = CRLReason.cessationOfOperation;
		} else if (jrbCertificateHold.isSelected()) {
			reason = CRLReason.certificateHold;
		} else if (jrbRemoveFromCR.isSelected()) {
			reason = CRLReason.removeFromCRL;
		} else if (jrbPrivilegeWithdrawn.isSelected()) {
			reason = CRLReason.privilegeWithdrawn;
		} else if (jrbAACompromise.isSelected()) {
			reason = CRLReason.aACompromise;
		}
		revocationDate = jdtRevocationDate.getDateTime();
		ok = true;
		closeDialog();
	}

	public int getReason() {
		return reason;
	}

	public Date getRevocationDate() {
		return revocationDate;
	}

	public boolean isOk() {
		return ok;
	}

	public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException {
		DialogViewer.run(new DCRLReason(new JFrame(), null));
	}
}
