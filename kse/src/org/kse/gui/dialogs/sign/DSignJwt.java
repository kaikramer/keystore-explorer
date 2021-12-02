package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.KeyEvent;
import java.security.PrivateKey;
import java.util.Date;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.datetime.JDateTime;

import net.miginfocom.swing.MigLayout;

public class DSignJwt extends JEscDialog {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlIssuer;
	private JTextField jtfIssuer;
	private JCheckBox jcbIssuer;
	private JLabel jlIssuedAt;
	private JDateTime jdtIssuedAt;
	private JCheckBox jcbIssuedAt;
	private JLabel jlSubject;
	private JTextField jtfSubject;
	private JCheckBox jcbSubject;
	private JLabel jlNotBefore;
	private JDateTime jdtNotBefore;
	private JCheckBox jcbNotBefore;
	private JLabel jlExpiration;
	private JDateTime jdtExpiration;
	private JCheckBox jcbExpiration;
	private JLabel jlAudience;
	private JTextField jtfAudience;
	private JCheckBox jcbAudience;

	private JButton jbOK;
	private JButton jbCancel;

	private KeyPairType signKeyPairType;
	private PrivateKey signPrivateKey;

	private JFrame parent;
	private KseFrame kseFrame;

	public DSignJwt(JFrame parent, KseFrame kseFrame, KeyPairType signKeyPairType, PrivateKey signPrivateKey)
			throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.parent = parent;
		this.kseFrame = kseFrame;
		this.signKeyPairType = signKeyPairType;
		this.signPrivateKey = signPrivateKey;
		setTitle(res.getString("DSignJwt.Title"));
		initComponents();
	}

	private void initComponents() throws CryptoException {
		Date now = new Date();
		
		jlIssuer = new JLabel(res.getString("DSignJwt.jlIssuer.text"));
		jtfIssuer = new JTextField("", 22);
		jtfIssuer.setToolTipText(res.getString("DSignJwt.jtfIssuer.tooltip"));
		jcbIssuer = new JCheckBox();
		jcbIssuer.setSelected(true);
		
		jlIssuedAt = new JLabel(res.getString("DSignJwt.jlIssuedAt.text"));
		jdtIssuedAt = new JDateTime(res.getString("DSignJwt.jdtIssuedAt.text"), false);
		jdtIssuedAt.setDateTime(now);
		jdtIssuedAt.setToolTipText(res.getString("DSignJwt.jdtIssuedAt.tooltip"));
		jcbIssuedAt = new JCheckBox();
		jcbIssuedAt.setSelected(true);	
	
		jlSubject = new JLabel(res.getString("DSignJwt.jlSubject.text"));
		jtfSubject = new JTextField("", 22);
		jtfSubject.setToolTipText(res.getString("DSignJwt.jtfSubject.tooltip"));
		jcbSubject = new JCheckBox();
		jcbSubject.setSelected(true);	
		
		jlNotBefore = new JLabel(res.getString("DSignJwt.jlNotBefore.text"));
		jdtNotBefore = new JDateTime(res.getString("DSignJwt.jdtNotBefore.text"), false);
		jdtNotBefore.setDateTime(now);
		jdtNotBefore.setToolTipText(res.getString("DSignJwt.jdtNotBefore.tooltip"));
		jcbNotBefore = new JCheckBox();
		jcbNotBefore.setSelected(true);	
		
		jlExpiration = new JLabel(res.getString("DSignJwt.jlExpiration.text"));
		jdtExpiration = new JDateTime(res.getString("DSignJwt.jdtExpiration.text"), false);
		jdtExpiration.setDateTime(now);
		jdtExpiration.setToolTipText(res.getString("DSignJwt.jdtExpiration.tooltip"));
		jcbExpiration = new JCheckBox();
		jcbExpiration.setSelected(true);

		jlAudience = new JLabel(res.getString("DSignJwt.jlAudience.text"));
		jtfAudience = new JTextField("", 22);
		jtfAudience.setToolTipText(res.getString("DSignJwt.jtfAudience.tooltip"));
		jcbAudience = new JCheckBox();
		jcbAudience.setSelected(true);
	
		jbOK = new JButton(res.getString("DSignJwt.jbOK.text"));
		jbCancel = new JButton(res.getString("DSignJwt.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		
		JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		
		pane.add(jlIssuer, "");
		pane.add(jtfIssuer, "");
		pane.add(jcbIssuer, "wrap");
		
		pane.add(jlIssuedAt, "");
		pane.add(jdtIssuedAt, "");
		pane.add(jcbIssuedAt, "wrap");

		pane.add(jlSubject, "");
		pane.add(jtfSubject, "");
		pane.add(jcbSubject, "wrap");

		pane.add(jlNotBefore, "");
		pane.add(jdtNotBefore, "");
		pane.add(jcbNotBefore, "wrap");
		
		pane.add(jlExpiration, "");
		pane.add(jdtExpiration, "");
		pane.add(jcbExpiration, "wrap");

		pane.add(jlAudience, "");
		pane.add(jtfAudience, "");
		pane.add(jcbAudience, "wrap");
		
		pane.add(jpButtons, "right, spanx");

		populateFields();
		
		jcbIssuer.addItemListener(evt -> {
			jtfIssuer.setEnabled(jcbIssuer.isSelected());
			jtfIssuer.requestFocus();
		});
		
		jcbIssuedAt.addItemListener(evt -> {
			jdtIssuedAt.setEnabled(jcbIssuedAt.isSelected());
			jdtIssuedAt.requestFocus();
		});

		jcbSubject.addItemListener(evt -> {
			jtfSubject.setEnabled(jcbSubject.isSelected());
			jtfSubject.requestFocus();
		});

		jcbNotBefore.addItemListener(evt -> {
			jdtNotBefore.setEnabled(jcbNotBefore.isSelected());
			jdtNotBefore.requestFocus();
		});

		jcbExpiration.addItemListener(evt -> {
			jdtExpiration.setEnabled(jcbExpiration.isSelected());
			jdtExpiration.requestFocus();
		});

		jcbAudience.addItemListener(evt -> {
			jtfAudience.setEnabled(jcbAudience.isSelected());
			jtfAudience.requestFocus();
		});

		jbOK.addActionListener(evt -> okPressed());
		jbCancel.addActionListener(evt -> cancelPressed());
		
		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}
	
	private void populateFields() {
		
	}
	
	private void okPressed() {
		closeDialog();
	}

	private void cancelPressed() {
		closeDialog();
	}
	
	private void closeDialog() {
		setVisible(false);
		dispose();
	}
	
	public String getIssuer()
	{
		if (jcbIssuer.isSelected()) {
			return jtfIssuer.getText();
		}
		else {
			return null;
		}
	}
	
	public Date getExpiration()
	{
		if (jcbExpiration.isSelected()) {
			return jdtExpiration.getDateTime();
		}
		else {
			return null;
		}
	}
	
	public String getSubject()
	{
		if (jcbSubject.isSelected()) {
			return jtfSubject.getText();
		}
		else {
			return null;
		}
	}
}
