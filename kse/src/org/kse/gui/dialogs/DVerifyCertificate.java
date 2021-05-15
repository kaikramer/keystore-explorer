package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import net.miginfocom.swing.MigLayout;

public class DVerifyCertificate extends JEscDialog{

	private static final long serialVersionUID = 1L;
	
	public enum VerifyOptions { CRL, OCSP, CHAIN}
	
	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/resources");
	
	private static final String CANCEL_KEY = "CANCEL_KEY";
	
	private String certificateAlias;

	private JLabel jlFormat;
	private JRadioButton jrbCrlCheck;
	private JRadioButton jrbOcspCheck;
	private JRadioButton jrbChainCheck;
	private JPanel jpButtons;
	private JButton jbOk;
	private JButton jbCancel;
	
	private boolean verifySelected = false;

	private VerifyOptions verifyOption = VerifyOptions.CRL;

	
	public DVerifyCertificate(JFrame parent, String certificateAlias) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.certificateAlias = certificateAlias;
		initComponents();
	}

	private void initComponents() 
	{
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
		pane.add(jrbCrlCheck, "");
		pane.add(jrbOcspCheck, "split 3");
		pane.add(jrbChainCheck, "wrap");
		
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
	
	public boolean isVerifySelected() {
		return verifySelected;
	}

	public VerifyOptions getVerifyOption() {
		return verifyOption;
	}
	
	private void okPressed() {
		if (jrbCrlCheck.isSelected()) {
			verifyOption = VerifyOptions.CRL;
		} else 
		if (jrbOcspCheck.isSelected()){
			verifyOption = VerifyOptions.OCSP;
		} else {
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
	
}
