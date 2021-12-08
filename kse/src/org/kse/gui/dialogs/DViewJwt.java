package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import net.miginfocom.swing.MigLayout;

public class DViewJwt extends JEscDialog {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpJwt;
	private JScrollPane jspJwt;
	private JTextArea jtAreaJwt;
	private JButton jbOK;
	private JButton jbCopy;

	public DViewJwt(JFrame parent, String jwt) {

		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DViewJwt.Title"));
		initComponents(jwt);
	}

	private void initComponents(String jwt) {
		jpJwt = new JPanel(new BorderLayout());
		jpJwt.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtAreaJwt = new JTextArea(jwt);
		jtAreaJwt.setToolTipText(res.getString("DViewJwt.jtAreaJwt.tooltip"));
		jtAreaJwt.setEditable(false);
		jtAreaJwt.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		// keep uneditable color same as editable
		jtAreaJwt.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
		jtAreaJwt.setLineWrap(true);
		jspJwt = PlatformUtil.createScrollPane(jtAreaJwt, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspJwt.setPreferredSize(new Dimension(400, 200));
		jpJwt.add(jspJwt, BorderLayout.CENTER);

		jbCopy = new JButton(res.getString("DViewJwt.jbCopy.text"));
		jbCopy.setToolTipText(res.getString("DViewJwt.jbCopy.tooltip"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewJwt.jbCopy.mnemonic").charAt(0));

		jbOK = new JButton(res.getString("DViewJwt.jbOK.text"));

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog"));
		pane.add(jpJwt, "span");
		pane.add(jbCopy, "tag Copy");
		pane.add(jbOK, "tag Ok");

		jbOK.addActionListener(evt -> okPressed());

		jbCopy.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DViewJwt.this);
				copyPressed();
			} finally {
				CursorUtil.setCursorFree(DViewJwt.this);
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbCopy);

		pack();

		SwingUtilities.invokeLater(() -> jbOK.requestFocus());
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private void copyPressed() {
		String policy = jtAreaJwt.getText();

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(policy);
		clipboard.setContents(copy, copy);
	}

	public static void main(String[] args) throws Exception {
		DViewJwt dialog = new DViewJwt(new javax.swing.JFrame(),
				"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9");
		DialogViewer.run(dialog);
	}

}
