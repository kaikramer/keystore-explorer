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
package org.kse.gui.dialogs.extensions;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERIA5String;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Netscape Comment extension.
 *
 */
public class DNetscapeComment extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpNetscapeComment;
	private JLabel jlNetscapeComment;
	private JScrollPane jspNetscapeComment;
	private JTextArea jtaNetscapeComment;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DNetscapeComment dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DNetscapeComment(JDialog parent) {
		super(parent);
		setTitle(res.getString("DNetscapeComment.Title"));
		initComponents();
	}

	/**
	 * Creates a new DNetscapeComment dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Netscape Comment DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DNetscapeComment(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DNetscapeComment.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlNetscapeComment = new JLabel(res.getString("DNetscapeComment.jlNetscapeComment.text"));

		jtaNetscapeComment = new JTextArea();
		jtaNetscapeComment.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));

		jspNetscapeComment = PlatformUtil.createScrollPane(jtaNetscapeComment,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspNetscapeComment.setPreferredSize(new Dimension(300, 200));

		jpNetscapeComment = new JPanel(new BorderLayout(5, 5));

		jpNetscapeComment.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpNetscapeComment.add(jlNetscapeComment, BorderLayout.NORTH);
		jpNetscapeComment.add(jspNetscapeComment, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DNetscapeComment.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DNetscapeComment.jbCancel.text"));
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
		getContentPane().add(jpNetscapeComment, BorderLayout.CENTER);
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

	private void prepopulateWithValue(byte[] value) throws IOException {
		DERIA5String netscapeComment = DERIA5String.getInstance(value);

		jtaNetscapeComment.setText(netscapeComment.getString());
		jtaNetscapeComment.setCaretPosition(0);
	}

	private void okPressed() {
		String netscapeCommentStr = jtaNetscapeComment.getText().trim();

		if (netscapeCommentStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DNetscapeComment.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		DERIA5String netscapeComment = new DERIA5String(netscapeCommentStr);

		try {
			value = netscapeComment.getEncoded(ASN1Encoding.DER);
		} catch (IOException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}

		closeDialog();
	}

	/**
	 * Get extension value DER-encoded.
	 *
	 * @return Extension value
	 */
	@Override
	public byte[] getValue() {
		return value;
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
