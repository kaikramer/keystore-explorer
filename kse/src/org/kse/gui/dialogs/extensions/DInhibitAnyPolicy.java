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
import java.awt.FlowLayout;
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
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.kse.crypto.x509.InhibitAnyPolicy;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit an Inhibit Any Policy extension.
 *
 */
public class DInhibitAnyPolicy extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpInhibitAnyPolicy;
	private JLabel jlInhibitAnyPolicy;
	private JPanel jpSkipCertificates;
	private JLabel jlSkipCertificates;
	private JTextField jtfSkipCertificates;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DInhibitAnyPolicy dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DInhibitAnyPolicy(JDialog parent) {
		super(parent);
		setTitle(res.getString("DInhibitAnyPolicy.Title"));
		initComponents();
	}

	/**
	 * Creates a new DInhibitAnyPolicy dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Inhibit Any Policy DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DInhibitAnyPolicy(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DInhibitAnyPolicy.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlInhibitAnyPolicy = new JLabel(res.getString("DInhibitAnyPolicy.jlInhibitAnyPolicy.text"));
		jlInhibitAnyPolicy.setBorder(new EmptyBorder(5, 5, 0, 5));

		jlSkipCertificates = new JLabel(res.getString("DInhibitAnyPolicy.jlSkipCertificates.text"));

		jtfSkipCertificates = new JTextField(3);

		jpSkipCertificates = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
		jpSkipCertificates.add(jlSkipCertificates);
		jpSkipCertificates.add(jtfSkipCertificates);

		jpInhibitAnyPolicy = new JPanel(new BorderLayout(5, 5));

		jpInhibitAnyPolicy.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpInhibitAnyPolicy.add(jlInhibitAnyPolicy, BorderLayout.NORTH);
		jpInhibitAnyPolicy.add(jpSkipCertificates, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DInhibitAnyPolicy.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DInhibitAnyPolicy.jbCancel.text"));
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
		getContentPane().add(jpInhibitAnyPolicy, BorderLayout.CENTER);
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
		InhibitAnyPolicy inhibitAnyPolicy =  InhibitAnyPolicy.getInstance(value);

		jtfSkipCertificates.setText("" + inhibitAnyPolicy.getSkipCerts());
		jtfSkipCertificates.setCaretPosition(0);
	}

	private void okPressed() {
		int skipCertificates = -1;

		String skipCertificatesStr = jtfSkipCertificates.getText().trim();

		if (skipCertificatesStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DInhibitAnyPolicy.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		try {
			skipCertificates = Integer.parseInt(skipCertificatesStr);
		} catch (NumberFormatException ex) {
			JOptionPane.showMessageDialog(this, res.getString("DInhibitAnyPolicy.InvalidLengthValue.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		if (skipCertificates < 0) {
			JOptionPane.showMessageDialog(this, res.getString("DInhibitAnyPolicy.InvalidLengthValue.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		InhibitAnyPolicy inhibitAnyPolicy = new InhibitAnyPolicy(skipCertificates);

		try {
			value = inhibitAnyPolicy.getEncoded(ASN1Encoding.DER);
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
