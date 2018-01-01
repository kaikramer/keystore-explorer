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
import javax.swing.JCheckBox;
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
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Basic Constraints extension.
 *
 */
public class DBasicConstraints extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpBasicConstraints;
	private JLabel jlBasicConstraints;
	private JCheckBox jcbSubjectIsCa;
	private JPanel jpPathLengthConstraint;
	private JLabel jlPathLengthConstraint;
	private JTextField jtfPathLengthConstraint;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DBasicConstraints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DBasicConstraints(JDialog parent) {
		super(parent);
		setTitle(res.getString("DBasicConstraints.Title"));
		initComponents();
	}

	/**
	 * Creates a new DBasicConstraints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Basic Constraints DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DBasicConstraints(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DBasicConstraints.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlBasicConstraints = new JLabel(res.getString("DBasicConstraints.jlBasicConstraints.text"));
		jlBasicConstraints.setBorder(new EmptyBorder(5, 5, 0, 5));

		jcbSubjectIsCa = new JCheckBox(res.getString("DBasicConstraints.jcbSubjectIsCa.text"));
		jcbSubjectIsCa.setSelected(false);
		jcbSubjectIsCa.setBorder(new EmptyBorder(5, 5, 0, 5));

		jlPathLengthConstraint = new JLabel(res.getString("DBasicConstraints.jlPathLengthConstraint.text"));

		jtfPathLengthConstraint = new JTextField(3);

		jpPathLengthConstraint = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
		jpPathLengthConstraint.add(jlPathLengthConstraint);
		jpPathLengthConstraint.add(jtfPathLengthConstraint);

		jpBasicConstraints = new JPanel(new BorderLayout(5, 5));

		jpBasicConstraints.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpBasicConstraints.add(jlBasicConstraints, BorderLayout.NORTH);
		jpBasicConstraints.add(jcbSubjectIsCa, BorderLayout.CENTER);
		jpBasicConstraints.add(jpPathLengthConstraint, BorderLayout.SOUTH);

		jbOK = new JButton(res.getString("DBasicConstraints.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DBasicConstraints.jbCancel.text"));
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
		getContentPane().add(jpBasicConstraints, BorderLayout.CENTER);
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
		BasicConstraints basicConstraints = BasicConstraints.getInstance(value);

		jcbSubjectIsCa.setSelected(basicConstraints.isCA());

		if (basicConstraints.getPathLenConstraint() != null) {
			jtfPathLengthConstraint.setText("" + basicConstraints.getPathLenConstraint().intValue());
			jtfPathLengthConstraint.setCaretPosition(0);
		}
	}

	private void okPressed() {
		boolean ca = jcbSubjectIsCa.isSelected();

		int pathLengthConstraint = -1;

		String pathLengthConstraintStr = jtfPathLengthConstraint.getText().trim();

		if (pathLengthConstraintStr.length() > 0) {
			try {
				pathLengthConstraint = Integer.parseInt(pathLengthConstraintStr);
			} catch (NumberFormatException ex) {
				JOptionPane.showMessageDialog(this, res.getString("DBasicConstraints.InvalidLengthValue.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (pathLengthConstraint < 0) {
				JOptionPane.showMessageDialog(this, res.getString("DBasicConstraints.InvalidLengthValue.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			}
		}

		BasicConstraints basicConstraints;

		if (pathLengthConstraint != -1) {
			// pathLengthConstraint set automatically means ca=true
			basicConstraints = new BasicConstraints(pathLengthConstraint);
		} else {
			basicConstraints = new BasicConstraints(ca);
		}

		try {
			value = basicConstraints.getEncoded(ASN1Encoding.DER);
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
