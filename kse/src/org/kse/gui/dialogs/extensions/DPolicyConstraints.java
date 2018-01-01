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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
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
import org.kse.crypto.x509.PolicyConstraints;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Policy Constraints extension.
 *
 */
public class DPolicyConstraints extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPolicyConstraints;
	private JLabel jlPolicyConstraints;
	private JLabel jlRequireExplicitPolicy;
	private JTextField jtfRequireExplicitPolicy;
	private JLabel jlInhibitPolicyMapping;
	private JTextField jtfInhibitPolicyMapping;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DPolicyConstraints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DPolicyConstraints(JDialog parent) {
		super(parent);
		setTitle(res.getString("DPolicyConstraints.Title"));
		initComponents();
	}

	/**
	 * Creates a new DPolicyConstraints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Policy Constraints DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DPolicyConstraints(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DPolicyConstraints.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlPolicyConstraints = new JLabel(res.getString("DPolicyConstraints.jlPolicyConstraints.text"));
		GridBagConstraints gbc_jlPolicyConstraints = new GridBagConstraints();
		gbc_jlPolicyConstraints.gridx = 0;
		gbc_jlPolicyConstraints.gridy = 0;
		gbc_jlPolicyConstraints.gridwidth = 2;
		gbc_jlPolicyConstraints.insets = new Insets(5, 5, 5, 5);
		gbc_jlPolicyConstraints.anchor = GridBagConstraints.WEST;

		jlRequireExplicitPolicy = new JLabel(res.getString("DPolicyConstraints.jlRequireExplicitPolicy.text"));
		GridBagConstraints gbc_jlRequireExplicitPolicy = new GridBagConstraints();
		gbc_jlRequireExplicitPolicy.gridx = 0;
		gbc_jlRequireExplicitPolicy.gridy = 1;
		gbc_jlRequireExplicitPolicy.gridwidth = 1;
		gbc_jlRequireExplicitPolicy.insets = new Insets(5, 5, 5, 5);
		gbc_jlRequireExplicitPolicy.anchor = GridBagConstraints.EAST;

		jtfRequireExplicitPolicy = new JTextField(3);
		GridBagConstraints gbc_jtfRequireExplicitPolicy = new GridBagConstraints();
		gbc_jtfRequireExplicitPolicy.gridx = 1;
		gbc_jtfRequireExplicitPolicy.gridy = 1;
		gbc_jtfRequireExplicitPolicy.gridwidth = 1;
		gbc_jtfRequireExplicitPolicy.insets = new Insets(5, 5, 5, 5);
		gbc_jtfRequireExplicitPolicy.anchor = GridBagConstraints.WEST;

		jlInhibitPolicyMapping = new JLabel(res.getString("DPolicyConstraints.jlInhibitPolicyMapping.text"));
		GridBagConstraints gbc_jlInhibitPolicyMapping = new GridBagConstraints();
		gbc_jlInhibitPolicyMapping.gridx = 0;
		gbc_jlInhibitPolicyMapping.gridy = 2;
		gbc_jlInhibitPolicyMapping.gridwidth = 1;
		gbc_jlInhibitPolicyMapping.insets = new Insets(5, 5, 5, 5);
		gbc_jlInhibitPolicyMapping.anchor = GridBagConstraints.EAST;

		jtfInhibitPolicyMapping = new JTextField(3);
		GridBagConstraints gbc_jtfInhibitPolicyMapping = new GridBagConstraints();
		gbc_jtfInhibitPolicyMapping.gridx = 1;
		gbc_jtfInhibitPolicyMapping.gridy = 2;
		gbc_jtfInhibitPolicyMapping.gridwidth = 1;
		gbc_jtfInhibitPolicyMapping.insets = new Insets(5, 5, 5, 5);
		gbc_jtfInhibitPolicyMapping.anchor = GridBagConstraints.WEST;

		jpPolicyConstraints = new JPanel(new GridBagLayout());

		jpPolicyConstraints.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpPolicyConstraints.add(jlPolicyConstraints, gbc_jlPolicyConstraints);
		jpPolicyConstraints.add(jlRequireExplicitPolicy, gbc_jlRequireExplicitPolicy);
		jpPolicyConstraints.add(jtfRequireExplicitPolicy, gbc_jtfRequireExplicitPolicy);
		jpPolicyConstraints.add(jlInhibitPolicyMapping, gbc_jlInhibitPolicyMapping);
		jpPolicyConstraints.add(jtfInhibitPolicyMapping, gbc_jtfInhibitPolicyMapping);

		jbOK = new JButton(res.getString("DPolicyConstraints.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DPolicyConstraints.jbCancel.text"));
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
		getContentPane().add(jpPolicyConstraints, BorderLayout.CENTER);
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
		PolicyConstraints policyConstraints = PolicyConstraints.getInstance(value);

		int requireExplictPolicy = policyConstraints.getRequireExplicitPolicy();

		if (requireExplictPolicy != -1) {
			jtfRequireExplicitPolicy.setText("" + requireExplictPolicy);
			jtfRequireExplicitPolicy.setCaretPosition(0);
		}

		int inhibitPolicyMapping = policyConstraints.getInhibitPolicyMapping();

		if (inhibitPolicyMapping != -1) {
			jtfInhibitPolicyMapping.setText("" + inhibitPolicyMapping);
			jtfInhibitPolicyMapping.setCaretPosition(0);
		}
	}

	private void okPressed() {
		int requireExplicitPolicy = -1;

		String requireExplicitPolicyStr = jtfRequireExplicitPolicy.getText().trim();

		if (requireExplicitPolicyStr.length() != 0) {
			try {
				requireExplicitPolicy = Integer.parseInt(requireExplicitPolicyStr);
			} catch (NumberFormatException ex) {
				JOptionPane.showMessageDialog(this,
						res.getString("DPolicyConstraints.InvalidRequireExplicitPolicyValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (requireExplicitPolicy < 0) {
				JOptionPane.showMessageDialog(this,
						res.getString("DPolicyConstraints.InvalidRequireExplicitPolicyValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}
		}

		int inhibitPolicyMapping = -1;

		String inhibitPolicyMappingStr = jtfInhibitPolicyMapping.getText().trim();

		if (inhibitPolicyMappingStr.length() != 0) {
			try {
				inhibitPolicyMapping = Integer.parseInt(inhibitPolicyMappingStr);
			} catch (NumberFormatException ex) {
				JOptionPane.showMessageDialog(this,
						res.getString("DPolicyConstraints.InvalidInhibitPolicyMappingValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (inhibitPolicyMapping < 0) {
				JOptionPane.showMessageDialog(this,
						res.getString("DPolicyConstraints.InvalidInhibitPolicyMappingValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}
		}

		if ((requireExplicitPolicy == -1) && (inhibitPolicyMapping == -1)) {
			JOptionPane.showMessageDialog(this, res.getString("DPolicyConstraints.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		PolicyConstraints policyConstraints = new PolicyConstraints(requireExplicitPolicy, inhibitPolicyMapping);

		try {
			value = policyConstraints.getEncoded(ASN1Encoding.DER);
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
