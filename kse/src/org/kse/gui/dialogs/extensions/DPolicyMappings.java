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
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.policymapping.JPolicyMappings;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit an Policy Mappings extension.
 *
 */
public class DPolicyMappings extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPolicyMappings;
	private JLabel jlPolicyMappings;
	private JPolicyMappings jpmPolicyMappings;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DPolicyMappings dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DPolicyMappings(JDialog parent) {
		super(parent);
		setTitle(res.getString("DPolicyMappings.Title"));
		initComponents();
	}

	/**
	 * Creates a new DPolicyMappings dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Policy Mappings DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DPolicyMappings(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DPolicyMappings.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlPolicyMappings = new JLabel(res.getString("DPolicyMappings.jlPolicyMappings.text"));

		GridBagConstraints gbc_jlPolicyMappings = new GridBagConstraints();
		gbc_jlPolicyMappings.gridx = 0;
		gbc_jlPolicyMappings.gridy = 0;
		gbc_jlPolicyMappings.gridwidth = 1;
		gbc_jlPolicyMappings.gridheight = 1;
		gbc_jlPolicyMappings.insets = new Insets(5, 5, 5, 5);
		gbc_jlPolicyMappings.anchor = GridBagConstraints.NORTHEAST;

		jpmPolicyMappings = new JPolicyMappings(res.getString("DPolicyMappings.PolicyMapping.Title"));

		GridBagConstraints gbc_jadPolicyMappings = new GridBagConstraints();
		gbc_jadPolicyMappings.gridx = 1;
		gbc_jadPolicyMappings.gridy = 0;
		gbc_jadPolicyMappings.gridwidth = 1;
		gbc_jadPolicyMappings.gridheight = 1;
		gbc_jadPolicyMappings.insets = new Insets(5, 5, 5, 5);
		gbc_jadPolicyMappings.anchor = GridBagConstraints.WEST;

		jpPolicyMappings = new JPanel(new GridBagLayout());

		jpPolicyMappings.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpPolicyMappings.add(jlPolicyMappings, gbc_jlPolicyMappings);
		jpPolicyMappings.add(jpmPolicyMappings, gbc_jadPolicyMappings);

		jbOK = new JButton(res.getString("DPolicyMappings.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DPolicyMappings.jbCancel.text"));
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
		getContentPane().add(jpPolicyMappings, BorderLayout.CENTER);
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
		PolicyMappings policyMappings = PolicyMappings.getInstance(value);

		jpmPolicyMappings.setPolicyMappings(policyMappings);
	}

	private void okPressed() {
		PolicyMappings policyMappings = jpmPolicyMappings.getPolicyMappings();
		ASN1Sequence policyMappingsSeq = (ASN1Sequence) policyMappings.toASN1Primitive();

		if (policyMappingsSeq.size() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DPolicyMappings.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		try {
			value = policyMappings.getEncoded(ASN1Encoding.DER);
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
