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
package org.kse.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.crypto.CryptoException;
import org.kse.crypto.jcepolicy.JcePolicy;
import org.kse.crypto.jcepolicy.JcePolicyUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Display crypto strength.
 *
 */
public class DCryptoStrength extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private static final int TEXT_FIELD_WIDTH = 10;

	private JPanel jpCryptoStrength;
	private JLabel jlLocalStrength;
	private JTextField jtfLocalStrength;
	private JButton jbLocalStrengthDetails;
	private JLabel jlUsExportStrength;
	private JTextField jtfUsExportStrength;
	private JButton jbUsExportStrengthDetails;
	private JButton jbOK;
	private JPanel jpOK;

	/**
	 * Creates a new DCryptoStrength dialog where the parent is a frame.
	 *
	 * @param parent
	 *            Parent frame
	 * @throws CryptoException
	 *             If a crypto problem occurred
	 */
	public DCryptoStrength(JFrame parent) throws CryptoException {
		super(parent, res.getString("DCryptoStrength.Title"), ModalityType.DOCUMENT_MODAL);

		initComponents();
	}

	/**
	 * Creates a new DCryptoStrength dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param modality
	 *            Dialog modality
	 * @throws CryptoException
	 *             If a crypto problem occurred
	 */
	public DCryptoStrength(JDialog parent, Dialog.ModalityType modality) throws CryptoException {
		super(parent, res.getString("DCryptoStrength.Title"), modality);

		initComponents();
	}

	private void initComponents() throws CryptoException {
		getContentPane().setLayout(new BorderLayout());

		GridBagConstraints gbcLabel = new GridBagConstraints();
		gbcLabel.gridx = 0;
		gbcLabel.gridwidth = 3;
		gbcLabel.gridheight = 1;
		gbcLabel.insets = new Insets(5, 5, 5, 5);
		gbcLabel.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcTextField = new GridBagConstraints();
		gbcTextField.gridx = 3;
		gbcTextField.gridwidth = 3;
		gbcTextField.gridheight = 1;
		gbcTextField.insets = new Insets(5, 5, 5, 5);
		gbcTextField.anchor = GridBagConstraints.WEST;

		GridBagConstraints gbcButton = new GridBagConstraints();
		gbcButton.gridx = 6;
		gbcButton.gridwidth = 3;
		gbcButton.gridheight = 1;
		gbcButton.insets = new Insets(5, 5, 5, 5);
		gbcButton.anchor = GridBagConstraints.WEST;

		jpCryptoStrength = new JPanel(new GridBagLayout());
		jpCryptoStrength.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jlLocalStrength = new JLabel(res.getString("DCryptoStrength.jlLocalStrength.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlLocalStrength = (GridBagConstraints) gbcLabel.clone();
		gbc_jlLocalStrength.gridy = 0;
		jpCryptoStrength.add(jlLocalStrength, gbc_jlLocalStrength);

		jtfLocalStrength = new JTextField(JcePolicyUtil.getCryptoStrength(JcePolicy.LOCAL_POLICY).friendly(),
				TEXT_FIELD_WIDTH);
		jtfLocalStrength.setToolTipText(res.getString("DCryptoStrength.jtfLocalStrength.tooltip"));
		jtfLocalStrength.setEditable(false);
		jtfLocalStrength.setCaretPosition(0);

		GridBagConstraints gbc_jtfLocalStrength = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfLocalStrength.gridy = 0;
		jpCryptoStrength.add(jtfLocalStrength, gbc_jtfLocalStrength);

		jbLocalStrengthDetails = new JButton(res.getString("DCryptoStrength.jbLocalStrengthDetails.text"));
		PlatformUtil.setMnemonic(jbLocalStrengthDetails,
				res.getString("DCryptoStrength.jbLocalStrengthDetails.mnemonic").charAt(0));
		jbLocalStrengthDetails.setToolTipText(res.getString("DCryptoStrength.jbLocalStrengthDetails.tooltip"));

		jbLocalStrengthDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DCryptoStrength.this);
					displayPolicyDetails(JcePolicy.LOCAL_POLICY);
				} finally {
					CursorUtil.setCursorFree(DCryptoStrength.this);
				}
			}
		});

		GridBagConstraints gbc_jbLocalStrengthDetails = (GridBagConstraints) gbcButton.clone();
		gbc_jbLocalStrengthDetails.gridy = 0;
		jpCryptoStrength.add(jbLocalStrengthDetails, gbc_jbLocalStrengthDetails);

		jlUsExportStrength = new JLabel(res.getString("DCryptoStrength.jlUsExportStrength.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlUsExportStrength = (GridBagConstraints) gbcLabel.clone();
		gbc_jlUsExportStrength.gridy = 1;
		jpCryptoStrength.add(jlUsExportStrength, gbc_jlUsExportStrength);

		jtfUsExportStrength = new JTextField(JcePolicyUtil.getCryptoStrength(JcePolicy.US_EXPORT_POLICY).friendly(),
				TEXT_FIELD_WIDTH);
		jtfUsExportStrength.setToolTipText(res.getString("DCryptoStrength.jtfUsExportStrength.tooltip"));
		jtfUsExportStrength.setEditable(false);
		jtfUsExportStrength.setCaretPosition(0);

		GridBagConstraints gbc_jtfUsExportStrength = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfUsExportStrength.gridy = 1;
		jpCryptoStrength.add(jtfUsExportStrength, gbc_jtfUsExportStrength);

		jbUsExportStrengthDetails = new JButton(res.getString("DCryptoStrength.jbUsExportStrengthDetails.text"));
		PlatformUtil.setMnemonic(jbUsExportStrengthDetails,
				res.getString("DCryptoStrength.jbUsExportStrengthDetails.mnemonic").charAt(0));
		jbUsExportStrengthDetails.setToolTipText(res.getString("DCryptoStrength.jbUsExportStrengthDetails.tooltip"));

		jbUsExportStrengthDetails.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DCryptoStrength.this);
					displayPolicyDetails(JcePolicy.US_EXPORT_POLICY);
				} finally {
					CursorUtil.setCursorFree(DCryptoStrength.this);
				}
			}
		});

		GridBagConstraints gbc_jbUsExportStrengthDetails = (GridBagConstraints) gbcButton.clone();
		gbc_jbUsExportStrengthDetails.gridy = 1;
		jpCryptoStrength.add(jbUsExportStrengthDetails, gbc_jbUsExportStrengthDetails);

		jbOK = new JButton(res.getString("DCryptoStrength.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().add(jpCryptoStrength, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		setResizable(false);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void displayPolicyDetails(JcePolicy jcePolicy) {
		try {
			DViewJcePolicy dViewJcePolicy = new DViewJcePolicy(this, jcePolicy);
			dViewJcePolicy.setLocationRelativeTo(this);
			dViewJcePolicy.setVisible(true);
		} catch (CryptoException ex) {
			DError.displayError(this, ex);
		}
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
