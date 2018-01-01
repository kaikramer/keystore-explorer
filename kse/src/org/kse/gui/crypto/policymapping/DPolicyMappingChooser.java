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
package org.kse.gui.crypto.policymapping;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.crypto.x509.PolicyMapping;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.oid.JObjectId;

/**
 * Dialog to choose an policy mapping.
 *
 */
public class DPolicyMappingChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policymapping/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPolicyMapping;
	private JLabel jlIssuerDomainPolicy;
	private JObjectId joiIssuerDomainPolicy;
	private JLabel jlSubjectDomainPolicy;
	private JObjectId joiSubjectDomainPolicy;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PolicyMapping policyMapping;

	/**
	 * Constructs a new DPolicyMappingChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param policyMapping
	 *            Policy mapping
	 */
	public DPolicyMappingChooser(JFrame parent, String title, PolicyMapping policyMapping) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(policyMapping);
	}

	/**
	 * Constructs a new DPolicyMappingChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param policyMapping
	 *            Policy mapping
	 */
	public DPolicyMappingChooser(JDialog parent, String title, PolicyMapping policyMapping) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(policyMapping);
	}

	private void initComponents(PolicyMapping policyMapping) {
		jlIssuerDomainPolicy = new JLabel(res.getString("DPolicyMappingChooser.jlIssuerDomainPolicy.text"));

		GridBagConstraints gbc_jlIssuerDomainPolicy = new GridBagConstraints();
		gbc_jlIssuerDomainPolicy.gridx = 0;
		gbc_jlIssuerDomainPolicy.gridy = 0;
		gbc_jlIssuerDomainPolicy.gridwidth = 1;
		gbc_jlIssuerDomainPolicy.gridheight = 1;
		gbc_jlIssuerDomainPolicy.insets = new Insets(5, 5, 5, 5);
		gbc_jlIssuerDomainPolicy.anchor = GridBagConstraints.EAST;

		joiIssuerDomainPolicy = new JObjectId(res.getString("DPolicyMappingChooser.IssuerDomainPolicy.Title"));
		joiIssuerDomainPolicy.setToolTipText(res.getString("DPolicyMappingChooser.joiIssuerDomainPolicy.tooltip"));

		GridBagConstraints gbc_joiIssuerDomainPolicy = new GridBagConstraints();
		gbc_joiIssuerDomainPolicy.gridx = 1;
		gbc_joiIssuerDomainPolicy.gridy = 0;
		gbc_joiIssuerDomainPolicy.gridwidth = 1;
		gbc_joiIssuerDomainPolicy.gridheight = 1;
		gbc_joiIssuerDomainPolicy.insets = new Insets(5, 5, 5, 5);
		gbc_joiIssuerDomainPolicy.anchor = GridBagConstraints.WEST;

		jlSubjectDomainPolicy = new JLabel(res.getString("DPolicyMappingChooser.jlSubjectDomainPolicy.text"));

		GridBagConstraints gbc_jlSubjectDomainPolicy = new GridBagConstraints();
		gbc_jlSubjectDomainPolicy.gridx = 0;
		gbc_jlSubjectDomainPolicy.gridy = 1;
		gbc_jlSubjectDomainPolicy.gridwidth = 1;
		gbc_jlSubjectDomainPolicy.gridheight = 1;
		gbc_jlSubjectDomainPolicy.insets = new Insets(5, 5, 5, 5);
		gbc_jlSubjectDomainPolicy.anchor = GridBagConstraints.EAST;

		joiSubjectDomainPolicy = new JObjectId(res.getString("DPolicyMappingChooser.SubjectDomainPolicy.Title"));
		joiSubjectDomainPolicy.setToolTipText(res.getString("DPolicyMappingChooser.joiSubjectDomainPolicy.tooltip"));

		GridBagConstraints gbc_joiSubjectDomainPolicy = new GridBagConstraints();
		gbc_joiSubjectDomainPolicy.gridx = 1;
		gbc_joiSubjectDomainPolicy.gridy = 1;
		gbc_joiSubjectDomainPolicy.gridwidth = 1;
		gbc_joiSubjectDomainPolicy.gridheight = 1;
		gbc_joiSubjectDomainPolicy.insets = new Insets(5, 5, 5, 5);
		gbc_joiSubjectDomainPolicy.anchor = GridBagConstraints.WEST;

		jpPolicyMapping = new JPanel(new GridBagLayout());

		jpPolicyMapping.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpPolicyMapping.add(jlIssuerDomainPolicy, gbc_jlIssuerDomainPolicy);
		jpPolicyMapping.add(joiIssuerDomainPolicy, gbc_joiIssuerDomainPolicy);
		jpPolicyMapping.add(jlSubjectDomainPolicy, gbc_jlSubjectDomainPolicy);
		jpPolicyMapping.add(joiSubjectDomainPolicy, gbc_joiSubjectDomainPolicy);

		jbOK = new JButton(res.getString("DPolicyMappingChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DPolicyMappingChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpPolicyMapping);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(policyMapping);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(PolicyMapping policyMapping) {
		if (policyMapping != null) {

			ASN1ObjectIdentifier issuerDomainPolicy = policyMapping.getIssuerDomainPolicy();
			ASN1ObjectIdentifier subjectDomainPolicy = policyMapping.getSubjectDomainPolicy();
			joiIssuerDomainPolicy.setObjectId(issuerDomainPolicy);
			joiSubjectDomainPolicy.setObjectId(subjectDomainPolicy);
		}
	}

	/**
	 * Get selected policy mapping.
	 *
	 * @return Policy mapping, or null if none
	 */
	public PolicyMapping getPolicyMapping() {
		return policyMapping;
	}

	private void okPressed() {
		ASN1ObjectIdentifier issuerDomainPolicy = joiIssuerDomainPolicy.getObjectId();

		if (issuerDomainPolicy == null) {
			JOptionPane.showMessageDialog(this,
					res.getString("DPolicyMappingChooser.IssuerDomainPolicyValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		ASN1ObjectIdentifier subjectDomainPolicy = joiSubjectDomainPolicy.getObjectId();

		if (subjectDomainPolicy == null) {
			JOptionPane.showMessageDialog(this,
					res.getString("DPolicyMappingChooser.SubjectDomainPolicyValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		policyMapping = new PolicyMapping(issuerDomainPolicy, subjectDomainPolicy);

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
