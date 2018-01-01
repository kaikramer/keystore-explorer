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
package org.kse.gui.crypto.policyinformation;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.gui.oid.JObjectId;

/**
 * Dialog to choose policy information.
 *
 */
public class DPolicyInformationChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policyinformation/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPolicyInformation;
	private JLabel jlPolicyIdentifier;
	private JObjectId joiPolicyIdentifier;
	private JLabel jlPolicyQualifiers;
	private JPolicyQualifierInfo jpqPolicyQualifiers;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PolicyInformation policyInformation;

	/**
	 * Constructs a new DPolicyInformationChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param policyInformation
	 *            Policy information
	 * @throws IOException
	 *             If policy information could not be decoded
	 */
	public DPolicyInformationChooser(JFrame parent, String title, PolicyInformation policyInformation)
			throws IOException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(policyInformation);
	}

	/**
	 * Constructs a new DPolicyInformationChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param policyInformation
	 *            Policy information
	 * @throws IOException
	 *             If policy information could not be decoded
	 */
	public DPolicyInformationChooser(JDialog parent, String title, PolicyInformation policyInformation)
			throws IOException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(policyInformation);
	}

	private void initComponents(PolicyInformation policyInformation) throws IOException {
		jlPolicyIdentifier = new JLabel(res.getString("DPolicyInformationChooser.jlPolicyIdentifier.text"));

		GridBagConstraints gbc_jlPolicyIdentifier = new GridBagConstraints();
		gbc_jlPolicyIdentifier.gridx = 0;
		gbc_jlPolicyIdentifier.gridy = 0;
		gbc_jlPolicyIdentifier.gridwidth = 1;
		gbc_jlPolicyIdentifier.gridheight = 1;
		gbc_jlPolicyIdentifier.insets = new Insets(5, 5, 5, 5);
		gbc_jlPolicyIdentifier.anchor = GridBagConstraints.EAST;

		joiPolicyIdentifier = new JObjectId(res.getString("DPolicyInformationChooser.PolicyIdentifier.Text"));
		joiPolicyIdentifier.setToolTipText(res.getString("DPolicyInformationChooser.joiPolicyIdentifier.tooltip"));

		GridBagConstraints gbc_joiPolicyIdentifier = new GridBagConstraints();
		gbc_joiPolicyIdentifier.gridx = 1;
		gbc_joiPolicyIdentifier.gridy = 0;
		gbc_joiPolicyIdentifier.gridwidth = 1;
		gbc_joiPolicyIdentifier.gridheight = 1;
		gbc_joiPolicyIdentifier.insets = new Insets(5, 5, 5, 5);
		gbc_joiPolicyIdentifier.anchor = GridBagConstraints.WEST;

		jlPolicyQualifiers = new JLabel(res.getString("DPolicyInformationChooser.jlPolicyQualifiers.text"));

		GridBagConstraints gbc_jlPolicyQualifiers = new GridBagConstraints();
		gbc_jlPolicyQualifiers.gridx = 0;
		gbc_jlPolicyQualifiers.gridy = 1;
		gbc_jlPolicyQualifiers.gridwidth = 1;
		gbc_jlPolicyQualifiers.gridheight = 1;
		gbc_jlPolicyQualifiers.insets = new Insets(5, 5, 5, 5);
		gbc_jlPolicyQualifiers.anchor = GridBagConstraints.NORTHEAST;

		jpqPolicyQualifiers = new JPolicyQualifierInfo(
				res.getString("DPolicyInformationChooser.PolicyQualifierInfo.Title"));
		jpqPolicyQualifiers.setPreferredSize(new Dimension(400, 150));

		GridBagConstraints gbc_jpqPolicyQualifiers = new GridBagConstraints();
		gbc_jpqPolicyQualifiers.gridx = 1;
		gbc_jpqPolicyQualifiers.gridy = 1;
		gbc_jpqPolicyQualifiers.gridwidth = 1;
		gbc_jpqPolicyQualifiers.gridheight = 1;
		gbc_jpqPolicyQualifiers.insets = new Insets(5, 5, 5, 5);
		gbc_jpqPolicyQualifiers.anchor = GridBagConstraints.WEST;

		jpPolicyInformation = new JPanel(new GridBagLayout());

		jpPolicyInformation.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpPolicyInformation.add(jlPolicyIdentifier, gbc_jlPolicyIdentifier);
		jpPolicyInformation.add(joiPolicyIdentifier, gbc_joiPolicyIdentifier);
		jpPolicyInformation.add(jlPolicyQualifiers, gbc_jlPolicyQualifiers);
		jpPolicyInformation.add(jpqPolicyQualifiers, gbc_jpqPolicyQualifiers);

		jbOK = new JButton(res.getString("DPolicyInformationChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DPolicyInformationChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpPolicyInformation);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(policyInformation);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(PolicyInformation policyInformation) throws IOException {
		if (policyInformation != null) {
			joiPolicyIdentifier.setObjectId(policyInformation.getPolicyIdentifier());

			ASN1Sequence policyQualifierInfoSeq = policyInformation.getPolicyQualifiers();

			if (policyQualifierInfoSeq != null) {
				List<PolicyQualifierInfo> policyQualifierInfo = new ArrayList<PolicyQualifierInfo>();

				for (int i = 0; i < policyQualifierInfoSeq.size(); i++) {
					PolicyQualifierInfo policyQualInfo = PolicyQualifierInfo.getInstance(
							policyQualifierInfoSeq.getObjectAt(i));
					policyQualifierInfo.add(policyQualInfo);
				}

				jpqPolicyQualifiers.setPolicyQualifierInfo(policyQualifierInfo);
			}
		}
	}

	/**
	 * Get selected policy information.
	 *
	 * @return Policy information, or null if none
	 */
	public PolicyInformation getPolicyInformation() {
		return policyInformation;
	}

	private void okPressed() {
		ASN1ObjectIdentifier policyIdentifer = joiPolicyIdentifier.getObjectId();

		if (policyIdentifer == null) {
			JOptionPane.showMessageDialog(this,
					res.getString("DPolicyInformationChooser.PolicyIdentifierValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		List<PolicyQualifierInfo> policyQualifierInfo = jpqPolicyQualifiers.getPolicyQualifierInfo();

		if (policyQualifierInfo.size() > 0) {
			ASN1EncodableVector policyQualifiersVec = new ASN1EncodableVector ();

			for (PolicyQualifierInfo policyQualInfo : policyQualifierInfo) {
				try {
					policyQualifiersVec.add(policyQualInfo);
				} catch (Exception ex) {
					DError dError = new DError(this, ex);
					dError.setLocationRelativeTo(this);
					dError.setVisible(true);
					return;
				}
			}

			DERSequence policyQualifiersSeq = new DERSequence(policyQualifiersVec);
			policyInformation = new PolicyInformation(policyIdentifer, policyQualifiersSeq);
		} else {

			policyInformation = new PolicyInformation(policyIdentifer);
		}

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
