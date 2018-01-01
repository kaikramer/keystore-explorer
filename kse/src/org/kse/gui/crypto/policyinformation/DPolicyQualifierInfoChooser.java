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

import static org.kse.crypto.x509.CertificatePolicyQualifierType.PKIX_CPS_POINTER_QUALIFIER;
import static org.kse.crypto.x509.CertificatePolicyQualifierType.PKIX_USER_NOTICE_QUALIFIER;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog to choose an policy qualifier info.
 *
 */
public class DPolicyQualifierInfoChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policyinformation/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPolicyQualifierInfo;
	private JLabel jlPolicyQualifierInfoType;
	private JRadioButton jrbCps;
	private JRadioButton jrbUserNotice;
	private JLabel jlPolicyQualifierInfoValue;
	private JPanel jpPolicyQualifierInfoValue;
	private JTextField jtfCps;
	private JUserNotice junUserNotice;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PolicyQualifierInfo policyQualifierInfo;

	/**
	 * Constructs a new DPolicyQualifierInfoChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param policyQualifierInfo
	 *            Policy qualifier info
	 * @throws IOException
	 *             If policy qualifier info could not be decoded
	 */
	public DPolicyQualifierInfoChooser(JFrame parent, String title, PolicyQualifierInfo policyQualifierInfo)
			throws IOException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(policyQualifierInfo);
	}

	/**
	 * Constructs a new DPolicyQualifierInfoChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param policyQualifierInfo
	 *            Policy qualifier info
	 * @throws IOException
	 *             If policy qualifier info could not be decoded
	 */
	public DPolicyQualifierInfoChooser(JDialog parent, String title, PolicyQualifierInfo policyQualifierInfo)
			throws IOException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(policyQualifierInfo);
	}

	private void initComponents(PolicyQualifierInfo policyQualifierInfo) throws IOException {
		jlPolicyQualifierInfoType = new JLabel(
				res.getString("DPolicyQualifierInfoChooser.jlPolicyQualifierInfoType.text"));

		GridBagConstraints gbc_jlPolicyQualifierInfoType = new GridBagConstraints();
		gbc_jlPolicyQualifierInfoType.gridx = 0;
		gbc_jlPolicyQualifierInfoType.gridy = 0;
		gbc_jlPolicyQualifierInfoType.gridwidth = 1;
		gbc_jlPolicyQualifierInfoType.gridheight = 1;
		gbc_jlPolicyQualifierInfoType.anchor = GridBagConstraints.EAST;

		jrbCps = new JRadioButton(res.getString("DPolicyQualifierInfoChooser.jrbCps.text"));
		PlatformUtil.setMnemonic(jrbCps, res.getString("DPolicyQualifierInfoChooser.jrbCps.mnemonic").charAt(0));
		jrbCps.setToolTipText(res.getString("DPolicyQualifierInfoChooser.jrbCps.tooltip"));
		jrbCps.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				policyQualifierInfoTypeChanged();
			}
		});

		GridBagConstraints gbc_jrbCps = new GridBagConstraints();
		gbc_jrbCps.gridx = 1;
		gbc_jrbCps.gridy = 0;
		gbc_jrbCps.gridwidth = 1;
		gbc_jrbCps.gridheight = 1;
		gbc_jrbCps.anchor = GridBagConstraints.WEST;

		jrbUserNotice = new JRadioButton(res.getString("DPolicyQualifierInfoChooser.jrbUserNotice.text"));
		PlatformUtil.setMnemonic(jrbUserNotice, res.getString("DPolicyQualifierInfoChooser.jrbUserNotice.mnemonic")
				.charAt(0));
		jrbUserNotice.setToolTipText(res.getString("DPolicyQualifierInfoChooser.jrbUserNotice.tooltip"));
		jrbUserNotice.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				policyQualifierInfoTypeChanged();
			}
		});

		GridBagConstraints gbc_jrbUserNotice = new GridBagConstraints();
		gbc_jrbUserNotice.gridx = 2;
		gbc_jrbUserNotice.gridy = 0;
		gbc_jrbUserNotice.gridwidth = 1;
		gbc_jrbUserNotice.gridheight = 1;
		gbc_jrbUserNotice.anchor = GridBagConstraints.WEST;

		ButtonGroup bgPolicyQualifierInfoType = new ButtonGroup();
		bgPolicyQualifierInfoType.add(jrbCps);
		bgPolicyQualifierInfoType.add(jrbUserNotice);

		jlPolicyQualifierInfoValue = new JLabel(
				res.getString("DPolicyQualifierInfoChooser.jlPolicyQualifierInfoValue.text"));

		GridBagConstraints gbc_jlPolicyQualifierInfoValue = new GridBagConstraints();
		gbc_jlPolicyQualifierInfoValue.gridx = 0;
		gbc_jlPolicyQualifierInfoValue.gridy = 1;
		gbc_jlPolicyQualifierInfoValue.gridwidth = 1;
		gbc_jlPolicyQualifierInfoValue.gridheight = 1;
		gbc_jlPolicyQualifierInfoValue.anchor = GridBagConstraints.EAST;

		jtfCps = new JTextField(30);
		junUserNotice = new JUserNotice(res.getString("DPolicyQualifierInfoChooser.UserNotice.Title"));

		jpPolicyQualifierInfoValue = new JPanel(new FlowLayout(FlowLayout.LEFT));

		GridBagConstraints gbc_jpPolicyQualifierInfoValue = new GridBagConstraints();
		gbc_jpPolicyQualifierInfoValue.gridx = 1;
		gbc_jpPolicyQualifierInfoValue.gridy = 1;
		gbc_jpPolicyQualifierInfoValue.gridwidth = 2;
		gbc_jpPolicyQualifierInfoValue.gridheight = 1;
		gbc_jpPolicyQualifierInfoValue.insets = new Insets(0, 0, 0, 0);
		gbc_jpPolicyQualifierInfoValue.anchor = GridBagConstraints.WEST;

		jpPolicyQualifierInfoValue.add(jtfCps);

		jpPolicyQualifierInfo = new JPanel(new GridBagLayout());

		jpPolicyQualifierInfo.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpPolicyQualifierInfo.add(jlPolicyQualifierInfoType, gbc_jlPolicyQualifierInfoType);
		jpPolicyQualifierInfo.add(jrbCps, gbc_jrbCps);
		jpPolicyQualifierInfo.add(jrbUserNotice, gbc_jrbUserNotice);
		jpPolicyQualifierInfo.add(jlPolicyQualifierInfoValue, gbc_jlPolicyQualifierInfoValue);
		jpPolicyQualifierInfo.add(jpPolicyQualifierInfoValue, gbc_jpPolicyQualifierInfoValue);

		jbOK = new JButton(res.getString("DPolicyQualifierInfoChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DPolicyQualifierInfoChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpPolicyQualifierInfo);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(policyQualifierInfo);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void policyQualifierInfoTypeChanged() {
		jpPolicyQualifierInfoValue.removeAll();

		if (jrbCps.isSelected()) {
			jpPolicyQualifierInfoValue.add(jtfCps);
		} else if (jrbUserNotice.isSelected()) {
			jpPolicyQualifierInfoValue.add(junUserNotice);
		}

		pack();
	}

	private void populate(PolicyQualifierInfo policyQualifierInfo) throws IOException {
		if (policyQualifierInfo == null) {
			jrbCps.setSelected(true);
		} else {
			ASN1ObjectIdentifier policyQualifierId = policyQualifierInfo.getPolicyQualifierId();

			if (policyQualifierId.equals(new ASN1ObjectIdentifier(PKIX_CPS_POINTER_QUALIFIER.oid()))) {
				jrbCps.setSelected(true);
				jtfCps.setText(((DERIA5String) policyQualifierInfo.getQualifier()).getString());
				jtfCps.setCaretPosition(0);
			} else if (policyQualifierId.equals(new ASN1ObjectIdentifier(PKIX_USER_NOTICE_QUALIFIER.oid()))) {
				jrbUserNotice.setSelected(true);

				ASN1Encodable userNoticeObj = policyQualifierInfo.getQualifier();

				UserNotice userNotice = UserNotice.getInstance(userNoticeObj);

				junUserNotice.setUserNotice(userNotice);
			} else {
				jrbCps.setSelected(true);
			}
		}
	}

	/**
	 * Get selected policy qualifier info.
	 *
	 * @return General subtree, or null if none
	 */
	public PolicyQualifierInfo getPolicyQualifierInfo() {
		return policyQualifierInfo;
	}

	private void okPressed() {

		PolicyQualifierInfo newPolicyQualifierInfo = null;
		try {

			if (jrbCps.isSelected()) {
				String cps = jtfCps.getText().trim();

				if (cps.length() == 0) {
					JOptionPane.showMessageDialog(this,
							res.getString("DPolicyQualifierInfoChooser.CpsValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				newPolicyQualifierInfo = new PolicyQualifierInfo(
						new ASN1ObjectIdentifier(PKIX_CPS_POINTER_QUALIFIER.oid()),
						(new DERIA5String(cps)).toASN1Primitive());
			} else {
				UserNotice userNotice = junUserNotice.getUserNotice();

				if (userNotice == null) {
					JOptionPane.showMessageDialog(this,
							res.getString("DPolicyQualifierInfoChooser.UserNoticeValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				newPolicyQualifierInfo = new PolicyQualifierInfo(
						new ASN1ObjectIdentifier(PKIX_USER_NOTICE_QUALIFIER.oid()),
						userNotice);
			}
		} catch (Exception ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}

		policyQualifierInfo = newPolicyQualifierInfo;

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
