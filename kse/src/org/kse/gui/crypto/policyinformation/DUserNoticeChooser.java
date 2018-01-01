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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.UserNotice;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog to choose a user notice.
 *
 */
public class DUserNoticeChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policyinformation/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpUserNotice;
	private JPanel jpNoticeReference;
	private JLabel jlOrganization;
	private JTextField jtfOrganization;
	private JLabel jlNoticeNumbers;
	private JTextField jtfNoticeNumbers;
	private JPanel jpExplicitText;
	private JLabel jlExplicitText;
	private JTextField jtfExplicitText;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private UserNotice userNotice;

	/**
	 * Constructs a new DUserNoticeChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param userNotice
	 *            User notice
	 */
	public DUserNoticeChooser(JFrame parent, String title, UserNotice userNotice) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(userNotice);
	}

	/**
	 * Constructs a new DUserNoticeChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param userNotice
	 *            User notice
	 */
	public DUserNoticeChooser(JDialog parent, String title, UserNotice userNotice) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(userNotice);
	}

	private void initComponents(UserNotice userNotice) {
		jlOrganization = new JLabel(res.getString("DUserNoticeChooser.jlOrganization.text"));

		GridBagConstraints gbc_jlOrganization = new GridBagConstraints();
		gbc_jlOrganization.gridx = 0;
		gbc_jlOrganization.gridy = 0;
		gbc_jlOrganization.gridwidth = 1;
		gbc_jlOrganization.gridheight = 1;
		gbc_jlOrganization.insets = new Insets(5, 5, 5, 5);
		gbc_jlOrganization.anchor = GridBagConstraints.EAST;

		jtfOrganization = new JTextField(40);
		jtfOrganization.setToolTipText(res.getString("DUserNoticeChooser.jtfOrganization.tooltip"));

		GridBagConstraints gbc_jtfOrganization = new GridBagConstraints();
		gbc_jtfOrganization.gridx = 1;
		gbc_jtfOrganization.gridy = 0;
		gbc_jtfOrganization.gridwidth = 1;
		gbc_jtfOrganization.gridheight = 1;
		gbc_jtfOrganization.insets = new Insets(5, 5, 5, 5);
		gbc_jtfOrganization.anchor = GridBagConstraints.WEST;

		jlNoticeNumbers = new JLabel(res.getString("DUserNoticeChooser.jlNoticeNumbers.text"));

		GridBagConstraints gbc_jlNoticeNumbers = new GridBagConstraints();
		gbc_jlNoticeNumbers.gridx = 0;
		gbc_jlNoticeNumbers.gridy = 1;
		gbc_jlNoticeNumbers.gridwidth = 1;
		gbc_jlNoticeNumbers.gridheight = 1;
		gbc_jlNoticeNumbers.insets = new Insets(5, 5, 5, 5);
		gbc_jlNoticeNumbers.anchor = GridBagConstraints.EAST;

		jtfNoticeNumbers = new JTextField(20);
		jtfNoticeNumbers.setToolTipText(res.getString("DUserNoticeChooser.jtfNoticeNumbers.tooltip"));

		GridBagConstraints gbc_jtfNoticeNumbers = new GridBagConstraints();
		gbc_jtfNoticeNumbers.gridx = 1;
		gbc_jtfNoticeNumbers.gridy = 1;
		gbc_jtfNoticeNumbers.gridwidth = 1;
		gbc_jtfNoticeNumbers.gridheight = 1;
		gbc_jtfNoticeNumbers.insets = new Insets(5, 5, 5, 5);
		gbc_jtfNoticeNumbers.anchor = GridBagConstraints.WEST;

		jpNoticeReference = new JPanel(new GridBagLayout());
		jpNoticeReference.setBorder(new TitledBorder(res.getString("DUserNoticeChooser.jpNoticeReference.text")));

		jpNoticeReference.add(jlOrganization, gbc_jlOrganization);
		jpNoticeReference.add(jtfOrganization, gbc_jtfOrganization);
		jpNoticeReference.add(jlNoticeNumbers, gbc_jlNoticeNumbers);
		jpNoticeReference.add(jtfNoticeNumbers, gbc_jtfNoticeNumbers);

		jlExplicitText = new JLabel(res.getString("DUserNoticeChooser.jlExplicitText.text"));

		jtfExplicitText = new JTextField(40);
		jtfExplicitText.setToolTipText(res.getString("DUserNoticeChooser.jtfExplicitText.tooltip"));

		jpExplicitText = new JPanel(new FlowLayout(FlowLayout.LEFT));

		jpExplicitText.add(jlExplicitText);
		jpExplicitText.add(jtfExplicitText);

		jpUserNotice = new JPanel(new BorderLayout());

		jpUserNotice.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpUserNotice.add(jpNoticeReference, BorderLayout.CENTER);
		jpUserNotice.add(jpExplicitText, BorderLayout.SOUTH);

		jbOK = new JButton(res.getString("DUserNoticeChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DUserNoticeChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpUserNotice);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(userNotice);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(UserNotice userNotice) {
		if (userNotice != null) {
			NoticeReference noticeReference = userNotice.getNoticeRef();

			if (noticeReference != null) {
				DisplayText organization = noticeReference.getOrganization();

				if (organization != null) {
					jtfOrganization.setText(organization.getString());
					jtfOrganization.setCaretPosition(0);
				}

				populateNoticeNumbers(noticeReference);
			}

			DisplayText explicitText = userNotice.getExplicitText();

			if (explicitText != null) {
				jtfExplicitText.setText(explicitText.getString());
				jtfExplicitText.setCaretPosition(0);
			}
		}
	}

	private void populateNoticeNumbers(NoticeReference noticeReference) {
		ASN1Integer[] noticeNumbers = noticeReference.getNoticeNumbers();

		if (noticeNumbers != null) {
			StringBuffer sb = new StringBuffer();

			for (int i = 0; i < noticeNumbers.length; i++) {
				ASN1Integer noticeNumber = noticeNumbers[i];

				sb.append(noticeNumber.getValue().intValue());

				if ((i + 1) < noticeNumbers.length) {
					sb.append(" ");
				}
			}

			jtfNoticeNumbers.setText(sb.toString());
			jtfNoticeNumbers.setCaretPosition(0);
		}
	}

	/**
	 * Get selected user notice.
	 *
	 * @return User notice, or null if none
	 */
	public UserNotice getUserNotice() {
		return userNotice;
	}

	private void okPressed() {

		String organizationString = jtfOrganization.getText().trim();
		int[] noticeNumberInts = extractNoticeNumbers();
		String explicitTextString = jtfExplicitText.getText().trim();

		if (noticeNumberInts == null) {
			JOptionPane.showMessageDialog(this, res.getString("DUserNoticeChooser.InvalidNoticeNumbers.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		if (((organizationString.length() > 0) && (noticeNumberInts.length == 0))
				|| ((organizationString.length() == 0) && (noticeNumberInts.length > 0))) {
			JOptionPane.showMessageDialog(this,
					res.getString("DUserNoticeChooser.OrganizationOrNoticeNumbersValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		if ((organizationString.length() == 0) && (noticeNumberInts.length == 0) && (explicitTextString.length() == 0)) {
			JOptionPane.showMessageDialog(this,
					res.getString("DUserNoticeChooser.NoticeRefOrExplicitTextValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		NoticeReference noticeReference = null;
		if (organizationString.length() > 0) { // If organization is present then so is al of notice reference

			Vector<ASN1Integer> noticeNumbers = new Vector<ASN1Integer>();

			for (int noticeNumber : noticeNumberInts) {
				noticeNumbers.add(new ASN1Integer(noticeNumber));
			}

			noticeReference = new NoticeReference(organizationString, noticeNumbers);
		}

		userNotice = new UserNotice(noticeReference, explicitTextString);

		closeDialog();
	}

	private int[] extractNoticeNumbers() {
		// If valid then return array of numbers, if blank return empty array,
		// if invalid return
		// null

		String noticeNumbersString = jtfNoticeNumbers.getText().trim();

		StringTokenizer strTokCnt = new StringTokenizer(noticeNumbersString, " ", false);
		int arcCount = strTokCnt.countTokens();

		StringTokenizer strTok = new StringTokenizer(noticeNumbersString, " ", true);

		boolean expectDelimiter = false;

		int[] noticeNumbers = new int[arcCount];
		int i = 0;
		while (strTok.hasMoreTokens()) {
			String token = strTok.nextToken();

			if (expectDelimiter && (!token.equals(" ") || !strTok.hasMoreTokens())) {
				return null;
			} else if (!expectDelimiter) {
				try {
					noticeNumbers[i] = Integer.parseInt(token);
					i++;
				} catch (NumberFormatException ex) {
					return null;
				}
			}

			expectDelimiter = !expectDelimiter;
		}

		return noticeNumbers;
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
