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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.accessdescription.JAccessDescriptions;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit an Authority Information Access extension.
 *
 */
public class DAuthorityInformationAccess extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpAccessDescriptions;
	private JLabel jlAccessDescriptions;
	private JAccessDescriptions jadAccessDescriptions;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DAuthorityInformationAccess dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DAuthorityInformationAccess(JDialog parent) {
		super(parent);
		setTitle(res.getString("DAuthorityInformationAccess.Title"));
		initComponents();
	}

	/**
	 * Creates a new DAuthorityInformationAccess dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Authority Information Access DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DAuthorityInformationAccess(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DAuthorityInformationAccess.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlAccessDescriptions = new JLabel(res.getString("DAuthorityInformationAccess.jlAccessDescriptions.text"));

		GridBagConstraints gbc_jlAccessDescriptions = new GridBagConstraints();
		gbc_jlAccessDescriptions.gridx = 0;
		gbc_jlAccessDescriptions.gridy = 0;
		gbc_jlAccessDescriptions.gridwidth = 1;
		gbc_jlAccessDescriptions.gridheight = 1;
		gbc_jlAccessDescriptions.insets = new Insets(5, 5, 5, 5);
		gbc_jlAccessDescriptions.anchor = GridBagConstraints.NORTHEAST;

		jadAccessDescriptions = new JAccessDescriptions(
				res.getString("DAuthorityInformationAccess.AccessDescription.Title"));

		GridBagConstraints gbc_jadAccessDescriptions = new GridBagConstraints();
		gbc_jadAccessDescriptions.gridx = 1;
		gbc_jadAccessDescriptions.gridy = 0;
		gbc_jadAccessDescriptions.gridwidth = 1;
		gbc_jadAccessDescriptions.gridheight = 1;
		gbc_jadAccessDescriptions.insets = new Insets(5, 5, 5, 5);
		gbc_jadAccessDescriptions.anchor = GridBagConstraints.WEST;

		jpAccessDescriptions = new JPanel(new GridBagLayout());

		jpAccessDescriptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpAccessDescriptions.add(jlAccessDescriptions, gbc_jlAccessDescriptions);
		jpAccessDescriptions.add(jadAccessDescriptions, gbc_jadAccessDescriptions);

		jbOK = new JButton(res.getString("DAuthorityInformationAccess.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DAuthorityInformationAccess.jbCancel.text"));
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
		getContentPane().add(jpAccessDescriptions, BorderLayout.CENTER);
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
		AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(value);

		List<AccessDescription> accessDescriptionList =
				new ArrayList<AccessDescription>(Arrays.asList(authorityInformationAccess.getAccessDescriptions()));

		jadAccessDescriptions.setAccessDescriptions(accessDescriptionList);
	}

	private void okPressed() {
		List<AccessDescription> accessDescriptions = jadAccessDescriptions.getAccessDescriptions();

		if (accessDescriptions.size() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DAuthorityInformationAccess.ValueReq.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		ASN1EncodableVector vec = new ASN1EncodableVector();
		for (AccessDescription accessDescription : accessDescriptions) {
			vec.add(accessDescription);
		}
		AuthorityInformationAccess authorityInformationAccess =
				AuthorityInformationAccess.getInstance(new DERSequence(vec));

		try {
			value = authorityInformationAccess.getEncoded(ASN1Encoding.DER);
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
