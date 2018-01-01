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
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JKeyIdentifier;
import org.kse.gui.crypto.generalname.JGeneralNames;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit an Authority Key Identifier extension.
 *
 */
public class DAuthorityKeyIdentifier extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpAuthorityKeyIdentifier;
	private JLabel jlKeyIdentifier;
	private JKeyIdentifier jkiKeyIdentifier;
	private JLabel jlAuthorityCertIssuer;
	private JGeneralNames jgnAuthorityCertIssuer;
	private JLabel jlAuthorityCertSerialNumber;
	private JTextField jtfAuthorityCertSerialNumber;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;
	private PublicKey authorityPublicKey;

	/**
	 * Creates a new DAuthorityKeyIdentifier dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param authorityPublicKey
	 *            Authority public key
	 * @param authorityCertName
	 *            Authority certificate name
	 * @param authorityCertSerialNumber
	 *            Authority certificate serial number
	 */
	public DAuthorityKeyIdentifier(JDialog parent, PublicKey authorityPublicKey, X500Name authorityCertName,
			BigInteger authorityCertSerialNumber) {
		super(parent);

		setTitle(res.getString("DAuthorityKeyIdentifier.Title"));
		this.authorityPublicKey = authorityPublicKey;
		initComponents();
		prepopulateWithAuthorityCertDetails(authorityCertName, authorityCertSerialNumber);
	}

	/**
	 * Creates a new DAuthorityKeyIdentifier dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Authority Key Identifier DER-encoded
	 * @param authorityPublicKey
	 *            Authority public key
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DAuthorityKeyIdentifier(JDialog parent, byte[] value, PublicKey authorityPublicKey) throws IOException {
		super(parent);
		setTitle(res.getString("DAuthorityKeyIdentifier.Title"));
		this.authorityPublicKey = authorityPublicKey;
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlKeyIdentifier = new JLabel(res.getString("DAuthorityKeyIdentifier.jlKeyIdentifer.text"));

		GridBagConstraints gbc_jlKeyIdentifier = new GridBagConstraints();
		gbc_jlKeyIdentifier.gridx = 0;
		gbc_jlKeyIdentifier.gridy = 0;
		gbc_jlKeyIdentifier.gridwidth = 1;
		gbc_jlKeyIdentifier.gridheight = 1;
		gbc_jlKeyIdentifier.insets = new Insets(5, 5, 5, 5);
		gbc_jlKeyIdentifier.anchor = GridBagConstraints.EAST;

		jkiKeyIdentifier = new JKeyIdentifier(res.getString("DAuthorityKeyIdentifier.KeyIdentifier.Title"),
				authorityPublicKey);

		GridBagConstraints gbc_jkiKeyIdentifier = new GridBagConstraints();
		gbc_jkiKeyIdentifier.gridx = 1;
		gbc_jkiKeyIdentifier.gridy = 0;
		gbc_jkiKeyIdentifier.gridwidth = 1;
		gbc_jkiKeyIdentifier.gridheight = 1;
		gbc_jkiKeyIdentifier.insets = new Insets(5, 5, 5, 5);
		gbc_jkiKeyIdentifier.anchor = GridBagConstraints.WEST;

		jlAuthorityCertIssuer = new JLabel(res.getString("DAuthorityKeyIdentifier.jlAuthorityCertIssuer.text"));

		GridBagConstraints gbc_jlAuthorityCertIssuer = new GridBagConstraints();
		gbc_jlAuthorityCertIssuer.gridx = 0;
		gbc_jlAuthorityCertIssuer.gridy = 1;
		gbc_jlAuthorityCertIssuer.gridwidth = 1;
		gbc_jlAuthorityCertIssuer.gridheight = 1;
		gbc_jlAuthorityCertIssuer.insets = new Insets(0, 5, 0, 5);
		gbc_jlAuthorityCertIssuer.anchor = GridBagConstraints.NORTHEAST;

		jgnAuthorityCertIssuer = new JGeneralNames(res.getString("DAuthorityKeyIdentifier.AuthorityCertIssuer.Title"));
		jgnAuthorityCertIssuer.setPreferredSize(new Dimension(400, 150));

		GridBagConstraints gbc_jgnAuthorityCertIssuer = new GridBagConstraints();
		gbc_jgnAuthorityCertIssuer.gridx = 1;
		gbc_jgnAuthorityCertIssuer.gridy = 1;
		gbc_jgnAuthorityCertIssuer.gridwidth = 1;
		gbc_jgnAuthorityCertIssuer.gridheight = 1;
		gbc_jgnAuthorityCertIssuer.insets = new Insets(0, 5, 0, 5);
		gbc_jgnAuthorityCertIssuer.anchor = GridBagConstraints.WEST;

		jlAuthorityCertSerialNumber = new JLabel(
				res.getString("DAuthorityKeyIdentifier.jlAuthorityCertSerialNumber.text"));

		GridBagConstraints gbc_jlAuthorityCertSerialNumber = new GridBagConstraints();
		gbc_jlAuthorityCertSerialNumber.gridx = 0;
		gbc_jlAuthorityCertSerialNumber.gridy = 2;
		gbc_jlAuthorityCertSerialNumber.gridwidth = 1;
		gbc_jlAuthorityCertSerialNumber.gridheight = 1;
		gbc_jlAuthorityCertSerialNumber.insets = new Insets(5, 5, 5, 5);
		gbc_jlAuthorityCertSerialNumber.anchor = GridBagConstraints.EAST;

		jtfAuthorityCertSerialNumber = new JTextField(20);

		GridBagConstraints gbc_jtfAuthorityCertSerialNumber = new GridBagConstraints();
		gbc_jtfAuthorityCertSerialNumber.gridx = 1;
		gbc_jtfAuthorityCertSerialNumber.gridy = 2;
		gbc_jtfAuthorityCertSerialNumber.gridwidth = 1;
		gbc_jtfAuthorityCertSerialNumber.gridheight = 1;
		gbc_jtfAuthorityCertSerialNumber.insets = new Insets(5, 5, 5, 5);
		gbc_jtfAuthorityCertSerialNumber.anchor = GridBagConstraints.WEST;

		jpAuthorityKeyIdentifier = new JPanel(new GridBagLayout());

		jpAuthorityKeyIdentifier.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpAuthorityKeyIdentifier.add(jlKeyIdentifier, gbc_jlKeyIdentifier);
		jpAuthorityKeyIdentifier.add(jkiKeyIdentifier, gbc_jkiKeyIdentifier);
		jpAuthorityKeyIdentifier.add(jlAuthorityCertIssuer, gbc_jlAuthorityCertIssuer);
		jpAuthorityKeyIdentifier.add(jgnAuthorityCertIssuer, gbc_jgnAuthorityCertIssuer);
		jpAuthorityKeyIdentifier.add(jlAuthorityCertSerialNumber, gbc_jlAuthorityCertSerialNumber);
		jpAuthorityKeyIdentifier.add(jtfAuthorityCertSerialNumber, gbc_jtfAuthorityCertSerialNumber);

		jbOK = new JButton(res.getString("DAuthorityKeyIdentifier.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DAuthorityKeyIdentifier.jbCancel.text"));
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
		getContentPane().add(jpAuthorityKeyIdentifier, BorderLayout.CENTER);
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

	private void prepopulateWithAuthorityCertDetails(X500Name authorityCertName, BigInteger authorityCertSerialNumber) {
		if (authorityCertName != null) {
			try {
				GeneralName generalName = new GeneralName(GeneralName.directoryName, authorityCertName);
				GeneralNames generalNames = new GeneralNames(generalName);

				jgnAuthorityCertIssuer.setGeneralNames(generalNames);
			} catch (Exception ex) {
				DError dError = new DError(this, ex);
				dError.setLocationRelativeTo(this);
				dError.setVisible(true);
				return;
			}
		}

		if (authorityCertSerialNumber != null) {
			jtfAuthorityCertSerialNumber.setText("" + authorityCertSerialNumber.toString());
			jtfAuthorityCertSerialNumber.setCaretPosition(0);
		}
	}

	private void prepopulateWithValue(byte[] value) throws IOException {
		AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(value);

		if (authorityKeyIdentifier.getKeyIdentifier() != null) {
			jkiKeyIdentifier.setKeyIdentifier(authorityKeyIdentifier.getKeyIdentifier());
		}

		GeneralNames authorityCertIssuer = authorityKeyIdentifier.getAuthorityCertIssuer();

		if (authorityCertIssuer != null) {
			jgnAuthorityCertIssuer.setGeneralNames(authorityCertIssuer);
		}

		BigInteger authorityCertSerialNumber = authorityKeyIdentifier.getAuthorityCertSerialNumber();

		if (authorityCertSerialNumber != null) {
			jtfAuthorityCertSerialNumber.setText("" + authorityCertSerialNumber.longValue());
			jtfAuthorityCertSerialNumber.setCaretPosition(0);
		}
	}

	private void okPressed() {
		byte[] keyIdentifier = jkiKeyIdentifier.getKeyIdentifier();
		GeneralNames authorityCertIssuer = jgnAuthorityCertIssuer.getGeneralNames();
		BigInteger authorityCertSerialNumber = null;

		String authorityCertSerialNumberStr = jtfAuthorityCertSerialNumber.getText().trim();

		if (authorityCertSerialNumberStr.length() != 0) {
			try {
				authorityCertSerialNumber = new BigInteger(authorityCertSerialNumberStr);
				if (authorityCertSerialNumber.compareTo(BigInteger.ONE) < 0) {
					JOptionPane.showMessageDialog(this,
							res.getString("DAuthorityKeyIdentifier.AuthorityCertSerialNumberNonZero.message"),
							getTitle(), JOptionPane.WARNING_MESSAGE);
					return;
				}
			} catch (NumberFormatException ex) {
				JOptionPane.showMessageDialog(this,
						res.getString("DAuthorityKeyIdentifier.AuthorityCertSerialNumberNotInteger.message"),
						getTitle(), JOptionPane.WARNING_MESSAGE);
				return;
			}
		}

		// Either key identifier or authority cert issuer and authority cert
		// serial number are required
		if ((keyIdentifier == null)
				&& ((authorityCertIssuer.getNames().length == 0) || (authorityCertSerialNumber == null))) {
			JOptionPane.showMessageDialog(this, res.getString("DAuthorityKeyIdentifier.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}


		AuthorityKeyIdentifier authorityKeyIdentifier;

		if ((keyIdentifier != null) && (authorityCertSerialNumber == null)) {

			// only key identifier
			authorityKeyIdentifier = new AuthorityKeyIdentifier(keyIdentifier);

		} else if (keyIdentifier == null) {

			// only issuer / serial
			authorityKeyIdentifier = new AuthorityKeyIdentifier(authorityCertIssuer, authorityCertSerialNumber);
		} else {

			// both
			authorityKeyIdentifier = new AuthorityKeyIdentifier(keyIdentifier, authorityCertIssuer,
					authorityCertSerialNumber);
		}

		try {
			value = authorityKeyIdentifier.getEncoded(ASN1Encoding.DER);
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
