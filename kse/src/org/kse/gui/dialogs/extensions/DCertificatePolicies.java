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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.policyinformation.JPolicyInformation;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Certificate Policies extension.
 *
 */
public class DCertificatePolicies extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpCertificatePolicies;
	private JLabel jlCertificatePolicies;
	private JPolicyInformation jpiCertificatePolicies;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DCertificatePolicies dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DCertificatePolicies(JDialog parent) {
		super(parent);

		setTitle(res.getString("DCertificatePolicies.Title"));
		initComponents();
	}

	/**
	 * Creates a new DCertificatePolicies dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Certificate Policies DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DCertificatePolicies(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DCertificatePolicies.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlCertificatePolicies = new JLabel(res.getString("DCertificatePolicies.jlCertificatePolicies.text"));

		GridBagConstraints gbc_jlCertificatePolicies = new GridBagConstraints();
		gbc_jlCertificatePolicies.gridx = 0;
		gbc_jlCertificatePolicies.gridy = 1;
		gbc_jlCertificatePolicies.gridwidth = 1;
		gbc_jlCertificatePolicies.gridheight = 1;
		gbc_jlCertificatePolicies.insets = new Insets(5, 5, 5, 5);
		gbc_jlCertificatePolicies.anchor = GridBagConstraints.NORTHEAST;

		jpiCertificatePolicies = new JPolicyInformation(res.getString("DCertificatePolicies.PolicyInformation.Title"));
		jpiCertificatePolicies.setPreferredSize(new Dimension(400, 150));

		GridBagConstraints gbc_jpiCertificatePolicies = new GridBagConstraints();
		gbc_jpiCertificatePolicies.gridx = 1;
		gbc_jpiCertificatePolicies.gridy = 1;
		gbc_jpiCertificatePolicies.gridwidth = 1;
		gbc_jpiCertificatePolicies.gridheight = 1;
		gbc_jpiCertificatePolicies.insets = new Insets(5, 5, 5, 5);
		gbc_jpiCertificatePolicies.anchor = GridBagConstraints.WEST;

		jpCertificatePolicies = new JPanel(new GridBagLayout());

		jpCertificatePolicies.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpCertificatePolicies.add(jlCertificatePolicies, gbc_jlCertificatePolicies);
		jpCertificatePolicies.add(jpiCertificatePolicies, gbc_jpiCertificatePolicies);

		jbOK = new JButton(res.getString("DCertificatePolicies.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DCertificatePolicies.jbCancel.text"));
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
		getContentPane().add(jpCertificatePolicies, BorderLayout.CENTER);
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
		CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

		List<PolicyInformation> accessDescriptionList =
				new ArrayList<PolicyInformation>(Arrays.asList(certificatePolicies.getPolicyInformation()));

		jpiCertificatePolicies.setPolicyInformation(accessDescriptionList);
	}

	private void okPressed() {
		List<PolicyInformation> policyInformation = jpiCertificatePolicies.getPolicyInformation();

		if (policyInformation.size() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DCertificatePolicies.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}



		CertificatePolicies certificatePolicies = new CertificatePolicies(policyInformation.toArray(
				new PolicyInformation[policyInformation.size()]));

		try {
			value = certificatePolicies.getEncoded(ASN1Encoding.DER);
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
