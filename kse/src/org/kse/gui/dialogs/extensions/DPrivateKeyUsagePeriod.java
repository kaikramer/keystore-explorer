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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
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
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.kse.gui.PlatformUtil;
import org.kse.gui.datetime.JDateTime;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Private Key Usage Period extension.
 *
 */
public class DPrivateKeyUsagePeriod extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPrivateKeyUsagePeriod;
	private JLabel jlNotBefore;
	private JDateTime jdtNotBefore;
	private JLabel jlNotAfter;
	private JDateTime jdtNotAfter;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DPrivateKeyUsagePeriod dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DPrivateKeyUsagePeriod(JDialog parent) {
		super(parent);
		setTitle(res.getString("DPrivateKeyUsagePeriod.Title"));
		initComponents();
	}

	/**
	 * Creates a new DPrivateKeyUsagePeriod dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Private Key Usage Period Constraints DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DPrivateKeyUsagePeriod(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DPrivateKeyUsagePeriod.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlNotBefore = new JLabel(res.getString("DPrivateKeyUsagePeriod.jlNotBefore.text"));

		GridBagConstraints gbc_jlNotBefore = new GridBagConstraints();
		gbc_jlNotBefore.gridx = 0;
		gbc_jlNotBefore.gridy = 0;
		gbc_jlNotBefore.gridwidth = 1;
		gbc_jlNotBefore.gridheight = 1;
		gbc_jlNotBefore.insets = new Insets(5, 5, 5, 5);
		gbc_jlNotBefore.anchor = GridBagConstraints.EAST;

		jdtNotBefore = new JDateTime(res.getString("DPrivateKeyUsagePeriod.jdtNotBefore.text"));
		jdtNotBefore.setToolTipText(res.getString("DPrivateKeyUsagePeriod.jdtNotBefore.tooltip"));

		GridBagConstraints gbc_jdtNotBefore = new GridBagConstraints();
		gbc_jdtNotBefore.gridx = 1;
		gbc_jdtNotBefore.gridy = 0;
		gbc_jdtNotBefore.gridwidth = 1;
		gbc_jdtNotBefore.gridheight = 1;
		gbc_jdtNotBefore.insets = new Insets(5, 5, 5, 5);
		gbc_jdtNotBefore.anchor = GridBagConstraints.WEST;

		jlNotAfter = new JLabel(res.getString("DPrivateKeyUsagePeriod.jlNotAfter.text"));

		GridBagConstraints gbc_jlNotAfter = new GridBagConstraints();
		gbc_jlNotAfter.gridx = 0;
		gbc_jlNotAfter.gridy = 1;
		gbc_jlNotAfter.gridwidth = 1;
		gbc_jlNotAfter.gridheight = 1;
		gbc_jlNotAfter.insets = new Insets(5, 5, 5, 5);
		gbc_jlNotAfter.anchor = GridBagConstraints.EAST;

		jdtNotAfter = new JDateTime(res.getString("DPrivateKeyUsagePeriod.jdtNotAfter.text"));
		jdtNotAfter.setToolTipText(res.getString("DPrivateKeyUsagePeriod.jdtNotAfter.tooltip"));

		GridBagConstraints gbc_jdtNotAfter = new GridBagConstraints();
		gbc_jdtNotAfter.gridx = 1;
		gbc_jdtNotAfter.gridy = 1;
		gbc_jdtNotAfter.gridwidth = 1;
		gbc_jdtNotAfter.gridheight = 1;
		gbc_jdtNotAfter.insets = new Insets(5, 5, 5, 5);
		gbc_jdtNotAfter.anchor = GridBagConstraints.WEST;

		jpPrivateKeyUsagePeriod = new JPanel(new FlowLayout());

		jpPrivateKeyUsagePeriod.add(jlNotBefore);
		jpPrivateKeyUsagePeriod.add(jdtNotBefore);
		jpPrivateKeyUsagePeriod.add(jlNotAfter);
		jpPrivateKeyUsagePeriod.add(jdtNotAfter);

		jpPrivateKeyUsagePeriod = new JPanel(new GridBagLayout());
		jpPrivateKeyUsagePeriod.add(jlNotBefore, gbc_jlNotBefore);
		jpPrivateKeyUsagePeriod.add(jdtNotBefore, gbc_jdtNotBefore);
		jpPrivateKeyUsagePeriod.add(jlNotAfter, gbc_jlNotAfter);
		jpPrivateKeyUsagePeriod.add(jdtNotAfter, gbc_jdtNotAfter);
		jpPrivateKeyUsagePeriod.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jbOK = new JButton(res.getString("DPrivateKeyUsagePeriod.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DPrivateKeyUsagePeriod.jbCancel.text"));
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
		getContentPane().add(jpPrivateKeyUsagePeriod, BorderLayout.CENTER);
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
		PrivateKeyUsagePeriod privateKeyUsagePeriod = PrivateKeyUsagePeriod.getInstance(value);

		ASN1GeneralizedTime notBefore = privateKeyUsagePeriod.getNotBefore();

		if (notBefore != null) {
			try {
				jdtNotBefore.setDateTime(notBefore.getDate());
			} catch (ParseException e) {
				throw new IOException(e);
			}
		}

		ASN1GeneralizedTime notAfter = privateKeyUsagePeriod.getNotAfter();

		if (notAfter != null) {
			try {
				jdtNotAfter.setDateTime(notAfter.getDate());
			} catch (ParseException e) {
				throw new IOException(e);
			}
		}
	}

	private void okPressed() {

		Date notBefore = jdtNotBefore.getDateTime();
		Date notAfter = jdtNotAfter.getDateTime();

		if ((notBefore == null) && (notAfter == null)) {
			JOptionPane.showMessageDialog(this, res.getString("DPrivateKeyUsagePeriod.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		// BC forgot the value constructor for PrivateKeyUsagePeriod...
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (notBefore != null) {
			DERGeneralizedTime notBeforeGenTime = new DERGeneralizedTime(notBefore);
			v.add(new DERTaggedObject(false, 0, notBeforeGenTime));
		}
		if (notAfter != null) {
			DERGeneralizedTime notAfterGenTime = new DERGeneralizedTime(notAfter);
			v.add(new DERTaggedObject(false, 1, notAfterGenTime));
		}

		PrivateKeyUsagePeriod privateKeyUsagePeriod = PrivateKeyUsagePeriod.getInstance(new DERSequence(v));

		try {
			value = privateKeyUsagePeriod.getEncoded(ASN1Encoding.DER);
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
