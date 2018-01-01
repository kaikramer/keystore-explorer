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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Key Usage extension.
 *
 */
public class DKeyUsage extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpKeyUsage;
	private JLabel jlKeyUsage;
	private JPanel jpKeyUsages;
	private JCheckBox jcbCertificateSigning;
	private JCheckBox jcbCrlSign;
	private JCheckBox jcbDataEncipherment;
	private JCheckBox jcbDecipherOnly;
	private JCheckBox jcbDigitalSignature;
	private JCheckBox jcbEncipherOnly;
	private JCheckBox jcbKeyAgreement;
	private JCheckBox jcbKeyEncipherment;
	private JCheckBox jcbNonRepudiation;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DKeyUsage dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DKeyUsage(JDialog parent) {
		super(parent);
		setTitle(res.getString("DKeyUsage.Title"));
		initComponents();
	}

	/**
	 * Creates a new DKeyUsage dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Key Usage DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DKeyUsage(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DKeyUsage.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlKeyUsage = new JLabel(res.getString("DKeyUsage.jlKeyUsage.text"));
		jlKeyUsage.setBorder(new EmptyBorder(5, 5, 0, 5));

		jcbCertificateSigning = new JCheckBox(res.getString("DKeyUsage.jcbCertificateSigning.text"));
		jcbCrlSign = new JCheckBox(res.getString("DKeyUsage.jcbCrlSign.text"));
		jcbDataEncipherment = new JCheckBox(res.getString("DKeyUsage.jcbDataEncipherment.text"));
		jcbDecipherOnly = new JCheckBox(res.getString("DKeyUsage.jcbDecipherOnly.text"));
		jcbDigitalSignature = new JCheckBox(res.getString("DKeyUsage.jcbDigitalSignature.text"));
		jcbEncipherOnly = new JCheckBox(res.getString("DKeyUsage.jcbEncipherOnly.text"));
		jcbKeyAgreement = new JCheckBox(res.getString("DKeyUsage.jcbKeyAgreement.text"));
		jcbKeyEncipherment = new JCheckBox(res.getString("DKeyUsage.jcbKeyEncipherment.text"));
		jcbNonRepudiation = new JCheckBox(res.getString("DKeyUsage.jcbNonRepudiation.text"));

		JPanel jpFirstColumn = new JPanel();
		jpFirstColumn.setLayout(new BoxLayout(jpFirstColumn, BoxLayout.Y_AXIS));

		jpFirstColumn.add(jcbCertificateSigning);
		jpFirstColumn.add(jcbCrlSign);
		jpFirstColumn.add(jcbDataEncipherment);

		JPanel jpSecondColumn = new JPanel();
		jpSecondColumn.setLayout(new BoxLayout(jpSecondColumn, BoxLayout.Y_AXIS));

		jpSecondColumn.add(jcbDecipherOnly);
		jpSecondColumn.add(jcbDigitalSignature);
		jpSecondColumn.add(jcbEncipherOnly);

		JPanel jpThirdColumn = new JPanel();
		jpThirdColumn.setLayout(new BoxLayout(jpThirdColumn, BoxLayout.Y_AXIS));

		jpThirdColumn.add(jcbKeyAgreement);
		jpThirdColumn.add(jcbKeyEncipherment);
		jpThirdColumn.add(jcbNonRepudiation);

		jpKeyUsages = new JPanel();
		jpKeyUsages.setLayout(new BoxLayout(jpKeyUsages, BoxLayout.X_AXIS));

		jpKeyUsages.add(jpFirstColumn);
		jpKeyUsages.add(jpSecondColumn);
		jpKeyUsages.add(jpThirdColumn);

		jpKeyUsage = new JPanel(new BorderLayout(5, 5));

		jpKeyUsage.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpKeyUsage.add(jlKeyUsage, BorderLayout.NORTH);
		jpKeyUsage.add(jpKeyUsages, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DKeyUsage.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DKeyUsage.jbCancel.text"));
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
		getContentPane().add(jpKeyUsage, BorderLayout.CENTER);
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
		@SuppressWarnings("resource") // we have a ByteArrayInputStream here which does not need to be closed
		DERBitString keyUsage = DERBitString.getInstance(new ASN1InputStream(value).readObject());

		int keyUsageValue = keyUsage.intValue();

		jcbDigitalSignature.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.digitalSignature));
		jcbNonRepudiation.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.nonRepudiation));
		jcbKeyEncipherment.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.keyEncipherment));
		jcbDataEncipherment.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.dataEncipherment));
		jcbKeyAgreement.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.keyAgreement));
		jcbCertificateSigning.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.keyCertSign));
		jcbCrlSign.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.cRLSign));
		jcbEncipherOnly.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.encipherOnly));
		jcbDecipherOnly.setSelected(hasKeyUsage(keyUsageValue, KeyUsage.decipherOnly));
	}

	private boolean hasKeyUsage(int keyUsages, int keyusage) {
		return ((keyUsages & keyusage) == keyusage);
	}

	private void okPressed() {
		if (!jcbDigitalSignature.isSelected() && !jcbNonRepudiation.isSelected() && !jcbKeyEncipherment.isSelected()
				&& !jcbDataEncipherment.isSelected() && !jcbKeyAgreement.isSelected()
				&& !jcbCertificateSigning.isSelected() && !jcbCrlSign.isSelected() && !jcbEncipherOnly.isSelected()
				&& !jcbDecipherOnly.isSelected()) {
			JOptionPane.showMessageDialog(this, res.getString("DKeyUsage.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		int keyUsageIntValue = 0;
		keyUsageIntValue |= jcbDigitalSignature.isSelected() ? KeyUsage.digitalSignature : 0;
		keyUsageIntValue |= jcbNonRepudiation.isSelected() ? KeyUsage.nonRepudiation : 0;
		keyUsageIntValue |= jcbKeyEncipherment.isSelected() ? KeyUsage.keyEncipherment : 0;
		keyUsageIntValue |= jcbDataEncipherment.isSelected() ? KeyUsage.dataEncipherment : 0;
		keyUsageIntValue |= jcbKeyAgreement.isSelected() ? KeyUsage.keyAgreement : 0;
		keyUsageIntValue |= jcbCertificateSigning.isSelected() ? KeyUsage.keyCertSign : 0;
		keyUsageIntValue |= jcbCrlSign.isSelected() ? KeyUsage.cRLSign : 0;
		keyUsageIntValue |= jcbEncipherOnly.isSelected() ? KeyUsage.encipherOnly : 0;
		keyUsageIntValue |= jcbDecipherOnly.isSelected() ? KeyUsage.decipherOnly : 0;

		KeyUsage keyUsage = new KeyUsage(keyUsageIntValue);

		try {
			value = keyUsage.getEncoded(ASN1Encoding.DER);
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
