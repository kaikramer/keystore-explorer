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
import javax.swing.Box;
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
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Netscape Certificate Type extension.
 *
 */
public class DNetscapeCertificateType extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpNetscapeCertificateType;
	private JLabel jlNetscapeCertificateType;
	private JPanel jpNetscapeCertificateTypes;
	private JCheckBox jcbObjectSigning;
	private JCheckBox jcbObjectSigningCa;
	private JCheckBox jcbReserved;
	private JCheckBox jcbSmime;
	private JCheckBox jcbSmimeCa;
	private JCheckBox jcbSslCa;
	private JCheckBox jcbSslClient;
	private JCheckBox jcbSslServer;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DNetscapeCertificateType dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DNetscapeCertificateType(JDialog parent) {
		super(parent);
		setTitle(res.getString("DNetscapeCertificateType.Title"));
		initComponents();
	}

	/**
	 * Creates a new DNetscapeCertificateType dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Netscape Certificate Type DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DNetscapeCertificateType(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DNetscapeCertificateType.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlNetscapeCertificateType = new JLabel(res.getString("DNetscapeCertificateType.jlNetscapeCertificateType.text"));
		jlNetscapeCertificateType.setBorder(new EmptyBorder(5, 5, 0, 5));

		jcbObjectSigning = new JCheckBox(res.getString("DNetscapeCertificateType.jcbObjectSigning.text"));
		jcbObjectSigningCa = new JCheckBox(res.getString("DNetscapeCertificateType.jcbObjectSigningCa.text"));
		jcbReserved = new JCheckBox(res.getString("DNetscapeCertificateType.jcbReserved.text"));
		jcbSmime = new JCheckBox(res.getString("DNetscapeCertificateType.jcbSmime.text"));
		jcbSmimeCa = new JCheckBox(res.getString("DNetscapeCertificateType.jcbSmimeCa.text"));
		jcbSslCa = new JCheckBox(res.getString("DNetscapeCertificateType.jcbSslCa.text"));
		jcbSslClient = new JCheckBox(res.getString("DNetscapeCertificateType.jcbSslClient.text"));
		jcbSslServer = new JCheckBox(res.getString("DNetscapeCertificateType.jcbSslServer.text"));

		JPanel jpFirstColumn = new JPanel();
		jpFirstColumn.setLayout(new BoxLayout(jpFirstColumn, BoxLayout.Y_AXIS));

		jpFirstColumn.add(jcbObjectSigning);
		jpFirstColumn.add(jcbObjectSigningCa);
		jpFirstColumn.add(jcbReserved);

		JPanel jpSecondColumn = new JPanel();
		jpSecondColumn.setLayout(new BoxLayout(jpSecondColumn, BoxLayout.Y_AXIS));

		jpSecondColumn.add(jcbSmime);
		jpSecondColumn.add(jcbSmimeCa);
		jpSecondColumn.add(jcbSslCa);

		JPanel jpThirdColumn = new JPanel();
		jpThirdColumn.setLayout(new BoxLayout(jpThirdColumn, BoxLayout.Y_AXIS));

		jpThirdColumn.add(jcbSslClient);
		jpThirdColumn.add(jcbSslServer);
		jpThirdColumn.add(Box.createVerticalGlue());

		jpNetscapeCertificateTypes = new JPanel();
		jpNetscapeCertificateTypes.setLayout(new BoxLayout(jpNetscapeCertificateTypes, BoxLayout.X_AXIS));

		jpNetscapeCertificateTypes.add(jpFirstColumn);
		jpNetscapeCertificateTypes.add(jpSecondColumn);
		jpNetscapeCertificateTypes.add(jpThirdColumn);

		jpNetscapeCertificateType = new JPanel(new BorderLayout(5, 5));

		jpNetscapeCertificateType.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpNetscapeCertificateType.add(jlNetscapeCertificateType, BorderLayout.NORTH);
		jpNetscapeCertificateType.add(jpNetscapeCertificateTypes, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DNetscapeCertificateType.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DNetscapeCertificateType.jbCancel.text"));
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
		getContentPane().add(jpNetscapeCertificateType, BorderLayout.CENTER);
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
		DERBitString netscapeCertType = DERBitString.getInstance(new ASN1InputStream(value).readObject());

		int netscapeCertTypes = netscapeCertType.intValue();

		jcbSslClient.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.sslClient));
		jcbSslServer.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.sslServer));
		jcbSmime.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.smime));
		jcbObjectSigning.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.objectSigning));
		jcbReserved.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.reserved));
		jcbSslCa.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.sslCA));
		jcbSmimeCa.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.smimeCA));
		jcbObjectSigningCa.setSelected(isCertType(netscapeCertTypes, NetscapeCertType.objectSigningCA));
	}

	private boolean isCertType(int netscapeCertTypes, int certType) {
		return ((netscapeCertTypes & certType) == certType);
	}

	private void okPressed() {
		if (!jcbSslClient.isSelected() && !jcbSslServer.isSelected() && !jcbSmime.isSelected()
				&& !jcbObjectSigning.isSelected() && !jcbReserved.isSelected() && !jcbSslCa.isSelected()
				&& !jcbSmimeCa.isSelected() && !jcbObjectSigningCa.isSelected()) {
			JOptionPane.showMessageDialog(this, res.getString("DNetscapeCertificateType.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		int netscapeCertTypeIntValue = 0;
		netscapeCertTypeIntValue |= jcbSslClient.isSelected() ? NetscapeCertType.sslClient : 0;
		netscapeCertTypeIntValue |= jcbSslServer.isSelected() ? NetscapeCertType.sslServer : 0;
		netscapeCertTypeIntValue |= jcbSmime.isSelected() ? NetscapeCertType.smime : 0;
		netscapeCertTypeIntValue |= jcbObjectSigning.isSelected() ? NetscapeCertType.objectSigning : 0;
		netscapeCertTypeIntValue |= jcbReserved.isSelected() ? NetscapeCertType.reserved : 0;
		netscapeCertTypeIntValue |= jcbSslCa.isSelected() ? NetscapeCertType.sslCA : 0;
		netscapeCertTypeIntValue |= jcbSmimeCa.isSelected() ? NetscapeCertType.smimeCA : 0;
		netscapeCertTypeIntValue |= jcbObjectSigningCa.isSelected() ? NetscapeCertType.objectSigningCA : 0;

		NetscapeCertType netscapeCertType = new NetscapeCertType(netscapeCertTypeIntValue);

		try {
			value = netscapeCertType.getEncoded(ASN1Encoding.DER);
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
