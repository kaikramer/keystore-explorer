/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs.extensions;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.CLIENT_AUTH;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.CODE_SIGNING;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.EMAIL_PROTECTION;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.IPSEC_END_SYSTEM;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.IPSEC_TUNNEL;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.IPSEC_USER;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.OCSP_SIGNING;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.SERVER_AUTH;
import static net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType.TIME_STAMPING;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ArrayList;
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

import net.sf.keystore_explorer.crypto.x509.ExtendedKeyUsageType;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.error.DError;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * Dialog used to add or edit an Extended Key Usage extension.
 * 
 */
public class DExtendedKeyUsage extends DExtension {
	private static ResourceBundle res = ResourceBundle
			.getBundle("net/sf/keystore_explorer/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpExtendedKeyUsage;
	private JLabel jlExtendedKeyUsage;
	private JPanel jpExtendedKeyUsages;
	private JCheckBox jcbCodeSigning;
	private JCheckBox jcbEmailProtection;
	private JCheckBox jcbIpSecurityEndSystem;
	private JCheckBox jcbIpSecurityTunnelTermination;
	private JCheckBox jcbIpSecurityUser;
	private JCheckBox jcbOcspStamping;
	private JCheckBox jcbTimeStamping;
	private JCheckBox jcbTlsWebClientAuthentication;
	private JCheckBox jcbTlsWebServerAuthentication;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DExtendedKeyUsage dialog.
	 * 
	 * @param parent
	 *            The parent dialog
	 */
	public DExtendedKeyUsage(JDialog parent) {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		setTitle(res.getString("DExtendedKeyUsage.Title"));
		initComponents();
	}

	/**
	 * Creates a new DExtendedKeyUsage dialog.
	 * 
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Extended Key Usage DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DExtendedKeyUsage(JDialog parent, byte[] value) throws IOException {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		setTitle(res.getString("DExtendedKeyUsage.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlExtendedKeyUsage = new JLabel(res.getString("DExtendedKeyUsage.jlExtendedKeyUsage.text"));
		jlExtendedKeyUsage.setBorder(new EmptyBorder(5, 5, 0, 5));

		jcbCodeSigning = new JCheckBox(res.getString("DExtendedKeyUsage.jcbCodeSigning.text"));
		jcbEmailProtection = new JCheckBox(res.getString("DExtendedKeyUsage.jcbEmailProtection.text"));
		jcbIpSecurityEndSystem = new JCheckBox(res.getString("DExtendedKeyUsage.jcbIpSecurityEndSystem.text"));
		jcbIpSecurityTunnelTermination = new JCheckBox(
				res.getString("DExtendedKeyUsage.jcbIpSecurityTunnelTermination.text"));
		jcbIpSecurityUser = new JCheckBox(res.getString("DExtendedKeyUsage.jcbIpSecurityUser.text"));
		jcbOcspStamping = new JCheckBox(res.getString("DExtendedKeyUsage.jcbOcspStamping.text"));
		jcbTimeStamping = new JCheckBox(res.getString("DExtendedKeyUsage.jcbTimeStamping.text"));
		jcbTlsWebClientAuthentication = new JCheckBox(
				res.getString("DExtendedKeyUsage.jcbTlsWebClientAuthentication.text"));
		jcbTlsWebServerAuthentication = new JCheckBox(
				res.getString("DExtendedKeyUsage.jcbTlsWebServerAuthentication.text"));

		JPanel jpFirstColumn = new JPanel();
		jpFirstColumn.setLayout(new BoxLayout(jpFirstColumn, BoxLayout.Y_AXIS));

		jpFirstColumn.add(jcbCodeSigning);
		jpFirstColumn.add(jcbEmailProtection);
		jpFirstColumn.add(jcbIpSecurityEndSystem);

		JPanel jpSecondColumn = new JPanel();
		jpSecondColumn.setLayout(new BoxLayout(jpSecondColumn, BoxLayout.Y_AXIS));

		jpSecondColumn.add(jcbIpSecurityTunnelTermination);
		jpSecondColumn.add(jcbIpSecurityUser);
		jpSecondColumn.add(jcbOcspStamping);

		JPanel jpThirdColumn = new JPanel();
		jpThirdColumn.setLayout(new BoxLayout(jpThirdColumn, BoxLayout.Y_AXIS));

		jpThirdColumn.add(jcbTimeStamping);
		jpThirdColumn.add(jcbTlsWebClientAuthentication);
		jpThirdColumn.add(jcbTlsWebServerAuthentication);

		jpExtendedKeyUsages = new JPanel();
		jpExtendedKeyUsages.setLayout(new BoxLayout(jpExtendedKeyUsages, BoxLayout.X_AXIS));

		jpExtendedKeyUsages.add(jpFirstColumn);
		jpExtendedKeyUsages.add(jpSecondColumn);
		jpExtendedKeyUsages.add(jpThirdColumn);

		jpExtendedKeyUsage = new JPanel(new BorderLayout(5, 5));

		jpExtendedKeyUsage.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpExtendedKeyUsage.add(jlExtendedKeyUsage, BorderLayout.NORTH);
		jpExtendedKeyUsage.add(jpExtendedKeyUsages, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DExtendedKeyUsage.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DExtendedKeyUsage.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpExtendedKeyUsage, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void prepopulateWithValue(byte[] value) throws IOException {
		ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(value);

		for (KeyPurposeId keyPurposeId : extendedKeyUsage.getUsages()) {
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) keyPurposeId.toASN1Primitive();

			ExtendedKeyUsageType type = ExtendedKeyUsageType.resolveOid(oid.getId());

			if (type == SERVER_AUTH) {
				jcbTlsWebServerAuthentication.setSelected(true);
			} else if (type == CLIENT_AUTH) {
				jcbTlsWebClientAuthentication.setSelected(true);
			} else if (type == CODE_SIGNING) {
				jcbCodeSigning.setSelected(true);
			} else if (type == EMAIL_PROTECTION) {
				jcbEmailProtection.setSelected(true);
			} else if (type == IPSEC_END_SYSTEM) {
				jcbIpSecurityEndSystem.setSelected(true);
			} else if (type == IPSEC_TUNNEL) {
				jcbIpSecurityTunnelTermination.setSelected(true);
			} else if (type == IPSEC_USER) {
				jcbIpSecurityUser.setSelected(true);
			} else if (type == TIME_STAMPING) {
				jcbTimeStamping.setSelected(true);
			} else if (type == OCSP_SIGNING) {
				jcbOcspStamping.setSelected(true);
			}
		}
	}

	private void okPressed() {
		if (!jcbTlsWebServerAuthentication.isSelected() && !jcbTlsWebClientAuthentication.isSelected()
				&& !jcbCodeSigning.isSelected() && !jcbEmailProtection.isSelected()
				&& !jcbIpSecurityEndSystem.isSelected() && !jcbIpSecurityTunnelTermination.isSelected()
				&& !jcbIpSecurityUser.isSelected() && !jcbTimeStamping.isSelected() && !jcbOcspStamping.isSelected()) {
			JOptionPane.showMessageDialog(this, res.getString("DExtendedKeyUsage.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		ArrayList<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();

		if (jcbTlsWebServerAuthentication.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(SERVER_AUTH.oid())));
		}

		if (jcbTlsWebClientAuthentication.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(CLIENT_AUTH.oid())));
		}

		if (jcbCodeSigning.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(CODE_SIGNING.oid())));
		}

		if (jcbEmailProtection.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(EMAIL_PROTECTION.oid())));
		}

		if (jcbIpSecurityEndSystem.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IPSEC_END_SYSTEM.oid())));
		}

		if (jcbIpSecurityTunnelTermination.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IPSEC_TUNNEL.oid())));
		}

		if (jcbIpSecurityUser.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(IPSEC_USER.oid())));
		}

		if (jcbTimeStamping.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(TIME_STAMPING.oid())));
		}

		if (jcbOcspStamping.isSelected()) {
			keyPurposeIds.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(OCSP_SIGNING.oid())));
		}

		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
				keyPurposeIds.toArray(new KeyPurposeId[keyPurposeIds.size()]));

		try {
			value = extendedKeyUsage.getEncoded(ASN1Encoding.DER);
		} catch (IOException ex) {
			DError dError = new DError(this, APPLICATION_MODAL, ex);
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
