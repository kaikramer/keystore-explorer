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
package org.kse.gui.crypto.generalname;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Security;
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
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UIManager;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.IPAddress;
import org.kse.crypto.x509.GeneralNameUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.error.DError;
import org.kse.gui.oid.JObjectId;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to choose a general name.
 *
 */
public class DGeneralNameChooser extends JEscDialog {

	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/generalname/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlGeneralNameType;
	private JRadioButton jrbDirectoryName;
	private JRadioButton jrbDnsName;
	private JRadioButton jrbIpAddress;
	private JRadioButton jrbRegisteredId;
	private JRadioButton jrbRfc822Name;
	private JRadioButton jrbUniformResourceIdentifier;
	private JRadioButton jrbPrincipalName;
	private JPanel jpGeneralNameValue;
	private JLabel jlGeneralNameValue;
	private JDistinguishedName jdnDirectoryName;
	private JTextField jtfDnsName;
	private JTextField jtfIpAddress;
	private JObjectId joiRegisteredId;
	private JTextField jtfRfc822Name;
	private JTextField jtfUniformResourceIdentifier;
	private JTextField jtfPrincipalName;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private GeneralName generalName;

	/**
	 * Constructs a new DGeneralNameChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param generalName
	 *            General name
	 */
	public DGeneralNameChooser(JFrame parent, String title, GeneralName generalName) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(generalName);
	}

	/**
	 * Constructs a new DGeneralNameChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param generalName
	 *            General name
	 */
	public DGeneralNameChooser(JDialog parent, String title, GeneralName generalName) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(generalName);
	}

	private void initComponents(GeneralName generalName) {

		jrbDirectoryName = new JRadioButton(res.getString("DGeneralNameChooser.jrbDirectoryName.text"));
		jrbDirectoryName.setToolTipText(res.getString("DGeneralNameChooser.jrbDirectoryName.tooltip"));

		jrbDnsName = new JRadioButton(res.getString("DGeneralNameChooser.jrbDnsName.text"));
		jrbDnsName.setToolTipText(res.getString("DGeneralNameChooser.jrbDnsName.tooltip"));

		jrbIpAddress = new JRadioButton(res.getString("DGeneralNameChooser.jrbIpAddress.text"));
		jrbIpAddress.setToolTipText(res.getString("DGeneralNameChooser.jrbIpAddress.tooltip"));

		jrbRegisteredId = new JRadioButton(res.getString("DGeneralNameChooser.jrbRegisteredId.text"));
		jrbRegisteredId.setToolTipText(res.getString("DGeneralNameChooser.jrbRegisteredId.tooltip"));

		jrbRfc822Name = new JRadioButton(res.getString("DGeneralNameChooser.jrbRfc822Name.text"));
		jrbRfc822Name.setToolTipText(res.getString("DGeneralNameChooser.jrbRfc822Name.tooltip"));

		jrbUniformResourceIdentifier = new JRadioButton(
				res.getString("DGeneralNameChooser.jrbUniformResourceIdentifier.text"));
		jrbUniformResourceIdentifier
		.setToolTipText(res.getString("DGeneralNameChooser.jrbUniformResourceIdentifier.tooltip"));

		jrbPrincipalName = new JRadioButton(res.getString("DGeneralNameChooser.jrbPrincipalName.text"));
		jrbPrincipalName.setToolTipText(res.getString("DGeneralNameChooser.jrbPrincipalName.tooltip"));

		ButtonGroup bgGeneralName = new ButtonGroup();
		bgGeneralName.add(jrbDirectoryName);
		bgGeneralName.add(jrbDnsName);
		bgGeneralName.add(jrbIpAddress);
		bgGeneralName.add(jrbRegisteredId);
		bgGeneralName.add(jrbRfc822Name);
		bgGeneralName.add(jrbUniformResourceIdentifier);
		bgGeneralName.add(jrbPrincipalName);

		jlGeneralNameType = new JLabel(res.getString("DGeneralNameChooser.jlGeneralNameType.text"));
		jlGeneralNameValue = new JLabel(res.getString("DGeneralNameChooser.jlGeneralNameValue.text"));
		jpGeneralNameValue = new JPanel(new FlowLayout(FlowLayout.LEFT));

		jdnDirectoryName = new JDistinguishedName(res.getString("DGeneralNameChooser.DirectoryName.Title"), 20, true);
		jtfDnsName = new JTextField(30);
		jtfIpAddress = new JTextField(30);
		joiRegisteredId = new JObjectId(res.getString("DGeneralNameChooser.RegisteredId.Title"));
		jtfRfc822Name = new JTextField(30);
		jtfUniformResourceIdentifier = new JTextField(30);
		jtfPrincipalName = new JTextField(30);

		jbOK = new JButton(res.getString("DGeneralNameChooser.jbOK.text"));
		jbCancel = new JButton(res.getString("DGeneralNameChooser.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[]rel[]", ""));
		pane.add(jlGeneralNameType, "spanx, wrap");
		pane.add(jrbDirectoryName, "");
		pane.add(jrbDnsName, "");
		pane.add(jrbIpAddress, "");
		pane.add(jrbRegisteredId, "wrap");
		pane.add(jrbRfc822Name, "");
		pane.add(jrbUniformResourceIdentifier, "");
		pane.add(jrbPrincipalName, "wrap");
		pane.add(jlGeneralNameValue, "spanx");
		pane.add(jpGeneralNameValue, "spanx, wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap para");
		pane.add(jpButtons, "right, spanx");

		// actions
		jrbDirectoryName.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jrbDnsName.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jrbRegisteredId.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jrbIpAddress.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jrbRfc822Name.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jrbUniformResourceIdentifier.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jrbPrincipalName.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});
		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		populate(generalName);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void generalNameTypeChanged() {
		jpGeneralNameValue.removeAll();

		jpGeneralNameValue.add(jlGeneralNameValue);

		if (jrbDirectoryName.isSelected()) {
			jpGeneralNameValue.add(jdnDirectoryName);
		} else if (jrbDnsName.isSelected()) {
			jpGeneralNameValue.add(jtfDnsName);
		} else if (jrbIpAddress.isSelected()) {
			jpGeneralNameValue.add(jtfIpAddress);
		} else if (jrbRegisteredId.isSelected()) {
			jpGeneralNameValue.add(joiRegisteredId);
		} else if (jrbRfc822Name.isSelected()) {
			jpGeneralNameValue.add(jtfRfc822Name);
		} else if (jrbUniformResourceIdentifier.isSelected()) {
			jpGeneralNameValue.add(jtfUniformResourceIdentifier);
		}  else if (jrbPrincipalName.isSelected()) {
			jpGeneralNameValue.add(jtfPrincipalName);
		}

		pack();
	}

	private void populate(GeneralName generalName) {
		if (generalName == null) {
			jrbDirectoryName.setSelected(true);
		} else {
			switch (generalName.getTagNo()) {
			case GeneralName.directoryName: {
				jrbDirectoryName.setSelected(true);
				jdnDirectoryName.setDistinguishedName((X500Name) generalName.getName());
				break;
			}
			case GeneralName.dNSName: {
				jrbDnsName.setSelected(true);
				jtfDnsName.setText(((DERIA5String) generalName.getName()).getString());
				break;
			}
			case GeneralName.iPAddress: {
				jrbIpAddress.setSelected(true);
				byte[] ipAddressBytes = ((ASN1OctetString) generalName.getName()).getOctets();
				try {
					jtfIpAddress.setText(InetAddress.getByAddress(ipAddressBytes).getHostAddress());
				} catch (UnknownHostException e) {
					// cannot happen here because user input was checked for validity
				}
				break;
			}
			case GeneralName.registeredID: {
				jrbRegisteredId.setSelected(true);
				joiRegisteredId.setObjectId((ASN1ObjectIdentifier) generalName.getName());
				break;
			}
			case GeneralName.rfc822Name: {
				jrbRfc822Name.setSelected(true);
				jtfRfc822Name.setText(((DERIA5String) generalName.getName()).getString());
				break;
			}
			case GeneralName.uniformResourceIdentifier: {
				jrbUniformResourceIdentifier.setSelected(true);
				jtfUniformResourceIdentifier.setText(((DERIA5String) generalName.getName()).getString());
				break;
			}
			case GeneralName.otherName: {
				jrbPrincipalName.setSelected(true);
				// we currently only support UPN in otherName
				jtfPrincipalName.setText(GeneralNameUtil.parseUPN(generalName));
				break;
			}
			}
		}
	}

	/**
	 * Get selected general name.
	 *
	 * @return General name, or null if none
	 */
	public GeneralName getGeneralName() {
		return generalName;
	}

	private void okPressed() {
		try {
			GeneralName newGeneralName = null;

			if (jrbDirectoryName.isSelected()) {
				X500Name directoryName = jdnDirectoryName.getDistinguishedName();

				if (directoryName == null) {
					JOptionPane.showMessageDialog(this,
							res.getString("DGeneralNameChooser.DirectoryNameValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				newGeneralName = new GeneralName(GeneralName.directoryName, directoryName);
			} else if (jrbDnsName.isSelected()) {
				String dnsName = jtfDnsName.getText().trim();

				if (dnsName.length() == 0) {
					JOptionPane.showMessageDialog(this, res.getString("DGeneralNameChooser.DnsNameValueReq.message"),
							getTitle(), JOptionPane.WARNING_MESSAGE);
					return;
				}

				newGeneralName = new GeneralName(GeneralName.dNSName, new DERIA5String(dnsName));
			} else if (jrbIpAddress.isSelected()) {

				String ipAddress = jtfIpAddress.getText().trim();

				if (ipAddress.length() == 0) {
					JOptionPane.showMessageDialog(this, res.getString("DGeneralNameChooser.IpAddressValueReq.message"),
							getTitle(), JOptionPane.WARNING_MESSAGE);
					return;
				}

				if (!IPAddress.isValid(ipAddress)) {
					JOptionPane.showMessageDialog(this, res.getString("DGeneralNameChooser.NotAValidIP.message"),
							getTitle(), JOptionPane.WARNING_MESSAGE);
					return;
				}

				newGeneralName = new GeneralName(GeneralName.iPAddress,	ipAddress);
			} else if (jrbRegisteredId.isSelected()) {
				ASN1ObjectIdentifier registeredId = joiRegisteredId.getObjectId();

				if (registeredId == null) {
					JOptionPane.showMessageDialog(this,
							res.getString("DGeneralNameChooser.RegisteredIdValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				newGeneralName = new GeneralName(GeneralName.registeredID, registeredId);
			} else if (jrbRfc822Name.isSelected()) {
				String rfc822Name = jtfRfc822Name.getText().trim();

				if (rfc822Name.length() == 0) {
					JOptionPane.showMessageDialog(this,
							res.getString("DGeneralNameChooser.Rfc822NameValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				newGeneralName = new GeneralName(GeneralName.rfc822Name, new DERIA5String(rfc822Name));
			} else if (jrbUniformResourceIdentifier.isSelected()) {
				String uniformResourceIdentifier = jtfUniformResourceIdentifier.getText().trim();

				if (uniformResourceIdentifier.length() == 0) {
					JOptionPane.showMessageDialog(this,
							res.getString("DGeneralNameChooser.UniformResourceIdentifierValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				newGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(
						uniformResourceIdentifier));
			} else if (jrbPrincipalName.isSelected()) {
				String upnString = jtfPrincipalName.getText().trim();

				if (upnString.length() == 0) {
					JOptionPane.showMessageDialog(this,
							res.getString("DGeneralNameChooser.PrincipalNameValueReq.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}

				ASN1EncodableVector asn1Vector = new ASN1EncodableVector();
				asn1Vector.add(new ASN1ObjectIdentifier(GeneralNameUtil.UPN_OID));
				asn1Vector.add(new DERTaggedObject(true, 0, new DERUTF8String(upnString)));

				newGeneralName = new GeneralName(GeneralName.otherName, new DERSequence(asn1Vector));
			}

			generalName = newGeneralName;
		} catch (Exception ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
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

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					DGeneralNameChooser dialog = new DGeneralNameChooser(new javax.swing.JFrame(), "GeneralNameChooser",
							null);
					dialog.addWindowListener(new java.awt.event.WindowAdapter() {
						@Override
						public void windowClosing(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
						@Override
						public void windowDeactivated(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}
