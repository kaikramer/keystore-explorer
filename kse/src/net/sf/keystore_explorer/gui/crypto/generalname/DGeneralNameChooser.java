/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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
package net.sf.keystore_explorer.gui.crypto.generalname;

import static java.awt.Dialog.ModalityType.DOCUMENT_MODAL;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dialog.ModalityType;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.BoxLayout;
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

import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.crypto.JDistinguishedName;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.gui.net.JIpAddress;
import net.sf.keystore_explorer.gui.oid.JObjectId;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Dialog to choose a general name.
 * 
 */
public class DGeneralNameChooser extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/crypto/generalname/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpGeneralName;
	private JPanel jpGeneralNameType;
	private JLabel jlGeneralNameType;
	private JPanel jpGeneralNameTypes;
	private JRadioButton jrbDirectoryName;
	private JRadioButton jrbDnsName;
	private JRadioButton jrbIpAddress;
	private JRadioButton jrbRegisteredId;
	private JRadioButton jrbRfc822Name;
	private JRadioButton jrbUniformResourceIdentifier;
	private JPanel jpGeneralNameValue;
	private JLabel jlGeneralNameValue;
	private JDistinguishedName jdnDirectoryName;
	private JTextField jtfDnsName;
	private JIpAddress jipaIpAddress;
	private JObjectId joiRegisteredId;
	private JTextField jtfRfc822Name;
	private JTextField jtfUniformResourceIdentifier;
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
		jrbDirectoryName.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});

		jrbDnsName = new JRadioButton(res.getString("DGeneralNameChooser.jrbDnsName.text"));
		jrbDnsName.setToolTipText(res.getString("DGeneralNameChooser.jrbDnsName.tooltip"));
		jrbDnsName.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});

		jrbIpAddress = new JRadioButton(res.getString("DGeneralNameChooser.jrbIpAddress.text"));
		jrbIpAddress.setToolTipText(res.getString("DGeneralNameChooser.jrbIpAddress.tooltip"));
		jrbIpAddress.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});

		jrbRegisteredId = new JRadioButton(res.getString("DGeneralNameChooser.jrbRegisteredId.text"));
		jrbRegisteredId.setToolTipText(res.getString("DGeneralNameChooser.jrbRegisteredId.tooltip"));
		jrbRegisteredId.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});

		jrbRfc822Name = new JRadioButton(res.getString("DGeneralNameChooser.jrbRfc822Name.text"));
		jrbRfc822Name.setToolTipText(res.getString("DGeneralNameChooser.jrbRfc822Name.tooltip"));
		jrbRfc822Name.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});

		jrbUniformResourceIdentifier = new JRadioButton(
				res.getString("DGeneralNameChooser.jrbUniformResourceIdentifier.text"));
		jrbUniformResourceIdentifier.setToolTipText(res
				.getString("DGeneralNameChooser.jrbUniformResourceIdentifier.tooltip"));
		jrbUniformResourceIdentifier.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				generalNameTypeChanged();
			}
		});

		ButtonGroup bgGeneralName = new ButtonGroup();
		bgGeneralName.add(jrbDirectoryName);
		bgGeneralName.add(jrbDnsName);
		bgGeneralName.add(jrbIpAddress);
		bgGeneralName.add(jrbRegisteredId);
		bgGeneralName.add(jrbRfc822Name);
		bgGeneralName.add(jrbUniformResourceIdentifier);

		JPanel jpFirstColumn = new JPanel();
		jpFirstColumn.setLayout(new BoxLayout(jpFirstColumn, BoxLayout.Y_AXIS));

		jpFirstColumn.add(jrbDirectoryName);
		jpFirstColumn.add(jrbDnsName);

		JPanel jpSecondColumn = new JPanel();
		jpSecondColumn.setLayout(new BoxLayout(jpSecondColumn, BoxLayout.Y_AXIS));

		jpSecondColumn.add(jrbIpAddress);
		jpSecondColumn.add(jrbRegisteredId);

		JPanel jpThirdColumn = new JPanel();
		jpThirdColumn.setLayout(new BoxLayout(jpThirdColumn, BoxLayout.Y_AXIS));

		jpThirdColumn.add(jrbRfc822Name);
		jpThirdColumn.add(jrbUniformResourceIdentifier);

		jpGeneralNameTypes = new JPanel();
		jpGeneralNameTypes.setLayout(new BoxLayout(jpGeneralNameTypes, BoxLayout.X_AXIS));

		jpGeneralNameTypes.add(jpFirstColumn);
		jpGeneralNameTypes.add(jpSecondColumn);
		jpGeneralNameTypes.add(jpThirdColumn);

		jlGeneralNameType = new JLabel(res.getString("DGeneralNameChooser.jlGeneralNameType.text"));
		jlGeneralNameType.setBorder(new EmptyBorder(5, 5, 5, 5));

		jpGeneralNameType = new JPanel(new BorderLayout(0, 0));

		jpGeneralNameType.add(jlGeneralNameType, BorderLayout.NORTH);
		jpGeneralNameType.add(jpGeneralNameTypes, BorderLayout.SOUTH);

		jlGeneralNameValue = new JLabel(res.getString("DGeneralNameChooser.jlGeneralNameValue.text"));

		jdnDirectoryName = new JDistinguishedName(res.getString("DGeneralNameChooser.DirectoryName.Title"), 20, true);
		jtfDnsName = new JTextField(30);
		jipaIpAddress = new JIpAddress();
		joiRegisteredId = new JObjectId(res.getString("DGeneralNameChooser.RegisteredId.Title"));
		jtfRfc822Name = new JTextField(30);
		jtfUniformResourceIdentifier = new JTextField(30);

		jpGeneralNameValue = new JPanel(new FlowLayout(FlowLayout.LEFT));

		jpGeneralName = new JPanel(new BorderLayout(0, 0));

		jpGeneralName.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpGeneralName.add(jpGeneralNameType, BorderLayout.NORTH);
		jpGeneralName.add(jpGeneralNameValue, BorderLayout.SOUTH);

		jbOK = new JButton(res.getString("DGeneralNameChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGeneralNameChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpGeneralName);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

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
			jpGeneralNameValue.add(jipaIpAddress);
		} else if (jrbRegisteredId.isSelected()) {
			jpGeneralNameValue.add(joiRegisteredId);
		} else if (jrbRfc822Name.isSelected()) {
			jpGeneralNameValue.add(jtfRfc822Name);
		} else if (jrbUniformResourceIdentifier.isSelected()) {
			jpGeneralNameValue.add(jtfUniformResourceIdentifier);
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
				jipaIpAddress.setIpAddress(((ASN1OctetString) generalName.getName()).getOctets());
				break;
			}
			case GeneralName.registeredID: {
				jrbRegisteredId.setSelected(true);
				joiRegisteredId.setObjectId(((ASN1ObjectIdentifier) generalName.getName()));
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
				newGeneralName = new GeneralName(GeneralName.iPAddress,
						new DEROctetString(jipaIpAddress.getIpAddress()));
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
			}

			generalName = newGeneralName;
		} catch (Exception ex) {
			DError dError = new DError(this, DOCUMENT_MODAL, ex);
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
}
