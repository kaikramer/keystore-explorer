/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package net.sf.keystore_explorer.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import net.sf.keystore_explorer.ApplicationSettings;
import net.sf.keystore_explorer.crypto.x509.KseX500NameStyle;
import net.sf.keystore_explorer.crypto.x509.X500NameUtils;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.utilities.StringUtils;

/**
 * Dialog to view or edit a distinguished name.
 *
 */
public class DDistinguishedNameChooser extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/crypto/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlCommonName;
	private JTextField jtfCommonName;
	private JLabel jlOrganisationUnit;
	private JTextField jtfOrganisationUnit;
	private JLabel jlOrganisationName;
	private JTextField jtfOrganisationName;
	private JLabel jlLocalityName;
	private JTextField jtfLocalityName;
	private JLabel jlStateName;
	private JTextField jtfStateName;
	private JLabel jlCountryCode;
	private JTextField jtfCountryCode;
	private JLabel jlEmailAddress;
	private JTextField jtfEmailAddress;
	private JPanel jpDistinguishedName;
	private JButton jbOK;
	private JButton jbCancel;
	private JPanel jpButtons;

	private boolean editable;
	private X500Name distinguishedName;

	private ApplicationSettings applicationSettings = ApplicationSettings.getInstance();

	/**
	 * Creates a new DDistinguishedNameChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param distinguishedName
	 *            The distinguished name
	 * @param editable
	 *            Is dialog editable?
	 */
	public DDistinguishedNameChooser(JFrame parent, String title, X500Name distinguishedName, boolean editable) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.distinguishedName = distinguishedName;
		this.editable = editable;
		initComponents();
	}

	/**
	 * Creates a new DDistinguishedNameChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param distinguishedName
	 *            The distinguished name
	 * @param editable
	 *            Is dialog editable?
	 */
	public DDistinguishedNameChooser(JDialog parent, String title, X500Name distinguishedName, boolean editable) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.distinguishedName = distinguishedName;
		this.editable = editable;
		initComponents();
	}

	private void initComponents() {
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 3;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcCtrl = new GridBagConstraints();
		gbcCtrl.gridx = 3;
		gbcCtrl.gridwidth = 3;
		gbcCtrl.gridheight = 1;
		gbcCtrl.insets = new Insets(5, 5, 5, 5);
		gbcCtrl.anchor = GridBagConstraints.WEST;

		jlCommonName = new JLabel(res.getString("DDistinguishedNameChooser.jlCommonName.text"));
		GridBagConstraints gbc_jlCommonName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCommonName.gridy = 0;

		jtfCommonName = new JTextField(25);
		jtfCommonName.setEditable(editable);
		GridBagConstraints gbc_jtfCommonName = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfCommonName.gridy = 0;

		jlOrganisationUnit = new JLabel(res.getString("DDistinguishedNameChooser.jlOrganisationUnit.text"));
		GridBagConstraints gbc_jlOrganisationUnit = (GridBagConstraints) gbcLbl.clone();
		gbc_jlOrganisationUnit.gridy = 1;

		jtfOrganisationUnit = new JTextField(25);
		jtfOrganisationUnit.setEditable(editable);
		GridBagConstraints gbc_jtfOrganisationUnit = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfOrganisationUnit.gridy = 1;

		jlOrganisationName = new JLabel(res.getString("DDistinguishedNameChooser.jlOrganisationName.text"));
		GridBagConstraints gbc_jlOrganisationName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlOrganisationName.gridy = 2;

		jtfOrganisationName = new JTextField(25);
		jtfOrganisationName.setEditable(editable);
		GridBagConstraints gbc_jtfOrganisationName = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfOrganisationName.gridy = 2;

		jlLocalityName = new JLabel(res.getString("DDistinguishedNameChooser.jlLocalityName.text"));
		GridBagConstraints gbc_jlLocalityName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlLocalityName.gridy = 3;

		jtfLocalityName = new JTextField(25);
		jtfLocalityName.setEditable(editable);
		GridBagConstraints gbc_jtfLocalityName = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfLocalityName.gridy = 3;

		jlStateName = new JLabel(res.getString("DDistinguishedNameChooser.jlStateName.text"));
		GridBagConstraints gbc_jlStateName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlStateName.gridy = 4;

		jtfStateName = new JTextField(25);
		jtfStateName.setEditable(editable);
		GridBagConstraints gbc_jtfStateName = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfStateName.gridy = 4;

		jlCountryCode = new JLabel(res.getString("DDistinguishedNameChooser.jlCountryCode.text"));
		GridBagConstraints gbc_jlCountryCode = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCountryCode.gridy = 5;

		jtfCountryCode = new JTextField(4);
		jtfCountryCode.setEditable(editable);
		GridBagConstraints gbc_jtfCountryCode = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfCountryCode.gridy = 5;

		jlEmailAddress = new JLabel(res.getString("DDistinguishedNameChooser.jlEmailAddress.text"));
		GridBagConstraints gbc_jlEmailAddress = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEmailAddress.gridy = 6;

		jtfEmailAddress = new JTextField(25);
		jtfEmailAddress.setEditable(editable);
		GridBagConstraints gbc_jtfEmailAddress = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfEmailAddress.gridy = 6;

		jpDistinguishedName = new JPanel(new GridBagLayout());
		jpDistinguishedName.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpDistinguishedName.add(jlCommonName, gbc_jlCommonName);
		jpDistinguishedName.add(jtfCommonName, gbc_jtfCommonName);
		jpDistinguishedName.add(jlOrganisationUnit, gbc_jlOrganisationUnit);
		jpDistinguishedName.add(jtfOrganisationUnit, gbc_jtfOrganisationUnit);
		jpDistinguishedName.add(jlOrganisationName, gbc_jlOrganisationName);
		jpDistinguishedName.add(jtfOrganisationName, gbc_jtfOrganisationName);
		jpDistinguishedName.add(jlLocalityName, gbc_jlLocalityName);
		jpDistinguishedName.add(jtfLocalityName, gbc_jtfLocalityName);
		jpDistinguishedName.add(jlStateName, gbc_jlStateName);
		jpDistinguishedName.add(jtfStateName, gbc_jtfStateName);
		jpDistinguishedName.add(jlCountryCode, gbc_jlCountryCode);
		jpDistinguishedName.add(jtfCountryCode, gbc_jtfCountryCode);
		jpDistinguishedName.add(jlEmailAddress, gbc_jlEmailAddress);
		jpDistinguishedName.add(jtfEmailAddress, gbc_jtfEmailAddress);

		populate();

		jbOK = new JButton(res.getString("DDistinguishedNameChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		if (editable) {
			jtfCommonName.setToolTipText(res.getString("DDistinguishedNameChooser.jtfCommonName.edit.tooltip"));
			jtfOrganisationUnit.setToolTipText(res
					.getString("DDistinguishedNameChooser.jtfOrganisationUnit.edit.tooltip"));
			jtfOrganisationName.setToolTipText(res
					.getString("DDistinguishedNameChooser.jtfOrganisationName.edit.tooltip"));
			jtfLocalityName.setToolTipText(res.getString("DDistinguishedNameChooser.jtfLocalityName.edit.tooltip"));
			jtfStateName.setToolTipText(res.getString("DDistinguishedNameChooser.jtfStateName.edit.tooltip"));
			jtfCountryCode.setToolTipText(res.getString("DDistinguishedNameChooser.jtfCountryCode.edit.tooltip"));
			jtfEmailAddress.setToolTipText(res.getString("DDistinguishedNameChooser.jtfEmailAddress.edit.tooltip"));

			jbCancel = new JButton(res.getString("DDistinguishedNameChooser.jbCancel.text"));
			jbCancel.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					cancelPressed();
				}
			});
			jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
					CANCEL_KEY);
			jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					cancelPressed();
				}
			});

			jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);
		} else {
			jtfCommonName.setToolTipText(res.getString("DDistinguishedNameChooser.jtfCommonName.view.tooltip"));
			jtfOrganisationUnit.setToolTipText(res
					.getString("DDistinguishedNameChooser.jtfOrganisationUnit.view.tooltip"));
			jtfOrganisationName.setToolTipText(res
					.getString("DDistinguishedNameChooser.jtfOrganisationName.view.tooltip"));
			jtfLocalityName.setToolTipText(res.getString("DDistinguishedNameChooser.jtfLocalityName.view.tooltip"));
			jtfStateName.setToolTipText(res.getString("DDistinguishedNameChooser.jtfStateName.view.tooltip"));
			jtfCountryCode.setToolTipText(res.getString("DDistinguishedNameChooser.jtfCountryCode.view.tooltip"));
			jtfEmailAddress.setToolTipText(res.getString("DDistinguishedNameChooser.jtfEmailAddress.view.tooltip"));

			jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, false);
		}

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpDistinguishedName, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				okPressed();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate() {

		if (distinguishedName != null) {
			populateRdnField(distinguishedName, jtfCommonName, BCStyle.CN);
			populateRdnField(distinguishedName, jtfOrganisationUnit, BCStyle.OU);
			populateRdnField(distinguishedName, jtfOrganisationName, BCStyle.O);
			populateRdnField(distinguishedName, jtfLocalityName, BCStyle.L);
			populateRdnField(distinguishedName, jtfStateName, BCStyle.ST);
			populateRdnField(distinguishedName, jtfCountryCode, BCStyle.C);
			populateRdnField(distinguishedName, jtfEmailAddress, BCStyle.E);
		} else {

			// use default DN for populating DN fields?
			String defaultDN = applicationSettings.getDefaultDN();
			if (!StringUtils.isBlank(defaultDN)) {
				X500Name defaultX500Name = new X500Name(KseX500NameStyle.INSTANCE, defaultDN);
				populateRdnField(defaultX500Name, jtfCommonName, BCStyle.CN);
				populateRdnField(defaultX500Name, jtfOrganisationUnit, BCStyle.OU);
				populateRdnField(defaultX500Name, jtfOrganisationName, BCStyle.O);
				populateRdnField(defaultX500Name, jtfLocalityName, BCStyle.L);
				populateRdnField(defaultX500Name, jtfStateName, BCStyle.ST);
				populateRdnField(defaultX500Name, jtfCountryCode, BCStyle.C);
				populateRdnField(defaultX500Name, jtfEmailAddress, BCStyle.E);
			}
		}
	}

	private void populateRdnField(X500Name x500Name, JTextField rdnField, ASN1ObjectIdentifier rdnOid) {
		rdnField.setText(X500NameUtils.getRdn(x500Name, rdnOid));
		rdnField.setCaretPosition(0);
	}

	/**
	 * Get selected distinguished name.
	 *
	 * @return Distinguished name, or null if none
	 */
	public X500Name getDistinguishedName() {
		return distinguishedName;
	}

	private void okPressed() {
		if (editable) {
			String commonName = StringUtils.trimAndConvertEmptyToNull(jtfCommonName.getText());
			String organisationUnit = StringUtils.trimAndConvertEmptyToNull(jtfOrganisationUnit.getText());
			String organisationName = StringUtils.trimAndConvertEmptyToNull(jtfOrganisationName.getText());
			String localityName = StringUtils.trimAndConvertEmptyToNull(jtfLocalityName.getText());
			String stateName = StringUtils.trimAndConvertEmptyToNull(jtfStateName.getText());
			String countryCode = StringUtils.trimAndConvertEmptyToNull(jtfCountryCode.getText());
			String emailAddress = StringUtils.trimAndConvertEmptyToNull(jtfEmailAddress.getText());

			if ((commonName == null) && (organisationUnit == null) && (organisationName == null)
					&& (localityName == null) && (stateName == null) && (countryCode == null) && (emailAddress == null)) {
				JOptionPane.showMessageDialog(this,
						res.getString("DDistinguishedNameChooser.ValueReqAtLeastOneField.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			if ((countryCode != null) && (countryCode.length() != 2)) {
				JOptionPane.showMessageDialog(this,
						res.getString("DDistinguishedNameChooser.CountryCodeTwoChars.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			distinguishedName = X500NameUtils.buildX500Name(commonName, organisationUnit, organisationName,
					localityName, stateName, countryCode, emailAddress);
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
