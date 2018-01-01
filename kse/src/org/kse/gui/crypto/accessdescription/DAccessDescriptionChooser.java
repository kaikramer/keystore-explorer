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
package org.kse.gui.crypto.accessdescription;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.generalname.JGeneralName;
import org.kse.gui.oid.JObjectId;

/**
 * Dialog to choose an access description.
 *
 */
public class DAccessDescriptionChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/accessdescription/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpAccessDescription;
	private JLabel jlAccessMethod;
	private JObjectId joiAccessMethod;
	private JLabel jlAccessLocation;
	private JGeneralName jgnAccessLocation;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private AccessDescription accessDescription;

	/**
	 * Constructs a new DAccessDescriptionChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param accessDescription
	 *            Access description
	 */
	public DAccessDescriptionChooser(JFrame parent, String title, AccessDescription accessDescription) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(accessDescription);
	}

	/**
	 * Constructs a new DAccessDescriptionChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param accessDescription
	 *            Access description
	 */
	public DAccessDescriptionChooser(JDialog parent, String title, AccessDescription accessDescription) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(accessDescription);
	}

	private void initComponents(AccessDescription accessDescription) {
		jlAccessMethod = new JLabel(res.getString("DAccessDescriptionChooser.jlAccessMethod.text"));

		GridBagConstraints gbc_jlAccessMethod = new GridBagConstraints();
		gbc_jlAccessMethod.gridx = 0;
		gbc_jlAccessMethod.gridy = 0;
		gbc_jlAccessMethod.gridwidth = 1;
		gbc_jlAccessMethod.gridheight = 1;
		gbc_jlAccessMethod.insets = new Insets(5, 5, 5, 5);
		gbc_jlAccessMethod.anchor = GridBagConstraints.EAST;

		joiAccessMethod = new JObjectId(res.getString("DAccessDescriptionChooser.AccessMethod.Text"));
		joiAccessMethod.setToolTipText(res.getString("DAccessDescriptionChooser.joiAccessMethod.tooltip"));

		GridBagConstraints gbc_joiAccessMethod = new GridBagConstraints();
		gbc_joiAccessMethod.gridx = 1;
		gbc_joiAccessMethod.gridy = 0;
		gbc_joiAccessMethod.gridwidth = 1;
		gbc_joiAccessMethod.gridheight = 1;
		gbc_joiAccessMethod.insets = new Insets(5, 5, 5, 5);
		gbc_joiAccessMethod.anchor = GridBagConstraints.WEST;

		jlAccessLocation = new JLabel(res.getString("DAccessDescriptionChooser.jlAccessLocation.text"));

		GridBagConstraints gbc_jlAccessLocation = new GridBagConstraints();
		gbc_jlAccessLocation.gridx = 0;
		gbc_jlAccessLocation.gridy = 1;
		gbc_jlAccessLocation.gridwidth = 1;
		gbc_jlAccessLocation.gridheight = 1;
		gbc_jlAccessLocation.insets = new Insets(5, 5, 5, 5);
		gbc_jlAccessLocation.anchor = GridBagConstraints.EAST;

		jgnAccessLocation = new JGeneralName(res.getString("DAccessDescriptionChooser.AccessLocation.Title"));
		jgnAccessLocation.setToolTipText(res.getString("DAccessDescriptionChooser.jgnAccessLocation.tooltip"));

		GridBagConstraints gbc_jgnAccessLocation = new GridBagConstraints();
		gbc_jgnAccessLocation.gridx = 1;
		gbc_jgnAccessLocation.gridy = 1;
		gbc_jgnAccessLocation.gridwidth = 1;
		gbc_jgnAccessLocation.gridheight = 1;
		gbc_jgnAccessLocation.insets = new Insets(5, 5, 5, 5);
		gbc_jgnAccessLocation.anchor = GridBagConstraints.WEST;

		jpAccessDescription = new JPanel(new GridBagLayout());

		jpAccessDescription.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpAccessDescription.add(jlAccessMethod, gbc_jlAccessMethod);
		jpAccessDescription.add(joiAccessMethod, gbc_joiAccessMethod);
		jpAccessDescription.add(jlAccessLocation, gbc_jlAccessLocation);
		jpAccessDescription.add(jgnAccessLocation, gbc_jgnAccessLocation);

		jbOK = new JButton(res.getString("DAccessDescriptionChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DAccessDescriptionChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpAccessDescription);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(accessDescription);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(AccessDescription accessDescription) {
		if (accessDescription != null) {
			joiAccessMethod.setObjectId(accessDescription.getAccessMethod());
			jgnAccessLocation.setGeneralName(accessDescription.getAccessLocation());
		}
	}

	/**
	 * Get selected access description.
	 *
	 * @return Access description, or null if none
	 */
	public AccessDescription getAccessDescription() {
		return accessDescription;
	}

	private void okPressed() {
		ASN1ObjectIdentifier accessMethod = joiAccessMethod.getObjectId();

		if (accessMethod == null) {
			JOptionPane.showMessageDialog(this,
					res.getString("DAccessDescriptionChooser.AccessMethodValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		GeneralName accessLocation = jgnAccessLocation.getGeneralName();

		if (accessLocation == null) {
			JOptionPane.showMessageDialog(this,
					res.getString("DAccessDescriptionChooser.AccessLocationValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		accessDescription = new AccessDescription(accessMethod, accessLocation);

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
