/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.Set;

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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.customextkeyusage.JCustomExtendedKeyUsage;

/**
 * Dialog used to add or edit custom extended key usages.
 *
 */
public class DCustomExtKeyUsage extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpCustomExtendedKeyUsage;
	private JLabel jlCustomExtendedKeyUsage;
	private JCustomExtendedKeyUsage jCustomExtendedKeyUsage;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private Set<ASN1ObjectIdentifier> customExtUsageOids;

	/**
	 * Creates a new DCustomExtKeyUsage dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DCustomExtKeyUsage(JDialog parent, Set<ASN1ObjectIdentifier> customExtUsageOids) {
		super(parent, ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DCustomExtendedKeyUsage.Title"));
		this.customExtUsageOids = customExtUsageOids;
		initComponents();
		prepopulateWithOidList(customExtUsageOids);
	}

	private void initComponents() {
		jlCustomExtendedKeyUsage = new JLabel(res.getString("DCustomExtendedKeyUsage.jlCustomExtendedKeyUsage.text"));

		GridBagConstraints gbc_jlCustomExtendedKeyUsage = new GridBagConstraints();
		gbc_jlCustomExtendedKeyUsage.gridx = 0;
		gbc_jlCustomExtendedKeyUsage.gridy = 1;
		gbc_jlCustomExtendedKeyUsage.gridwidth = 1;
		gbc_jlCustomExtendedKeyUsage.gridheight = 1;
		gbc_jlCustomExtendedKeyUsage.insets = new Insets(5, 5, 5, 5);
		gbc_jlCustomExtendedKeyUsage.anchor = GridBagConstraints.NORTHEAST;

		jCustomExtendedKeyUsage = new JCustomExtendedKeyUsage(res.getString("DCustomExtendedKeyUsage.jCustomExtendedKeyUsage.text"));
		jCustomExtendedKeyUsage.setPreferredSize(new Dimension(400, 150));

		GridBagConstraints gbc_jpiCustomExtendedKeyUsage = new GridBagConstraints();
		gbc_jpiCustomExtendedKeyUsage.gridx = 1;
		gbc_jpiCustomExtendedKeyUsage.gridy = 1;
		gbc_jpiCustomExtendedKeyUsage.gridwidth = 1;
		gbc_jpiCustomExtendedKeyUsage.gridheight = 1;
		gbc_jpiCustomExtendedKeyUsage.insets = new Insets(5, 5, 5, 5);
		gbc_jpiCustomExtendedKeyUsage.anchor = GridBagConstraints.WEST;

		jpCustomExtendedKeyUsage = new JPanel(new GridBagLayout());

		jpCustomExtendedKeyUsage.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpCustomExtendedKeyUsage.add(jlCustomExtendedKeyUsage, gbc_jlCustomExtendedKeyUsage);
		jpCustomExtendedKeyUsage.add(jCustomExtendedKeyUsage, gbc_jpiCustomExtendedKeyUsage);

		jbOK = new JButton(res.getString("DCustomExtendedKeyUsage.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DCustomExtendedKeyUsage.jbCancel.text"));
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

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpCustomExtendedKeyUsage, BorderLayout.CENTER);
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

	private void prepopulateWithOidList(Set<ASN1ObjectIdentifier> customExtKeyUsageOids) {
		Set<ASN1ObjectIdentifier> oids =new HashSet<ASN1ObjectIdentifier>();
		oids.addAll(customExtKeyUsageOids);
		jCustomExtendedKeyUsage.setCustomExtKeyUsages(oids);
	}

	private void okPressed() {
		Set<ASN1ObjectIdentifier> objectIds = jCustomExtendedKeyUsage.getCustomExtKeyUsages();
		if (objectIds.size() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DCustomExtendedKeyUsage.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}
		customExtUsageOids = objectIds;

		closeDialog();
	}

	/**
	 * Get extension value DER-encoded.
	 *
	 * @return Extension value
	 */
	public Set<ASN1ObjectIdentifier> getObjectIds() {
		return customExtUsageOids;
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
