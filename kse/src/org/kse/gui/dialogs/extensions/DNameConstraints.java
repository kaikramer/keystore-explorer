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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.kse.crypto.x509.GeneralSubtrees;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.generalsubtree.JGeneralSubtrees;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit a Name Constraints extension.
 *
 */
public class DNameConstraints extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpNameConstraints;
	private JLabel jlPermittedSubtrees;
	private JGeneralSubtrees jgsPermittedSubtrees;
	private JLabel jlExcludedSubtrees;
	private JGeneralSubtrees jgsExcludedSubtrees;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DNameConstraints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DNameConstraints(JDialog parent) {
		super(parent);
		setTitle(res.getString("DNameConstraints.Title"));
		initComponents();
	}

	/**
	 * Creates a new DNameConstraints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Name Constraints DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DNameConstraints(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DNameConstraints.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlPermittedSubtrees = new JLabel(res.getString("DNameConstraints.jlPermittedSubtrees.text"));

		GridBagConstraints gbc_jlPermittedSubtrees = new GridBagConstraints();
		gbc_jlPermittedSubtrees.gridx = 0;
		gbc_jlPermittedSubtrees.gridy = 0;
		gbc_jlPermittedSubtrees.gridwidth = 1;
		gbc_jlPermittedSubtrees.gridheight = 1;
		gbc_jlPermittedSubtrees.insets = new Insets(5, 5, 5, 5);
		gbc_jlPermittedSubtrees.anchor = GridBagConstraints.NORTHEAST;

		jgsPermittedSubtrees = new JGeneralSubtrees(res.getString("DNameConstraints.PermittedSubtrees.Title"));
		jgsPermittedSubtrees.setToolTipText(res.getString("DNameConstraints.jgsPermittedSubtrees.tooltip"));

		GridBagConstraints gbc_jgsPermittedSubtrees = new GridBagConstraints();
		gbc_jgsPermittedSubtrees.gridx = 1;
		gbc_jgsPermittedSubtrees.gridy = 0;
		gbc_jgsPermittedSubtrees.gridwidth = 1;
		gbc_jgsPermittedSubtrees.gridheight = 1;
		gbc_jgsPermittedSubtrees.insets = new Insets(5, 5, 5, 5);
		gbc_jgsPermittedSubtrees.anchor = GridBagConstraints.WEST;

		jlExcludedSubtrees = new JLabel(res.getString("DNameConstraints.jlExcludedSubtrees.text"));

		GridBagConstraints gbc_jlExcludedSubtrees = new GridBagConstraints();
		gbc_jlExcludedSubtrees.gridx = 0;
		gbc_jlExcludedSubtrees.gridy = 1;
		gbc_jlExcludedSubtrees.gridwidth = 1;
		gbc_jlExcludedSubtrees.gridheight = 1;
		gbc_jlExcludedSubtrees.insets = new Insets(5, 5, 5, 5);
		gbc_jlExcludedSubtrees.anchor = GridBagConstraints.NORTHEAST;

		jgsExcludedSubtrees = new JGeneralSubtrees(res.getString("DNameConstraints.ExcludedSubtrees.Title"));
		jgsExcludedSubtrees.setToolTipText(res.getString("DNameConstraints.jgsExcludedSubtrees.tooltip"));

		GridBagConstraints gbc_jgsExcludedSubtrees = new GridBagConstraints();
		gbc_jgsExcludedSubtrees.gridx = 1;
		gbc_jgsExcludedSubtrees.gridy = 1;
		gbc_jgsExcludedSubtrees.gridwidth = 1;
		gbc_jgsExcludedSubtrees.gridheight = 1;
		gbc_jgsExcludedSubtrees.insets = new Insets(5, 5, 5, 5);
		gbc_jgsExcludedSubtrees.anchor = GridBagConstraints.WEST;

		jpNameConstraints = new JPanel(new GridBagLayout());

		jpNameConstraints.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpNameConstraints.add(jlPermittedSubtrees, gbc_jlPermittedSubtrees);
		jpNameConstraints.add(jgsPermittedSubtrees, gbc_jgsPermittedSubtrees);
		jpNameConstraints.add(jlExcludedSubtrees, gbc_jlExcludedSubtrees);
		jpNameConstraints.add(jgsExcludedSubtrees, gbc_jgsExcludedSubtrees);

		jbOK = new JButton(res.getString("DNameConstraints.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DNameConstraints.jbCancel.text"));
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
		getContentPane().add(jpNameConstraints, BorderLayout.CENTER);
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
		NameConstraints nameConstraints = NameConstraints.getInstance(value);

		if (nameConstraints.getPermittedSubtrees() != null) {
			jgsPermittedSubtrees.setGeneralSubtrees(new GeneralSubtrees(nameConstraints.getPermittedSubtrees()));
		}

		if (nameConstraints.getExcludedSubtrees() != null) {
			jgsExcludedSubtrees.setGeneralSubtrees(new GeneralSubtrees(nameConstraints.getExcludedSubtrees()));
		}
	}

	private void okPressed() {
		List<GeneralSubtree> permittedSubtrees = jgsPermittedSubtrees.getGeneralSubtrees().getGeneralSubtrees();
		List<GeneralSubtree> excludedSubtrees = jgsExcludedSubtrees.getGeneralSubtrees().getGeneralSubtrees();

		GeneralSubtree[] permittedSubtreesArray = permittedSubtrees.toArray(new GeneralSubtree[permittedSubtrees.size()]);
		GeneralSubtree[] excludedSubtreesArray = excludedSubtrees.toArray(new GeneralSubtree[excludedSubtrees.size()]);

		NameConstraints nameConstraints = new NameConstraints(permittedSubtreesArray, excludedSubtreesArray);

		try {
			value = nameConstraints.getEncoded(ASN1Encoding.DER);
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
