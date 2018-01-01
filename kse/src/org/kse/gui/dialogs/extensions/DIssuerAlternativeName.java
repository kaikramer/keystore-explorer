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
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.generalname.JGeneralNames;
import org.kse.gui.error.DError;

/**
 * Dialog used to add or edit an Issuer Alternative Name extension.
 *
 */
public class DIssuerAlternativeName extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpIssuerAlternativeName;
	private JLabel jlAlternativeName;
	private JGeneralNames jgnAlternativeName;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DIssuerAlternativeName dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DIssuerAlternativeName(JDialog parent) {
		super(parent);

		setTitle(res.getString("DIssuerAlternativeName.Title"));
		initComponents();
	}

	/**
	 * Creates a new DIssuerAlternativeName dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param value
	 *            Issuer Alternative Name DER-encoded
	 * @throws IOException
	 *             If value could not be decoded
	 */
	public DIssuerAlternativeName(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DIssuerAlternativeName.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlAlternativeName = new JLabel(res.getString("DIssuerAlternativeName.jlAlternativeName.text"));

		GridBagConstraints gbc_jlAlternativeName = new GridBagConstraints();
		gbc_jlAlternativeName.gridx = 0;
		gbc_jlAlternativeName.gridy = 1;
		gbc_jlAlternativeName.gridwidth = 1;
		gbc_jlAlternativeName.gridheight = 1;
		gbc_jlAlternativeName.insets = new Insets(5, 5, 5, 5);
		gbc_jlAlternativeName.anchor = GridBagConstraints.NORTHEAST;

		jgnAlternativeName = new JGeneralNames(res.getString("DIssuerAlternativeName.AlternativeName.Title"));
		jgnAlternativeName.setPreferredSize(new Dimension(400, 150));

		GridBagConstraints gbc_jgnAlternativeName = new GridBagConstraints();
		gbc_jgnAlternativeName.gridx = 1;
		gbc_jgnAlternativeName.gridy = 1;
		gbc_jgnAlternativeName.gridwidth = 1;
		gbc_jgnAlternativeName.gridheight = 1;
		gbc_jgnAlternativeName.insets = new Insets(5, 5, 5, 5);
		gbc_jgnAlternativeName.anchor = GridBagConstraints.WEST;

		jpIssuerAlternativeName = new JPanel(new GridBagLayout());

		jpIssuerAlternativeName.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpIssuerAlternativeName.add(jlAlternativeName, gbc_jlAlternativeName);
		jpIssuerAlternativeName.add(jgnAlternativeName, gbc_jgnAlternativeName);

		jbOK = new JButton(res.getString("DIssuerAlternativeName.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DIssuerAlternativeName.jbCancel.text"));
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
		getContentPane().add(jpIssuerAlternativeName, BorderLayout.CENTER);
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
		GeneralNames issuerAlternativeName = GeneralNames.getInstance(value);

		if (issuerAlternativeName != null) {
			jgnAlternativeName.setGeneralNames(issuerAlternativeName);
		}
	}

	private void okPressed() {
		GeneralNames issuerAlternativeName = jgnAlternativeName.getGeneralNames();

		if (issuerAlternativeName.getNames().length == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DIssuerAlternativeName.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		try {
			value = issuerAlternativeName.getEncoded(ASN1Encoding.DER);
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
