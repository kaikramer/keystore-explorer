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
package org.kse.gui.dialogs.importexport;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used to request the type of key pair import.
 *
 */
public class DImportKeyPairType extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpImportType;
	private JLabel jlImportType;
	private JRadioButton jrbPkcs12;
	private JRadioButton jrbPkcs8;
	private JRadioButton jrbPvk;
	private JRadioButton jrbOpenSsl;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private boolean importTypeSelected = false;

	/**
	 * Creates a new DImportKeyPairType dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DImportKeyPairType(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DImportKeyPairType.Title"));
		initComponents();
	}

	private void initComponents() {
		jlImportType = new JLabel(res.getString("DImportKeyPairType.jlImportType.text"));

		jrbPkcs12 = new JRadioButton(res.getString("DImportKeyPairType.jrbPkcs12.text"), true);
		PlatformUtil.setMnemonic(jrbPkcs12, res.getString("DImportKeyPairType.jrbPkcs12.mnemonic").charAt(0));
		jrbPkcs12.setToolTipText(res.getString("DImportKeyPairType.jrbPkcs12.tooltip"));

		jrbPkcs8 = new JRadioButton(res.getString("DImportKeyPairType.jrbPkcs8.text"));
		PlatformUtil.setMnemonic(jrbPkcs8, res.getString("DImportKeyPairType.jrbPkcs8.mnemonic").charAt(0));
		jrbPkcs8.setToolTipText(res.getString("DImportKeyPairType.jrbPkcs8.tooltip"));

		jrbPvk = new JRadioButton(res.getString("DImportKeyPairType.jrbPvk.text"));
		PlatformUtil.setMnemonic(jrbPvk, res.getString("DImportKeyPairType.jrbPvk.mnemonic").charAt(0));
		jrbPvk.setToolTipText(res.getString("DImportKeyPairType.jrbPvk.tooltip"));

		jrbOpenSsl = new JRadioButton(res.getString("DImportKeyPairType.jrbOpenSsl.text"));
		PlatformUtil.setMnemonic(jrbOpenSsl, res.getString("DImportKeyPairType.jrbOpenSsl.mnemonic").charAt(0));
		jrbOpenSsl.setToolTipText(res.getString("DImportKeyPairType.jrbOpenSsl.tooltip"));

		ButtonGroup keyStoreTypes = new ButtonGroup();

		keyStoreTypes.add(jrbPkcs12);
		keyStoreTypes.add(jrbPkcs8);
		keyStoreTypes.add(jrbPvk);
		keyStoreTypes.add(jrbOpenSsl);

		jpImportType = new JPanel(new GridLayout(5, 1));
		jpImportType.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpImportType.add(jlImportType);
		jpImportType.add(jrbPkcs12);
		jpImportType.add(jrbPkcs8);
		jpImportType.add(jrbPvk);
		jpImportType.add(jrbOpenSsl);

		jbOK = new JButton(res.getString("DImportKeyPairType.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DImportKeyPairType.jbCancel.text"));
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
		getContentPane().add(jpImportType, BorderLayout.CENTER);
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

	/**
	 * Has an import type been selected?
	 *
	 * @return True if it has, false otherwise
	 */
	public boolean importTypeSelected() {
		return importTypeSelected;
	}

	/**
	 * Has the user chosen to import from a PKCS #12 file?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean importPkcs12() {
		return jrbPkcs12.isSelected();
	}

	/**
	 * Has the user chosen to import from PKCS #8 private key and certificate
	 * file combination?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean importPkcs8() {
		return jrbPkcs8.isSelected();
	}

	/**
	 * Has the user chosen to import from PVK private key and certificate file
	 * combination?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean importPvk() {
		return jrbPvk.isSelected();
	}

	/**
	 * Has the user chosen to import from OpenSSL private key and certificate
	 * file combination?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean importOpenSsl() {
		return jrbOpenSsl.isSelected();
	}

	private void okPressed() {
		importTypeSelected = true;

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
