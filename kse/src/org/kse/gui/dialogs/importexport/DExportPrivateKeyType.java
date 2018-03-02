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
 * Dialog used to request the type of private key export.
 *
 */
public class DExportPrivateKeyType extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/importexport/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpExportType;
	private JLabel jlExportType;
	private JRadioButton jrbPkcs8;
	private JRadioButton jrbPvk;
	private JRadioButton jrbOpenSsl;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private boolean exportTypeSelected = false;

	/**
	 * Creates a new DExportPrivateKeyType dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DExportPrivateKeyType(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DExportPrivateKeyType.Title"));
		initComponents();
	}

	private void initComponents() {
		jlExportType = new JLabel(res.getString("DExportPrivateKeyType.jlExportType.text"));

		jrbPkcs8 = new JRadioButton(res.getString("DExportPrivateKeyType.jrbPkcs8.text"), true);
		PlatformUtil.setMnemonic(jrbPkcs8, res.getString("DExportPrivateKeyType.jrbPkcs8.mnemonic").charAt(0));
		jrbPkcs8.setToolTipText(res.getString("DExportPrivateKeyType.jrbPkcs8.tooltip"));

		jrbPvk = new JRadioButton(res.getString("DExportPrivateKeyType.jrbPvk.text"));
		PlatformUtil.setMnemonic(jrbPvk, res.getString("DExportPrivateKeyType.jrbPvk.mnemonic").charAt(0));
		jrbPvk.setToolTipText(res.getString("DExportPrivateKeyType.jrbPvk.tooltip"));

		jrbOpenSsl = new JRadioButton(res.getString("DExportPrivateKeyType.jrbOpenSsl.text"));
		PlatformUtil.setMnemonic(jrbOpenSsl, res.getString("DExportPrivateKeyType.jrbOpenSsl.mnemonic").charAt(0));
		jrbOpenSsl.setToolTipText(res.getString("DExportPrivateKeyType.jrbOpenSsl.tooltip"));

		ButtonGroup keyStoreTypes = new ButtonGroup();

		keyStoreTypes.add(jrbPkcs8);
		keyStoreTypes.add(jrbPvk);
		keyStoreTypes.add(jrbOpenSsl);

		jpExportType = new JPanel(new GridLayout(4, 1));
		jpExportType.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpExportType.add(jlExportType);
		jpExportType.add(jrbPkcs8);
		jpExportType.add(jrbPvk);
		jpExportType.add(jrbOpenSsl);

		jbOK = new JButton(res.getString("DExportPrivateKeyType.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DExportPrivateKeyType.jbCancel.text"));
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
		getContentPane().add(jpExportType, BorderLayout.CENTER);
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
	 * Has an export type been selected?
	 *
	 * @return True if it has, false otherwise
	 */
	public boolean exportTypeSelected() {
		return exportTypeSelected;
	}

	/**
	 * Has the user chosen to export to PKCS #8?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean exportPkcs8() {
		return jrbPkcs8.isSelected();
	}

	/**
	 * Has the user chosen to export to PVK?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean exportPvk() {
		return jrbPvk.isSelected();
	}

	/**
	 * Has the user chosen to export to OpenSSL?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean exportOpenSsl() {
		return jrbOpenSsl.isSelected();
	}

	private void okPressed() {
		exportTypeSelected = true;

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
