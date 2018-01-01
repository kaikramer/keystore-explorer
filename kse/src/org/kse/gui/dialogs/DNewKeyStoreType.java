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
package org.kse.gui.dialogs;

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

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used to retrieve the type to use in the creation of a new KeyStore.
 *
 */
public class DNewKeyStoreType extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpKeyStoreType;
	private JLabel jlKeyStoreType;
	private JRadioButton jrbJceksKeyStore;
	private JRadioButton jrbJksKeyStore;
	private JRadioButton jrbPkcs12KeyStore;
	private JRadioButton jrbBksV1KeyStore;
	private JRadioButton jrbBksKeyStore;
	private JRadioButton jrbUberKeyStore;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private KeyStoreType keyStoreType;

	/**
	 * Creates a new DNewKeyStoreType dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DNewKeyStoreType(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DNewKeyStoreType.Title"));
		initComponents();
	}

	private void initComponents() {
		jlKeyStoreType = new JLabel(res.getString("DNewKeyStoreType.jlKeyStoreType.text"));

		jrbJceksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbJceksKeyStore.text"), true);
		PlatformUtil.setMnemonic(jrbJceksKeyStore, res.getString("DNewKeyStoreType.jrbJceksKeyStore.mnemonic")
				.charAt(0));
		jrbJceksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbJceksKeyStore.tooltip"));

		jrbJksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbJksKeyStore.text"));
		PlatformUtil.setMnemonic(jrbJksKeyStore, res.getString("DNewKeyStoreType.jrbJksKeyStore.mnemonic").charAt(0));
		jrbJksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbJksKeyStore.tooltip"));

		jrbPkcs12KeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbPkcs12KeyStore.text"));
		PlatformUtil.setMnemonic(jrbPkcs12KeyStore, res.getString("DNewKeyStoreType.jrbPkcs12KeyStore.mnemonic")
				.charAt(0));
		jrbPkcs12KeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbPkcs12KeyStore.tooltip"));

		jrbBksV1KeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbBksV1KeyStore.text"));
		PlatformUtil.setMnemonic(jrbBksV1KeyStore, res.getString("DNewKeyStoreType.jrbBksV1KeyStore.mnemonic").charAt(0));
		jrbBksV1KeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbBksV1KeyStore.tooltip"));

		jrbBksKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbBksKeyStore.text"));
		PlatformUtil.setMnemonic(jrbBksKeyStore, res.getString("DNewKeyStoreType.jrbBksKeyStore.mnemonic").charAt(0));
		jrbBksKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbBksKeyStore.tooltip"));

		jrbUberKeyStore = new JRadioButton(res.getString("DNewKeyStoreType.jrbUberKeyStore.text"));
		PlatformUtil.setMnemonic(jrbUberKeyStore, res.getString("DNewKeyStoreType.jrbUberKeyStore.mnemonic").charAt(0));
		jrbUberKeyStore.setToolTipText(res.getString("DNewKeyStoreType.jrbUberKeyStore.tooltip"));

		ButtonGroup keyStoreTypes = new ButtonGroup();

		keyStoreTypes.add(jrbJceksKeyStore);
		keyStoreTypes.add(jrbJksKeyStore);
		keyStoreTypes.add(jrbPkcs12KeyStore);
		keyStoreTypes.add(jrbBksV1KeyStore);
		keyStoreTypes.add(jrbBksKeyStore);
		keyStoreTypes.add(jrbUberKeyStore);

		jpKeyStoreType = new JPanel(new GridLayout(7, 1));
		jpKeyStoreType.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpKeyStoreType.add(jlKeyStoreType);
		jpKeyStoreType.add(jrbJceksKeyStore);
		jpKeyStoreType.add(jrbJksKeyStore);
		jpKeyStoreType.add(jrbPkcs12KeyStore);
		jpKeyStoreType.add(jrbBksV1KeyStore);
		jpKeyStoreType.add(jrbBksKeyStore);
		jpKeyStoreType.add(jrbUberKeyStore);

		jbOK = new JButton(res.getString("DNewKeyStoreType.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DNewKeyStoreType.jbCancel.text"));
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
		getContentPane().add(jpKeyStoreType, BorderLayout.CENTER);
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
	 * Get the selected KeyStore type.
	 *
	 * @return The selected KeyStore type or null if none was selected
	 */
	public KeyStoreType getKeyStoreType() {
		return keyStoreType;
	}

	private void okPressed() {
		if (jrbJceksKeyStore.isSelected()) {
			keyStoreType = KeyStoreType.JCEKS;
		} else if (jrbJksKeyStore.isSelected()) {
			keyStoreType = KeyStoreType.JKS;
		} else if (jrbPkcs12KeyStore.isSelected()) {
			keyStoreType = KeyStoreType.PKCS12;
		} else if (jrbBksV1KeyStore.isSelected()) {
			keyStoreType = KeyStoreType.BKS_V1;
		} else if (jrbBksKeyStore.isSelected()) {
			keyStoreType = KeyStoreType.BKS;
		} else {
			keyStoreType = KeyStoreType.UBER;
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
