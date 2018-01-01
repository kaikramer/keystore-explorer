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
package org.kse.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.crypto.CryptoException;
import org.kse.crypto.publickey.KeyIdentifierGenerator;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog to choose a key identifier value.
 *
 */
public class DKeyIdentifierChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpKeyIdentifier;
	private JLabel jlGenerationMethod;
	private JRadioButton jrb160BitHash;
	private JRadioButton jrb64BitHash;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PublicKey publicKey;
	private byte[] keyIdentifier160Bit;
	private byte[] keyIdentifier64Bit;
	private byte[] keyIdentifier;

	/**
	 * Constructs a new DKeyIdentifierChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param publicKey
	 *            Public key
	 * @param keyIdentifier
	 *            Key identifier
	 * @throws CryptoException
	 *             If there was a problem generating identifiers
	 */
	public DKeyIdentifierChooser(JFrame parent, String title, PublicKey publicKey, byte[] keyIdentifier)
			throws CryptoException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.publicKey = publicKey;
		initComponents(keyIdentifier);
	}

	/**
	 * Constructs a new DKeyIdentifierChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param publicKey
	 *            Public key
	 * @param keyIdentifier
	 *            Key identifier
	 * @throws CryptoException
	 *             If there was a problem generating identifiers
	 */
	public DKeyIdentifierChooser(JDialog parent, String title, PublicKey publicKey, byte[] keyIdentifier)
			throws CryptoException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.publicKey = publicKey;
		initComponents(keyIdentifier);
	}

	private void initComponents(byte[] keyIdentifier) throws CryptoException {
		jlGenerationMethod = new JLabel(res.getString("DKeyIdentifierChooser.jlGenerationMethod.text"));

		jrb160BitHash = new JRadioButton(res.getString("DKeyIdentifierChooser.jrb160BitHash.text"));
		jrb160BitHash.setToolTipText(res.getString("DKeyIdentifierChooser.jrb160BitHash.tooltip"));

		jrb64BitHash = new JRadioButton(res.getString("DKeyIdentifierChooser.jrb64BitHash.text"));
		jrb64BitHash.setToolTipText(res.getString("DKeyIdentifierChooser.jrb64BitHash.tooltip"));

		ButtonGroup bgKeyIdentifier = new ButtonGroup();
		bgKeyIdentifier.add(jrb160BitHash);
		bgKeyIdentifier.add(jrb64BitHash);

		jpKeyIdentifier = new JPanel(new GridLayout(3, 1));
		jpKeyIdentifier.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));
		jpKeyIdentifier.add(jlGenerationMethod);
		jpKeyIdentifier.add(jrb160BitHash);
		jpKeyIdentifier.add(jrb64BitHash);

		jbOK = new JButton(res.getString("DKeyIdentifierChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DKeyIdentifierChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpKeyIdentifier);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(keyIdentifier);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(byte[] keyIdentifier) throws CryptoException {
		KeyIdentifierGenerator keyIdentifierGenerator = new KeyIdentifierGenerator(publicKey);

		keyIdentifier160Bit = keyIdentifierGenerator.generate160BitHashId();
		keyIdentifier64Bit = keyIdentifierGenerator.generate64BitHashId();

		if (keyIdentifier == null || (keyIdentifier.length == keyIdentifier160Bit.length)) {
			jrb160BitHash.setSelected(true);
		} else {
			jrb64BitHash.setSelected(true);
		}
	}

	/**
	 * Get selected key identifier.
	 *
	 * @return Key identifier, or null if none
	 */
	public byte[] getKeyIdentifier() {
		return keyIdentifier;
	}

	private void okPressed() {
		if (jrb160BitHash.isSelected()) {
			keyIdentifier = keyIdentifier160Bit;
		} else {
			keyIdentifier = keyIdentifier64Bit;
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
