/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
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
import javax.swing.JSpinner;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;

/**
 * Dialog used to choose the parameters required for key pair generation. The
 * user may select an asymmetric key generation algorithm of RSA or DSA and
 * enter a key size in bits.
 * 
 */
public class DGenerateKeyPair extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpOptions;
	private JPanel jpKeyAlg;
	private JLabel jlKeyAlg;
	private JRadioButton jrbRSA;
	private JRadioButton jrbDSA;
	private JPanel jpKeySize;
	private JLabel jlKeySize;
	private JSpinner jsKeySize;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private KeyPairType keyPairType;
	private int keyPairSize;
	private boolean success = false;

	/**
	 * Creates a new DGenerateKeyPair dialog.
	 * 
	 * @param parent
	 *            The parent frame
	 * @param keyPairType
	 *            Initial key pair type
	 * @param keyPairSize
	 *            Initial key pair size
	 */
	public DGenerateKeyPair(JFrame parent, KeyPairType keyPairType, int keyPairSize) {
		super(parent, res.getString("DGenerateKeyPair.Title"), Dialog.ModalityType.APPLICATION_MODAL);

		this.keyPairType = keyPairType;
		this.keyPairSize = keyPairSize;

		initComponents();
	}

	private void initComponents() {
		jlKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));

		jsKeySize = new JSpinner();
		jsKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));

		jpKeySize = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeySize.add(jlKeySize);
		jpKeySize.add(jsKeySize);

		jlKeyAlg = new JLabel(res.getString("DGenerateKeyPair.jlKeyAlg.text"));

		jrbRSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbRSA.text"), false);
		PlatformUtil.setMnemonic(jrbRSA, res.getString("DGenerateKeyPair.jrbRSA.mnemonic").charAt(0));
		jrbRSA.setToolTipText(res.getString("DGenerateKeyPair.jrbRSA.tooltip"));

		jrbDSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbDSA.text"), true);
		PlatformUtil.setMnemonic(jrbDSA, res.getString("DGenerateKeyPair.jrbDSA.mnemonic").charAt(0));
		jrbDSA.setToolTipText(res.getString("DGenerateKeyPair.jrbDSA.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbRSA);
		buttonGroup.add(jrbDSA);

		if (keyPairType == KeyPairType.RSA) {
			jrbRSA.setSelected(true);
		} else {
			jrbDSA.setSelected(true);
		}

		loadKeySizes(keyPairSize);

		jrbRSA.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				loadKeySizes(getKeyPairSize());
			}
		});

		jrbDSA.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				loadKeySizes(getKeyPairSize());
			}
		});

		jpKeyAlg = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeyAlg.add(jlKeyAlg);
		jpKeyAlg.add(jrbRSA);
		jpKeyAlg.add(jrbDSA);

		jsKeySize.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent evt) {
				correctKeyPairSize();
			}
		});

		jpOptions = new JPanel(new GridLayout(2, 1, 5, 5));
		jpOptions.add(jpKeyAlg);
		jpOptions.add(jpKeySize);

		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jbOK = new JButton(res.getString("DGenerateKeyPair.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGenerateKeyPair.jbCancel.text"));
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
		getContentPane().add(jpOptions, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void loadKeySizes(int keyPairSize) {
		KeyPairType keyPairType = getKeyPairType();
		keyPairSize = validateKeyPairSize(keyPairType, keyPairSize);

		jsKeySize.setModel(new SpinnerNumberModel(keyPairSize, keyPairType.minSize(), keyPairType.maxSize(),
				keyPairType.stepSize()));
	}

	private void correctKeyPairSize() {
		KeyPairType keyPairType = getKeyPairType();
		int keyPairSize = getKeyPairSize();

		int validatedKeyPairSize = validateKeyPairSize(keyPairType, keyPairSize);

		if (validatedKeyPairSize != keyPairSize) {
			jsKeySize.getModel().setValue(validatedKeyPairSize);
		}
	}

	private int validateKeyPairSize(KeyPairType keyPairType, int keyPairSize) {
		// Validate against step size
		int stepSize = keyPairType.stepSize();

		if ((keyPairSize % stepSize) != 0) {
			int difference = keyPairSize % stepSize;

			if (difference <= (stepSize / 2)) {
				keyPairSize -= difference;
			} else {
				keyPairSize += (stepSize - difference);
			}
		}

		// Validate against minimum size
		int minSize = keyPairType.minSize();

		if (keyPairSize < minSize) {
			keyPairSize = minSize;
		}

		// Validate against maximum size
		int maxSize = keyPairType.maxSize();

		if (keyPairSize > maxSize) {
			keyPairSize = maxSize;
		}

		return keyPairSize;
	}

	/**
	 * Get the key pair size chosen.
	 * 
	 * @return The key pair size
	 */
	public int getKeyPairSize() {
		return ((Number) jsKeySize.getValue()).intValue();
	}

	/**
	 * Get the key pair type chosen.
	 * 
	 * @return The key pair generation type
	 */
	public KeyPairType getKeyPairType() {
		if (jrbRSA.isSelected()) {
			return KeyPairType.RSA;
		}

		return KeyPairType.DSA;

	}

	/**
	 * Have the parameters been entered correctly?
	 * 
	 * @return True if they have, false otherwise
	 */
	public boolean isSuccessful() {
		return success;
	}

	private void okPressed() {
		success = true;
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
