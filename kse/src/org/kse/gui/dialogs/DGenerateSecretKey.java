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
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used to choose the parameters required for secret key generation. The
 * user may select an secret key algorithm and enter a key size in bits.
 *
 */
public class DGenerateSecretKey extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpOptions;
	private JPanel jpKeyAlg;
	private JLabel jlKeyAlg;
	private JComboBox<SecretKeyType> jcbKeyAlg;
	private JPanel jpKeySize;
	private JLabel jlKeySize;
	private JSpinner jsKeySize;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private SecretKeyType secretKeyType;
	private int secretKeySize;
	private boolean success = false;

	/**
	 * Creates a new DGenerateSecretKey dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param secretKeyType
	 *            Initial secret key type
	 * @param secretKeySize
	 *            Initial secret key size
	 */
	public DGenerateSecretKey(JFrame parent, SecretKeyType secretKeyType, int secretKeySize) {
		super(parent, res.getString("DGenerateSecretKey.Title"), Dialog.ModalityType.DOCUMENT_MODAL);

		this.secretKeyType = secretKeyType;
		this.secretKeySize = secretKeySize;

		initComponents();
	}

	private void initComponents() {
		jlKeySize = new JLabel(res.getString("DGenerateSecretKey.jlKeySize.text"));

		jsKeySize = new JSpinner();
		jsKeySize.setToolTipText(res.getString("DGenerateSecretKey.jsKeySize.tooltip"));

		jpKeySize = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeySize.add(jlKeySize);
		jpKeySize.add(jsKeySize);

		jlKeyAlg = new JLabel(res.getString("DGenerateSecretKey.jlKeyAlg.text"));

		jcbKeyAlg = new JComboBox<SecretKeyType>();
		jcbKeyAlg.setToolTipText(res.getString("DGenerateSecretKey.jcbKeyAlg.tooltip"));

		populateKeyAlgs();
		loadKeySizes(secretKeySize);

		jcbKeyAlg.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				loadKeySizes(getSecretKeySize());
			}
		});

		jpKeyAlg = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeyAlg.add(jlKeyAlg);
		jpKeyAlg.add(jcbKeyAlg);

		jsKeySize.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent evt) {
				correctSecretKeySize();
			}
		});

		jpOptions = new JPanel(new GridLayout(2, 1, 5, 5));
		jpOptions.add(jpKeyAlg);
		jpOptions.add(jpKeySize);

		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jbOK = new JButton(res.getString("DGenerateSecretKey.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGenerateSecretKey.jbCancel.text"));
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
		getContentPane().add(jpOptions, BorderLayout.CENTER);
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

	private void populateKeyAlgs() {
		for (SecretKeyType secretKeyType : SecretKeyType.values()) {
			jcbKeyAlg.addItem(secretKeyType);
		}

		jcbKeyAlg.setSelectedItem(secretKeyType);
	}

	private void loadKeySizes(int secretKeySize) {
		SecretKeyType secretKeyType = getSecretKeyType();
		secretKeySize = validateSecretKeySize(secretKeyType, secretKeySize);

		jsKeySize.setModel(new SpinnerNumberModel(secretKeySize, secretKeyType.minSize(), secretKeyType.maxSize(),
				secretKeyType.stepSize()));

		jsKeySize.setEnabled(secretKeyType.maxSize() > secretKeyType.minSize());
	}

	private void correctSecretKeySize() {
		SecretKeyType secretKeyType = getSecretKeyType();
		int secretKeySize = getSecretKeySize();

		int validatedSecretKeySize = validateSecretKeySize(secretKeyType, secretKeySize);

		if (validatedSecretKeySize != secretKeySize) {
			jsKeySize.getModel().setValue(validatedSecretKeySize);
		}
	}

	private int validateSecretKeySize(SecretKeyType secretKeyType, int secretKeySize) {
		// Validate against step size
		int stepSize = secretKeyType.stepSize();

		if ((secretKeySize % stepSize) != 0) {
			int difference = secretKeySize % stepSize;

			if (difference <= (stepSize / 2)) {
				secretKeySize -= difference;
			} else {
				secretKeySize += (stepSize - difference);
			}
		}

		// Validate against minimum size
		int minSize = secretKeyType.minSize();

		if (secretKeySize < minSize) {
			secretKeySize = minSize;
		}

		// Validate against maximum size
		int maxSize = secretKeyType.maxSize();

		if (secretKeySize > maxSize) {
			secretKeySize = maxSize;
		}

		return secretKeySize;
	}

	/**
	 * Get the secret key size chosen.
	 *
	 * @return The secret key size
	 */
	public int getSecretKeySize() {
		return ((Number) jsKeySize.getValue()).intValue();
	}

	/**
	 * Get the secret key type chosen.
	 *
	 * @return The secret key generation type
	 */
	public SecretKeyType getSecretKeyType() {
		return ((SecretKeyType) jcbKeyAlg.getSelectedItem());
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
