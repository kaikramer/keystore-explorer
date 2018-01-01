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

import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Collections;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSpinner;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.UIManager;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.kse.crypto.ecc.CurveSet;
import org.kse.crypto.ecc.EccUtil;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to choose the parameters required for key pair generation. The
 * user may select an asymmetric key generation algorithm of RSA or DSA and
 * enter a key size in bits.
 *
 */
public class DGenerateKeyPair extends JEscDialog {

	private static final long serialVersionUID = 7178673779995142190L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JRadioButton jrbRSA;
	private JLabel jlRSAKeySize;
	private JSpinner jspRSAKeySize;

	private JRadioButton jrbDSA;
	private JLabel jlDSAKeySize;
	private JSpinner jspDSAKeySize;

	private JRadioButton jrbEC;
	private JLabel jlECCurveSet;
	private JComboBox<String> jcbECCurveSet;
	private JLabel jlECCurve;
	private JComboBox<String> jcbECCurve;

	private JButton jbOK;
	private JButton jbCancel;

	private KeyPairType keyPairType;
	private KeyStoreType keyStoreType;
	private int keyPairSize;
	private boolean success = false;


	/**
	 * Creates a new DGenerateKeyPair dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param keyStoreType
	 *            Type of the key store for the new ke pair
	 * @param keyPairType
	 *            Initial key pair type
	 * @param keyPairSize
	 *            Initial key pair size
	 */
	public DGenerateKeyPair(JFrame parent, KeyStoreType keyStoreType, KeyPairType keyPairType, int keyPairSize) {
		super(parent, res.getString("DGenerateKeyPair.Title"), Dialog.ModalityType.DOCUMENT_MODAL);

		this.keyPairType = keyPairType;
		this.keyPairSize = keyPairSize;
		this.keyStoreType = keyStoreType;

		initComponents();
	}

	private void initComponents() {
		jlRSAKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));

		jspRSAKeySize = new JSpinner();
		jspRSAKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));

		jlDSAKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));

		jspDSAKeySize = new JSpinner();
		jspDSAKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));

		jrbRSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbRSA.text"), false);
		PlatformUtil.setMnemonic(jrbRSA, res.getString("DGenerateKeyPair.jrbRSA.mnemonic").charAt(0));
		jrbRSA.setToolTipText(res.getString("DGenerateKeyPair.jrbRSA.tooltip"));

		jrbDSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbDSA.text"), true);
		PlatformUtil.setMnemonic(jrbDSA, res.getString("DGenerateKeyPair.jrbDSA.mnemonic").charAt(0));
		jrbDSA.setToolTipText(res.getString("DGenerateKeyPair.jrbDSA.tooltip"));

		jrbEC = new JRadioButton(res.getString("DGenerateKeyPair.jrbEC.text"), true);
		PlatformUtil.setMnemonic(jrbEC, res.getString("DGenerateKeyPair.jrbEC.mnemonic").charAt(0));

		// EC available?
		if (EccUtil.isECAvailable(keyStoreType)) {
			jrbEC.setEnabled(true);
			jrbEC.setToolTipText(res.getString("DGenerateKeyPair.jrbEC.tooltip"));
		} else {
			jrbEC.setEnabled(false);
			jrbEC.setToolTipText(res.getString("DGenerateKeyPair.jrbEC.na.tooltip"));
		}

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbRSA);
		buttonGroup.add(jrbDSA);
		buttonGroup.add(jrbEC);

		jlECCurveSet = new JLabel(res.getString("DGenerateKeyPair.jlECCurveSet.text"));
		jlECCurveSet.setToolTipText(res.getString("DGenerateKeyPair.jlECCurveSet.tooltip"));

		jcbECCurveSet = new JComboBox<String>();
		jcbECCurveSet.setModel(new DefaultComboBoxModel<String>(CurveSet.getAvailableSetNames(keyStoreType)));
		jcbECCurveSet.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurveSet.tooltip"));

		jlECCurve = new JLabel(res.getString("DGenerateKeyPair.jlECCurve.text"));
		jlECCurve.setToolTipText(res.getString("DGenerateKeyPair.jlECCurve.tooltip"));

		jcbECCurve = new JComboBox<String>();
		// make combo box wide enough for longest curve name
		jcbECCurve.setPrototypeDisplayValue(EccUtil.findLongestCurveName());
		jcbECCurve.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurve.tooltip"));

		jbCancel = new JButton(res.getString("DGenerateKeyPair.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jbOK = new JButton(res.getString("DGenerateKeyPair.jbOK.text"));

		if (keyPairType == KeyPairType.RSA) {
			jrbRSA.setSelected(true);
		} else if (keyPairType == KeyPairType.DSA) {
			jrbDSA.setSelected(true);
		} else {
			if (jrbEC.isEnabled()) {
				jrbDSA.setSelected(true);
			} else {
				// EC not available => fall back to RSA
				jrbRSA.setSelected(true);
			}
		}

		loadKeySizes(keyPairSize);
		loadECNamedCurves((String) jcbECCurveSet.getModel().getSelectedItem());
		enableDisableElements();

		JPanel jpContent = new JPanel();
		jpContent.setBorder(new TitledBorder(new EtchedBorder(), res.getString("DGenerateKeyPair.jpContent.text")));
		//jpContent.setBorder(BorderFactory.createTitledBorder(res.getString("DGenerateKeyPair.jpContent.text")));
		JPanel buttons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		// layout
		getContentPane().setLayout(new MigLayout("fill", "", "para[]"));
		getContentPane().add(jpContent, "wrap unrel");
		getContentPane().add(buttons, "growx");
		jpContent.setLayout(new MigLayout("insets dialog, ", "[][right][]", "[]unrel[]"));
		jpContent.add(jrbRSA, "");
		jpContent.add(jlRSAKeySize, "");
		jpContent.add(jspRSAKeySize, "growx, wrap");
		jpContent.add(jrbDSA, "");
		jpContent.add(jlDSAKeySize, "");
		jpContent.add(jspDSAKeySize, "growx, wrap");
		jpContent.add(jrbEC, "");
		jpContent.add(jlECCurveSet, "");
		jpContent.add(jcbECCurveSet, "growx, wrap");
		jpContent.add(jlECCurve, "skip");
		jpContent.add(jcbECCurve, "growx");


		jcbECCurveSet.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				loadECNamedCurves((String) jcbECCurveSet.getModel().getSelectedItem());
			}
		});

		jrbRSA.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				enableDisableElements();
			}
		});

		jrbDSA.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				enableDisableElements();
			}
		});

		jrbEC.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				enableDisableElements();
			}
		});

		jspRSAKeySize.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent evt) {
				correctKeyPairSize();
			}
		});

		jspDSAKeySize.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent evt) {
				correctKeyPairSize();
			}
		});

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

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

	private void loadECNamedCurves(String curveSet) {
		CurveSet set = CurveSet.resolveName(curveSet);
		List<String> curveNames = set.getAvailableCurveNames(keyStoreType);

		Collections.sort(curveNames);

		jcbECCurve.setModel(new DefaultComboBoxModel<String>(curveNames.toArray(new String[curveNames.size()])));
	}

	protected void enableDisableElements() {
		KeyPairType keyPairType = getKeyPairType();

		jlRSAKeySize.setEnabled(keyPairType == KeyPairType.RSA);
		jspRSAKeySize.setEnabled(keyPairType == KeyPairType.RSA);

		jlDSAKeySize.setEnabled(keyPairType == KeyPairType.DSA);
		jspDSAKeySize.setEnabled(keyPairType == KeyPairType.DSA);

		jlECCurve.setEnabled(keyPairType == KeyPairType.EC);
		jcbECCurve.setEnabled(keyPairType == KeyPairType.EC);
		jlECCurveSet.setEnabled(keyPairType == KeyPairType.EC);
		jcbECCurveSet.setEnabled(keyPairType == KeyPairType.EC);
	}

	private void loadKeySizes(int keyPairSize) {
		KeyPairType keyPairType = KeyPairType.RSA;
		keyPairSize = validateKeyPairSize(keyPairType, keyPairSize);
		jspRSAKeySize.setModel(new SpinnerNumberModel(keyPairSize, keyPairType.minSize(), keyPairType.maxSize(),
				keyPairType.stepSize()));

		keyPairType = KeyPairType.DSA;
		keyPairSize = validateKeyPairSize(keyPairType, keyPairSize);
		jspDSAKeySize.setModel(new SpinnerNumberModel(keyPairSize, keyPairType.minSize(), keyPairType.maxSize(),
				keyPairType.stepSize()));
	}

	private void correctKeyPairSize() {
		KeyPairType keyPairType = getKeyPairType();
		int keyPairSize = getKeyPairSize();

		int validatedKeyPairSize = validateKeyPairSize(keyPairType, keyPairSize);

		if (validatedKeyPairSize != keyPairSize) {
			if (keyPairType == KeyPairType.RSA) {
				jspRSAKeySize.getModel().setValue(validatedKeyPairSize);
			} else if (keyPairType == KeyPairType.DSA) {
				jspDSAKeySize.getModel().setValue(validatedKeyPairSize);
			}
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

		if  (getKeyPairType() == KeyPairType.RSA) {
			return ((Number) jspRSAKeySize.getValue()).intValue();
		}
		if  (getKeyPairType() == KeyPairType.DSA) {
			return ((Number) jspDSAKeySize.getValue()).intValue();
		}

		return this.keyPairSize;
	}

	/**
	 * Get the name of the selected curve.
	 *
	 * @return The curve name
	 */
	public String getCurveName() {
		return (String) jcbECCurve.getModel().getSelectedItem();
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

		if (jrbDSA.isSelected()) {
			return KeyPairType.DSA;
		}

		return KeyPairType.EC;

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

	// for quick UI testing
	public static void main(String[] args) throws Exception {
		UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");

		java.awt.EventQueue.invokeLater(new Runnable() {

			@Override
			public void run() {
				DGenerateKeyPair dialog = new DGenerateKeyPair(new JFrame(), KeyStoreType.JKS, KeyPairType.RSA, 1024);
				dialog.addWindowListener(new java.awt.event.WindowAdapter() {

					@Override
					public void windowClosing(java.awt.event.WindowEvent e) {
						System.exit(0);
					}
				});
				dialog.setVisible(true);
			}
		});
	}
}
