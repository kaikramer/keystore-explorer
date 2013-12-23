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

import java.awt.Dialog;
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
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JSpinner;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.UIManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import net.miginfocom.swing.MigLayout;
import net.sf.keystore_explorer.crypto.keypair.KeyPairType;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;

/**
 * Dialog used to choose the parameters required for key pair generation. The
 * user may select an asymmetric key generation algorithm of RSA or DSA and
 * enter a key size in bits.
 * 
 */
public class DGenerateKeyPair extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JRadioButton jrbRSA;
	private JLabel jlRSAKeySize;
	private JSpinner jspRSAKeySize;

	private JRadioButton jrbDSA;
	private JLabel jlDSAKeySize;
	private JSpinner jspDSAKeySize;
	
	private JRadioButton jrbEC;
	private JLabel jlECCurveSet;
	private JComboBox jcbECCurveSet;
	private JLabel jlECCurve;
	private JComboBox jcbECCurve;
	
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
		JLabel jlKeyAlg = new JLabel(res.getString("DGenerateKeyPair.jlKeyAlg.text"));

		jlRSAKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));
		
		jspRSAKeySize = new JSpinner();
		jspRSAKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));
		jspRSAKeySize.setModel(new SpinnerNumberModel(keyPairSize, KeyPairType.RSA.minSize(), KeyPairType.RSA.maxSize(),
				KeyPairType.RSA.stepSize()));

		jlDSAKeySize = new JLabel(res.getString("DGenerateKeyPair.jlKeySize.text"));

		jspDSAKeySize = new JSpinner();
		jspDSAKeySize.setToolTipText(res.getString("DGenerateKeyPair.jsKeySize.tooltip"));
		jspDSAKeySize.setModel(new SpinnerNumberModel(keyPairSize, KeyPairType.DSA.minSize(), KeyPairType.DSA.maxSize(),
				KeyPairType.DSA.stepSize()));

		jrbRSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbRSA.text"), false);
		PlatformUtil.setMnemonic(jrbRSA, res.getString("DGenerateKeyPair.jrbRSA.mnemonic").charAt(0));
		jrbRSA.setToolTipText(res.getString("DGenerateKeyPair.jrbRSA.tooltip"));

		jrbDSA = new JRadioButton(res.getString("DGenerateKeyPair.jrbDSA.text"), true);
		PlatformUtil.setMnemonic(jrbDSA, res.getString("DGenerateKeyPair.jrbDSA.mnemonic").charAt(0));
		jrbDSA.setToolTipText(res.getString("DGenerateKeyPair.jrbDSA.tooltip"));

		jrbEC = new JRadioButton(res.getString("DGenerateKeyPair.jrbEC.text"), true);
		PlatformUtil.setMnemonic(jrbEC, res.getString("DGenerateKeyPair.jrbEC.mnemonic").charAt(0));
		jrbEC.setToolTipText(res.getString("DGenerateKeyPair.jrbEC.tooltip"));

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbRSA);
		buttonGroup.add(jrbDSA);
		buttonGroup.add(jrbEC);

		jlECCurveSet = new JLabel("Set:");
	 
		jcbECCurveSet = new JComboBox();
		jcbECCurveSet.setModel(new DefaultComboBoxModel(new String[] { "ANSI X9.62 (F p)", "ANSI X9.62 (F 2m)",
				"SEC / NIST (F p)", "SEC / NIST (F 2m)", "Teletrust (F 2m)" }));
		jcbECCurveSet.setMaximumRowCount(20);
		
		jlECCurve = new JLabel("Named Curve:");
		
		jcbECCurve = new JComboBox();
		jcbECCurve.setModel(new DefaultComboBoxModel(new String[] { "prime192v1 (192 bits)", "prime192v2 (192 bits)",
				"prime192v3 (192 bits)", "prime239v1 (239 bits)", "prime239v2 (239 bits)", "prime239v3 (239 bits)",
				"prime256v1 (256 bits)" }));
		
		jbCancel = new JButton(res.getString("DGenerateKeyPair.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jbOK = new JButton(res.getString("DGenerateKeyPair.jbOK.text"));
		
		if (keyPairType == KeyPairType.RSA) {
			jrbRSA.setSelected(true);
		} else if (keyPairType == KeyPairType.DSA) {
			jrbDSA.setSelected(true);
		} else {
			jrbEC.setSelected(true);
		}

		loadKeySizes(keyPairSize);
		loadECNamedCurves();
		enableDisableElements();
		
		// layout
		getContentPane().setLayout(new MigLayout("", "[][right][]", ""));
		getContentPane().add(jrbRSA, "");
		getContentPane().add(jlRSAKeySize, "");
		getContentPane().add(jspRSAKeySize, "sg, wrap unrel");
		getContentPane().add(jrbDSA, "");
		getContentPane().add(jlDSAKeySize, "");
		getContentPane().add(jspDSAKeySize, "sg, wrap unrel");
		getContentPane().add(jrbEC, "");
		getContentPane().add(jlECCurveSet, "");
		getContentPane().add(jcbECCurveSet, "growx, wrap");
		getContentPane().add(jlECCurve, "skip");
		getContentPane().add(jcbECCurve, "growx, wrap unrel:push");
		getContentPane().add(jbCancel, "spanx, split, tag cancel");
		getContentPane().add(jbOK, "tag ok");


		jrbRSA.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				loadKeySizes(getKeyPairSize());
				enableDisableElements();
			}
		});

		jrbDSA.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				loadKeySizes(getKeyPairSize());
				enableDisableElements();
			}
		});

		jrbEC.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				loadKeySizes(getKeyPairSize());
				enableDisableElements();
			}
		});

		jspRSAKeySize.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent evt) {
				correctKeyPairSize();
			}
		});

		jspDSAKeySize.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent evt) {
				correctKeyPairSize();
			}
		});

		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void loadECNamedCurves() {
		
		
         X962NamedCurves.getNames();
         SECNamedCurves.getNames();
         NISTNamedCurves.getNames();
         TeleTrusTNamedCurves.getNames();
		
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
		KeyPairType keyPairType = getKeyPairType();
		keyPairSize = validateKeyPairSize(keyPairType, keyPairSize);

		if (keyPairType == KeyPairType.RSA) {
			jspRSAKeySize.setModel(new SpinnerNumberModel(keyPairSize, keyPairType.minSize(), keyPairType.maxSize(),
				keyPairType.stepSize()));
		} else if (keyPairType == KeyPairType.DSA) {
			jspDSAKeySize.setModel(new SpinnerNumberModel(keyPairSize, keyPairType.minSize(), keyPairType.maxSize(),
				keyPairType.stepSize()));
		}
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
		return 0;
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

			public void run() {
				DGenerateKeyPair dialog = new DGenerateKeyPair(new JFrame(), KeyPairType.RSA, 1024);
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
