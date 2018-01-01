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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.KeyPair;
import java.security.Provider;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

/**
 * Generates a key pair which the user may cancel at any time by pressing the
 * cancel button.
 *
 */
public class DGeneratingKeyPair extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpGenKeyPair;
	private JLabel jlGenKeyPair;
	private JPanel jpProgress;
	private JProgressBar jpbGenKeyPair;
	private JPanel jpCancel;
	private JButton jbCancel;

	private KeyPairType keyPairType;
	private int keySize;
	private String curveName;
	private KeyPair keyPair;
	private Thread generator;

	private Provider provider;

	/**
	 * Creates a new DGeneratingKeyPair dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param keyPairType
	 *            The key pair generation type
	 * @param keySize
	 *            The key size to generate
	 */
	public DGeneratingKeyPair(JFrame parent, KeyPairType keyPairType, int keySize, Provider provider) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.keyPairType = keyPairType;
		this.keySize = keySize;
		this.provider = provider;
		initComponents();
	}

	/**
	 * Creates a new DGeneratingKeyPair dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param keyPairType
	 *            The key pair generation type
	 * @param curveName
	 *            The name of the curve to create
	 */
	public DGeneratingKeyPair(JFrame parent, KeyPairType keyPairType, String curveName, Provider provider) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.keyPairType = keyPairType;
		this.curveName = curveName;
		this.provider = provider;
		initComponents();
	}

	private void initComponents() {
		jlGenKeyPair = new JLabel(res.getString("DGeneratingKeyPair.jlGenKeyPair.text"));
		ImageIcon icon = new ImageIcon(getClass().getResource(res.getString("DGeneratingKeyPair.jlGenKeyPair.image")));
		jlGenKeyPair.setIcon(icon);
		jlGenKeyPair.setHorizontalTextPosition(SwingConstants.LEADING);
		jlGenKeyPair.setIconTextGap(15);

		jpGenKeyPair = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpGenKeyPair.add(jlGenKeyPair);
		jpGenKeyPair.setBorder(new EmptyBorder(5, 5, 5, 5));

		jpbGenKeyPair = new JProgressBar();
		jpbGenKeyPair.setIndeterminate(true);

		jpProgress = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpProgress.add(jpbGenKeyPair);
		jpProgress.setBorder(new EmptyBorder(5, 5, 5, 5));

		jbCancel = new JButton(res.getString("DGeneratingKeyPair.jbCancel.text"));
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

		jpCancel = PlatformUtil.createDialogButtonPanel(jbCancel, false);

		getContentPane().add(jpGenKeyPair, BorderLayout.NORTH);
		getContentPane().add(jpProgress, BorderLayout.CENTER);
		getContentPane().add(jpCancel, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				if ((generator != null) && (generator.isAlive())) {
					generator.interrupt();
				}
				closeDialog();
			}
		});

		setTitle(res.getString("DGeneratingKeyPair.Title"));
		setResizable(false);

		pack();
	}

	/**
	 * Start key pair generation in a separate thread.
	 */
	public void startKeyPairGeneration() {
		generator = new Thread(new GenerateKeyPair());
		generator.setPriority(Thread.MIN_PRIORITY);
		generator.start();
	}

	private void cancelPressed() {
		if ((generator != null) && (generator.isAlive())) {
			generator.interrupt();
		}
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	/**
	 * Get the generated key pair.
	 *
	 * @return The generated key pair or null if the user cancelled the dialog
	 *         or an error occurred
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

	private class GenerateKeyPair implements Runnable {
		@Override
		public void run() {
			try {
				// RSA, DSA or EC?
				if (keyPairType != KeyPairType.EC) {
					keyPair = KeyPairUtil.generateKeyPair(keyPairType, keySize, provider);
				} else {
					keyPair = KeyPairUtil.generateECKeyPair(curveName, provider);
				}

				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						if (DGeneratingKeyPair.this.isShowing()) {
							closeDialog();
						}
					}
				});
			} catch (final Exception ex) {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						if (DGeneratingKeyPair.this.isShowing()) {
							DError dError = new DError(DGeneratingKeyPair.this, ex);
							dError.setLocationRelativeTo(DGeneratingKeyPair.this);
							dError.setVisible(true);
							closeDialog();
						}
					}
				});
			}
		}
	}
}
