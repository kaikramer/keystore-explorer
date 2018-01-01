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
package org.kse.gui.password;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;

import org.kse.crypto.Password;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used for entering and confirming a password.
 *
 */
public class DGetNewPassword extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/password/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpPassword;
	private JLabel jlFirst;
	private JComponent jpfFirst;
	private JLabel jlConfirm;
	private JPasswordField jpfConfirm;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private PasswordQualityConfig passwordQualityConfig;
	private Password password;

	/**
	 * Creates new DGetNewPassword dialog where the parent is a frame.
	 *
	 * @param parent
	 *            Parent frame
	 * @param modality
	 *            Dialog modality
	 * @param passwordQualityConfig
	 *            Password quality configuration
	 */
	public DGetNewPassword(JFrame parent, Dialog.ModalityType modality, PasswordQualityConfig passwordQualityConfig) {
		super(parent, res.getString("DGetNewPassword.Title"), modality);

		this.passwordQualityConfig = passwordQualityConfig;

		initComponents();
	}

	/**
	 * Creates new DGetNewPassword dialog where the parent is a frame.
	 *  @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog's title
	 * @param passwordQualityConfig
	 */
	public DGetNewPassword(JFrame parent, String title,
			PasswordQualityConfig passwordQualityConfig) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);

		this.passwordQualityConfig = passwordQualityConfig;

		initComponents();
	}

	/**
	 * Creates new DGetNewPassword dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param modality
	 *            Dialog modality
	 * @param passwordQualityConfig
	 *            Password quality configuration
	 */
	public DGetNewPassword(JDialog parent, Dialog.ModalityType modality, PasswordQualityConfig passwordQualityConfig) {
		this(parent, res.getString("DGetNewPassword.Title"), modality, passwordQualityConfig);
	}

	/**
	 * Creates new DGetNewPassword dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog's title
	 * @param modality
	 *            Dialog modality
	 * @param passwordQualityConfig
	 *            Password quality configuration
	 */
	public DGetNewPassword(JDialog parent, String title, Dialog.ModalityType modality,
			PasswordQualityConfig passwordQualityConfig) {
		super(parent, title, modality);

		this.passwordQualityConfig = passwordQualityConfig;

		initComponents();
	}

	private void initComponents() {
		getContentPane().setLayout(new BorderLayout());

		jlFirst = new JLabel(res.getString("DGetNewPassword.jlFirst.text"));
		GridBagConstraints gbc_jlFirst = new GridBagConstraints();
		gbc_jlFirst.gridx = 0;
		gbc_jlFirst.gridy = 0;
		gbc_jlFirst.anchor = GridBagConstraints.EAST;
		gbc_jlFirst.insets = new Insets(5, 5, 5, 5);

		jlConfirm = new JLabel(res.getString("DGetNewPassword.jlConfirm.text"));
		GridBagConstraints gbc_jpfFirst = new GridBagConstraints();
		gbc_jpfFirst.gridx = 1;
		gbc_jpfFirst.gridy = 0;
		gbc_jpfFirst.anchor = GridBagConstraints.WEST;
		gbc_jpfFirst.insets = new Insets(5, 5, 5, 5);

		if (passwordQualityConfig.getEnabled()) {
			if (passwordQualityConfig.getEnforced()) {
				jpfFirst = new JPasswordQualityField(15, passwordQualityConfig.getMinimumQuality());
			} else {
				jpfFirst = new JPasswordQualityField(15);
			}
		} else {
			jpfFirst = new JPasswordField(15);
		}

		GridBagConstraints gbc_jlConfirm = new GridBagConstraints();
		gbc_jlConfirm.gridx = 0;
		gbc_jlConfirm.gridy = 1;
		gbc_jlConfirm.anchor = GridBagConstraints.EAST;
		gbc_jlConfirm.insets = new Insets(5, 5, 5, 5);

		jpfConfirm = new JPasswordField(15);
		GridBagConstraints gbc_jpfConfirm = new GridBagConstraints();
		gbc_jpfConfirm.gridx = 1;
		gbc_jpfConfirm.gridy = 1;
		gbc_jpfConfirm.anchor = GridBagConstraints.WEST;
		gbc_jpfConfirm.insets = new Insets(5, 5, 5, 5);

		jpPassword = new JPanel(new GridBagLayout());
		jpPassword.add(jlFirst, gbc_jlFirst);
		jpPassword.add(jpfFirst, gbc_jpfFirst);

		jpPassword.add(jlConfirm, gbc_jlConfirm);
		jpPassword.add(jpfConfirm, gbc_jpfConfirm);
		jpPassword.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jbOK = new JButton(res.getString("DGetNewPassword.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGetNewPassword.jbCancel.text"));
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

		getContentPane().add(jpPassword, BorderLayout.CENTER);
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

		// fix for focus issues: request focus after dialog was made visible
		jpfFirst.addAncestorListener(new AncestorListener() {
			@Override
			public void ancestorRemoved(AncestorEvent event) {
			}
			@Override
			public void ancestorMoved(AncestorEvent event) {
			}
			@Override
			public void ancestorAdded(AncestorEvent event) {
				JComponent component = event.getComponent();
				component.requestFocusInWindow();
			}
		});
	}

	/**
	 * Get the password set in the dialog.
	 *
	 * @return The password or null if none was set
	 */
	public Password getPassword() {
		return password;
	}

	private boolean checkPassword() {
		Password firstPassword;

		if (jpfFirst instanceof JPasswordQualityField) {
			char[] firstPasswordChars = ((JPasswordQualityField) jpfFirst).getPassword();

			if (firstPasswordChars == null) {
				JOptionPane.showMessageDialog(this, res.getString("MinimumPasswordQualityNotMet.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return false;
			}

			firstPassword = new Password(firstPasswordChars);
		} else {
			firstPassword = new Password(((JPasswordField) jpfFirst).getPassword());
		}

		Password confirmPassword = new Password(jpfConfirm.getPassword());

		if (firstPassword.equals(confirmPassword)) {
			password = firstPassword;
			return true;
		}

		JOptionPane.showMessageDialog(this, res.getString("PasswordsNoMatch.message"), getTitle(),
				JOptionPane.WARNING_MESSAGE);

		return false;
	}

	private void okPressed() {
		if (checkPassword()) {
			closeDialog();
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
