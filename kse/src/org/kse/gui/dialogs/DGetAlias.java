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
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used for entering a KeyStore alias.
 *
 */
public class DGetAlias extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpAlias;
	private JLabel jlAlias;
	private JTextField jtfAlias;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private String alias;

	/**
	 * Creates a new DGetAlias dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog's title
	 * @param alias
	 *            The alias to display initially
	 */
	public DGetAlias(JFrame parent, String title, String alias) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(alias);
	}

	/**
	 * Creates new DGetAlias dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog's title
	 * @param modality
	 *            Is the dialog modal?
	 * @param alias
	 *            The alias to display initially
	 */
	public DGetAlias(JDialog parent, String title, Dialog.ModalityType modality, String alias) {
		super(parent, title, modality);
		initComponents(alias);
	}

	/**
	 * Get the alias entered by the user.
	 *
	 * @return The alias, or null if none was entered
	 */
	public String getAlias() {
		return alias;
	}

	private void initComponents(final String alias) {
		getContentPane().setLayout(new BorderLayout());

		jlAlias = new JLabel(res.getString("DGetAlias.jlAlias.text"));
		jtfAlias = new JTextField(15);

		if (alias != null) {
			jtfAlias.setText(alias);
			jtfAlias.setCaretPosition(0);
		}

		jbOK = new JButton(res.getString("DGetAlias.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGetAlias.jbCancel.text"));
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

		jpAlias = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpAlias.add(jlAlias);
		jpAlias.add(jtfAlias);
		jpAlias.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().add(jpAlias, BorderLayout.CENTER);
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

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				if (alias != null) {
					jbOK.requestFocus();
				} else {
					jtfAlias.requestFocus();
				}
			}
		});
	}

	private boolean checkAlias() {
		String alias = jtfAlias.getText().trim().toLowerCase();

		if (alias.length() > 0) {
			this.alias = alias;
			return true;
		}

		JOptionPane.showMessageDialog(this, res.getString("DGetAlias.AliasReq.message"), getTitle(),
				JOptionPane.WARNING_MESSAGE);
		return false;
	}

	private void okPressed() {
		if (checkAlias()) {
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
