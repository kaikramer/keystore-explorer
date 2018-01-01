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
package org.kse.gui.crypto.generalsubtree;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
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
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.generalname.JGeneralName;

/**
 * Dialog to choose an general subtree.
 *
 */
public class DGeneralSubtreeChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/generalsubtree/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpGeneralSubtree;
	private JLabel jlBase;
	private JGeneralName jgnBase;
	private JLabel jlMinimum;
	private JTextField jtfMinimum;
	private JLabel jlMaximum;
	private JTextField jtfMaximum;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private GeneralSubtree generalSubtree;

	/**
	 * Constructs a new DGeneralSubtreeChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param generalSubtree
	 *            General subtree
	 */
	public DGeneralSubtreeChooser(JFrame parent, String title, GeneralSubtree generalSubtree) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(generalSubtree);
	}

	/**
	 * Constructs a new DGeneralSubtreeChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param generalSubtree
	 *            General subtree
	 */
	public DGeneralSubtreeChooser(JDialog parent, String title, GeneralSubtree generalSubtree) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(generalSubtree);
	}

	private void initComponents(GeneralSubtree generalSubtree) {
		jlBase = new JLabel(res.getString("DGeneralSubtreeChooser.jlBase.text"));

		GridBagConstraints gbc_jlBase = new GridBagConstraints();
		gbc_jlBase.gridx = 0;
		gbc_jlBase.gridy = 0;
		gbc_jlBase.gridwidth = 1;
		gbc_jlBase.gridheight = 1;
		gbc_jlBase.insets = new Insets(5, 5, 0, 5);
		gbc_jlBase.anchor = GridBagConstraints.EAST;

		jgnBase = new JGeneralName(res.getString("DGeneralSubtreeChooser.Base.Title"));
		jgnBase.setToolTipText(res.getString("DGeneralSubtreeChooser.jgnBase.tooltip"));

		GridBagConstraints gbc_jgnBase = new GridBagConstraints();
		gbc_jgnBase.gridx = 1;
		gbc_jgnBase.gridy = 0;
		gbc_jgnBase.gridwidth = 1;
		gbc_jgnBase.gridheight = 1;
		gbc_jgnBase.insets = new Insets(5, 5, 0, 5);
		gbc_jgnBase.anchor = GridBagConstraints.WEST;

		jlMinimum = new JLabel(res.getString("DGeneralSubtreeChooser.jlMinimum.text"));

		GridBagConstraints gbc_jlMinimum = new GridBagConstraints();
		gbc_jlMinimum.gridx = 0;
		gbc_jlMinimum.gridy = 1;
		gbc_jlMinimum.gridwidth = 1;
		gbc_jlMinimum.gridheight = 1;
		gbc_jlMinimum.insets = new Insets(5, 5, 5, 5);
		gbc_jlMinimum.anchor = GridBagConstraints.EAST;

		jtfMinimum = new JTextField(3);
		jtfMinimum.setToolTipText(res.getString("DGeneralSubtreeChooser.jtfMinimum.tooltip"));

		GridBagConstraints gbc_jtfMinimum = new GridBagConstraints();
		gbc_jtfMinimum.gridx = 1;
		gbc_jtfMinimum.gridy = 1;
		gbc_jtfMinimum.gridwidth = 1;
		gbc_jtfMinimum.gridheight = 1;
		gbc_jtfMinimum.insets = new Insets(5, 5, 5, 5);
		gbc_jtfMinimum.anchor = GridBagConstraints.WEST;

		jlMaximum = new JLabel(res.getString("DGeneralSubtreeChooser.jlMaximum.text"));

		GridBagConstraints gbc_jlMaximum = new GridBagConstraints();
		gbc_jlMaximum.gridx = 0;
		gbc_jlMaximum.gridy = 2;
		gbc_jlMaximum.gridwidth = 1;
		gbc_jlMaximum.gridheight = 1;
		gbc_jlMaximum.insets = new Insets(5, 5, 5, 5);
		gbc_jlMaximum.anchor = GridBagConstraints.EAST;

		jtfMaximum = new JTextField(3);
		jtfMaximum.setToolTipText(res.getString("DGeneralSubtreeChooser.jtfMaximum.tooltip"));

		GridBagConstraints gbc_jtfMaximum = new GridBagConstraints();
		gbc_jtfMaximum.gridx = 1;
		gbc_jtfMaximum.gridy = 2;
		gbc_jtfMaximum.gridwidth = 1;
		gbc_jtfMaximum.gridheight = 1;
		gbc_jtfMaximum.insets = new Insets(5, 5, 5, 5);
		gbc_jtfMaximum.anchor = GridBagConstraints.WEST;

		jpGeneralSubtree = new JPanel(new GridBagLayout());

		jpGeneralSubtree.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpGeneralSubtree.add(jlBase, gbc_jlBase);
		jpGeneralSubtree.add(jgnBase, gbc_jgnBase);
		jpGeneralSubtree.add(jlMinimum, gbc_jlMinimum);
		jpGeneralSubtree.add(jtfMinimum, gbc_jtfMinimum);
		jpGeneralSubtree.add(jlMaximum, gbc_jlMaximum);
		jpGeneralSubtree.add(jtfMaximum, gbc_jtfMaximum);

		jbOK = new JButton(res.getString("DGeneralSubtreeChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DGeneralSubtreeChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpGeneralSubtree);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(generalSubtree);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(GeneralSubtree generalSubtree) {
		if (generalSubtree != null) {
			jgnBase.setGeneralName(generalSubtree.getBase());

			if (generalSubtree.getMinimum() != null) {
				jtfMinimum.setText("" + generalSubtree.getMinimum().intValue());
				jtfMinimum.setCaretPosition(0);
			}

			if (generalSubtree.getMaximum() != null) {
				jtfMaximum.setText("" + generalSubtree.getMaximum().intValue());
				jtfMaximum.setCaretPosition(0);
			}
		}
	}

	/**
	 * Get selected general subtree.
	 *
	 * @return General subtree, or null if none
	 */
	public GeneralSubtree getGeneralSubtree() {
		return generalSubtree;
	}

	private void okPressed() {
		GeneralName base = jgnBase.getGeneralName();

		if (base == null) {
			JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.BaseValueReq.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		int minimum = -1;
		String minimumStr = jtfMinimum.getText().trim();

		if (minimumStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.MinimumValueReq.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		if (minimumStr.length() > 0) {
			try {
				minimum = Integer.parseInt(minimumStr);
			} catch (NumberFormatException ex) {
				JOptionPane.showMessageDialog(this,
						res.getString("DGeneralSubtreeChooser.InvalidMinimumValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (minimum < 0) {
				JOptionPane.showMessageDialog(this,
						res.getString("DGeneralSubtreeChooser.InvalidMinimumValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}
		}

		int maximum = -1;
		String maximumStr = jtfMaximum.getText().trim();

		if (maximumStr.length() > 0) {
			try {
				maximum = Integer.parseInt(maximumStr);
			} catch (NumberFormatException ex) {
				JOptionPane.showMessageDialog(this,
						res.getString("DGeneralSubtreeChooser.InvalidMaximumValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (maximum < 0) {
				JOptionPane.showMessageDialog(this,
						res.getString("DGeneralSubtreeChooser.InvalidMaximumValue.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}
		}


		BigInteger asn1Minimum = (minimum != -1) ? BigInteger.valueOf(minimum) : null;
		BigInteger asn1Maximum = (maximum != -1) ? BigInteger.valueOf(maximum) : null;

		generalSubtree = new GeneralSubtree(base, asn1Minimum, asn1Maximum);

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
