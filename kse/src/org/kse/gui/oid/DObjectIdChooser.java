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
package org.kse.gui.oid;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.oid.InvalidObjectIdException;
import org.kse.utilities.oid.ObjectIdUtil;

/**
 * Dialog to choose an object identifier.
 *
 */
public class DObjectIdChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/oid/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpObjectId;
	private JLabel jlObjectId;
	private JComboBox<?> jcbFirstArc;
	private JLabel jlFirstPeriod;
	private JComboBox<Integer> jcbSecondArc;
	private JTextField jtfRemainingArcs;
	private JLabel jlSecondPeriod;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private ASN1ObjectIdentifier objectId;

	/**
	 * Constructs a new DObjectIdChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param objectId
	 *            Object identifier
	 * @throws InvalidObjectIdException
	 *             If there was a problem with the object identifier
	 */
	public DObjectIdChooser(JFrame parent, String title, ASN1ObjectIdentifier objectId) throws InvalidObjectIdException {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(objectId);
	}

	/**
	 * Constructs a new DObjectIdChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param objectId
	 *            Object identifier
	 * @throws InvalidObjectIdException
	 *             If there was a problem with the object identifier
	 */
	public DObjectIdChooser(JDialog parent, String title, ASN1ObjectIdentifier objectId)
			throws InvalidObjectIdException {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(objectId);
	}

	private void initComponents(ASN1ObjectIdentifier objectId) throws InvalidObjectIdException {
		jlObjectId = new JLabel(res.getString("DObjectIdChooser.jlObjectId.text"));

		jcbFirstArc = new JComboBox<Object>(new Integer[] { 0, 1, 2 });
		jcbFirstArc.setToolTipText(res.getString("DObjectIdChooser.jcbFirstArc.tooltip"));

		jlFirstPeriod = new JLabel(".");

		jcbSecondArc = new JComboBox<Integer>();
		jcbSecondArc.setToolTipText(res.getString("DObjectIdChooser.jcbSecondArc.tooltip"));

		jlSecondPeriod = new JLabel(".");

		jtfRemainingArcs = new JTextField(15);
		jtfRemainingArcs.setToolTipText(res.getString("DObjectIdChooser.jtfRemainingArcs.tooltip"));

		populateSecondArc();

		jcbFirstArc.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				populateSecondArc();
			}
		});

		jpObjectId = new JPanel(new FlowLayout());

		jpObjectId.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpObjectId.add(jlObjectId);
		jpObjectId.add(jcbFirstArc);
		jpObjectId.add(jlFirstPeriod);
		jpObjectId.add(jcbSecondArc);
		jpObjectId.add(jlSecondPeriod);
		jpObjectId.add(jtfRemainingArcs);

		jbOK = new JButton(res.getString("DObjectIdChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DObjectIdChooser.jbCancel.text"));
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
		getContentPane().add(BorderLayout.CENTER, jpObjectId);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(objectId);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(ASN1ObjectIdentifier objectId) throws InvalidObjectIdException {
		if (objectId == null) {
			populateSecondArc();
		} else {
			ObjectIdUtil.validate(objectId);
			int[] arcs = ObjectIdUtil.extractArcs(objectId);

			jcbFirstArc.setSelectedItem(arcs[0]);
			jcbSecondArc.setSelectedItem(arcs[1]);

			String remainingArcs = "";

			for (int i = 2; i < arcs.length; i++) {
				remainingArcs += arcs[i];

				if ((i + 1) < arcs.length) {
					remainingArcs += ".";
				}
			}

			jtfRemainingArcs.setText(remainingArcs);
		}
	}

	private void populateSecondArc() {
		int firstArc = (Integer) jcbFirstArc.getSelectedItem();
		int secondArc = jcbSecondArc.getSelectedIndex();
		int maxSecondArc;

		if ((firstArc == 0) || (firstArc == 1)) {
			maxSecondArc = 39;
		} else
			// firstArc == 2
		{
			maxSecondArc = 47;
		}

		jcbSecondArc.removeAllItems();

		for (int i = 0; i <= maxSecondArc; i++) {
			jcbSecondArc.addItem(i);
		}

		if ((secondArc != -1) && (secondArc <= maxSecondArc)) {
			jcbSecondArc.setSelectedIndex(secondArc);
		} else {
			jcbSecondArc.setSelectedIndex(0);
		}
	}

	/**
	 * Get selected object identifier name.
	 *
	 * @return Object identifier, or null if none
	 */
	public ASN1ObjectIdentifier getObjectId() {
		return objectId;
	}

	private void okPressed() {
		String firstArc = "" + jcbFirstArc.getSelectedItem();
		String secondArc = "" + jcbSecondArc.getSelectedItem();
		String remainingArcs = jtfRemainingArcs.getText().trim();

		ASN1ObjectIdentifier newObjectId = new ASN1ObjectIdentifier(firstArc + "." + secondArc + "." + remainingArcs);

		try {
			ObjectIdUtil.validate(newObjectId);
		} catch (InvalidObjectIdException e) {
			JOptionPane.showMessageDialog(this, e.getMessage(), getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		objectId = newObjectId;

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
