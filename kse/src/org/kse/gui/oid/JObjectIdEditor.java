/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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

import java.util.ResourceBundle;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.utilities.oid.InvalidObjectIdException;
import org.kse.utilities.oid.ObjectIdUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Swing component for editing an OID
 */
public class JObjectIdEditor extends JPanel {

	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/oid/resources");

	private JComboBox<?> jcbFirstArc;
	private JLabel jlFirstPeriod;
	private JComboBox<Integer> jcbSecondArc;
	private JTextField jtfRemainingArcs;
	private JLabel jlSecondPeriod;

	private ASN1ObjectIdentifier objectId;

	/**
	 * Constructor
	 */
	public JObjectIdEditor() {
		super();

		try {
			initComponents();
		} catch (InvalidObjectIdException e) {
			// cannot happen here
		}
	}

	/**
	 * Constructor with optional OID
	 *
	 * @param objectId An OID or null when component should be empty
	 * @throws InvalidObjectIdException If given OID is invalid
	 */
	public JObjectIdEditor(ASN1ObjectIdentifier objectId) throws InvalidObjectIdException {
		super();
		this.objectId = objectId;
		initComponents();
	}

	private void initComponents() throws InvalidObjectIdException {
		jcbFirstArc = new JComboBox<>(new Integer[] { 0, 1, 2 });
		jcbFirstArc.setToolTipText(res.getString("DObjectIdChooser.jcbFirstArc.tooltip"));

		jlFirstPeriod = new JLabel(".");

		jcbSecondArc = new JComboBox<>();
		jcbSecondArc.setToolTipText(res.getString("DObjectIdChooser.jcbSecondArc.tooltip"));

		jlSecondPeriod = new JLabel(".");

		jtfRemainingArcs = new JTextField(15);
		jtfRemainingArcs.setToolTipText(res.getString("DObjectIdChooser.jtfRemainingArcs.tooltip"));

		populateSecondArc();

		jcbFirstArc.addItemListener(e -> populateSecondArc());

		// layout
		setLayout(new MigLayout("insets 0", "", ""));
		add(jcbFirstArc, "");
		add(jlFirstPeriod, "");
		add(jcbSecondArc, "");
		add(jlSecondPeriod, "");
		add(jtfRemainingArcs, "");

		populate(objectId);
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
		} else {
			// firstArc == 2
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
	 * @throws InvalidObjectIdException If not a valid OID
	 */
	public ASN1ObjectIdentifier getObjectId() throws InvalidObjectIdException {
		String firstArc = "" + jcbFirstArc.getSelectedItem();
		String secondArc = "" + jcbSecondArc.getSelectedItem();
		String remainingArcs = jtfRemainingArcs.getText().trim();

		ASN1ObjectIdentifier newObjectId = new ASN1ObjectIdentifier(firstArc + "." + secondArc + "." + remainingArcs);
		ObjectIdUtil.validate(newObjectId);
		objectId = newObjectId;

		return objectId;
	}

	/**
	 * Set new object identifier.
	 *
	 * @param oid New object identifier
	 * @throws InvalidObjectIdException If not a valid OID
	 */
	public void setObjectId(ASN1ObjectIdentifier oid) throws InvalidObjectIdException {
		this.objectId = oid;
		populate(oid);
	}
}
