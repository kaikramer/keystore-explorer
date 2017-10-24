/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package org.kse.gui.dialogs.extensions;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.kse.crypto.x509.CRLDistributionPoints;
import org.kse.gui.crypto.crldistributionpoints.JCrlDistributionPointsPanel;

/**
 * Dialog used to add or edit an CRL Distribution Points extension.
 *
 */
public class DCrlDistributionPoints extends DExtensionBase {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");


	private JPanel jpCrlDristributionPoints;
	private JLabel jlDistributionPoints;
	private JCrlDistributionPointsPanel jgsDistributionPoints;

	/**
	 * Creates a new DCrlDistributionPoints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 */
	public DCrlDistributionPoints(JDialog parent) {
		super(parent);

		setTitle(res.getString("DCRLDistributionPoints.Title"));
	}
	public DCrlDistributionPoints(JDialog parent, byte[] prepopulatedValue) throws IOException {
		super(parent, prepopulatedValue);

		setTitle(res.getString("DCRLDistributionPoints.Title"));
	}

	protected void initComponents() {
		super.initComponents();
		
		jlDistributionPoints = new JLabel(res.getString("DCRLDistributionPoints.jlDistributionPoints.text"));

		GridBagConstraints gbc_jlDistributionPoints = new GridBagConstraints();
		gbc_jlDistributionPoints.gridx = 0;
		gbc_jlDistributionPoints.gridy = 0;
		gbc_jlDistributionPoints.gridwidth = 1;
		gbc_jlDistributionPoints.gridheight = 1;
		gbc_jlDistributionPoints.insets = new Insets(5, 5, 5, 5);
		gbc_jlDistributionPoints.anchor = GridBagConstraints.NORTHEAST;

		jgsDistributionPoints = new JCrlDistributionPointsPanel();
		jgsDistributionPoints.setToolTipText(res.getString("DCRLDistributionPoints.jgsDistributionPoints.tooltip"));

		GridBagConstraints gbc_jgsDistributionPoints = new GridBagConstraints();
		gbc_jgsDistributionPoints.gridx = 1;
		gbc_jgsDistributionPoints.gridy = 0;
		gbc_jgsDistributionPoints.gridwidth = 1;
		gbc_jgsDistributionPoints.gridheight = 1;
		gbc_jgsDistributionPoints.insets = new Insets(5, 5, 5, 5);
		gbc_jgsDistributionPoints.anchor = GridBagConstraints.WEST;

		jpCrlDristributionPoints = new JPanel(new GridBagLayout());

		jpCrlDristributionPoints.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpCrlDristributionPoints.add(jlDistributionPoints, gbc_jlDistributionPoints);
		jpCrlDristributionPoints.add(jgsDistributionPoints, gbc_jgsDistributionPoints);


		getContentPane().add(jpCrlDristributionPoints, BorderLayout.CENTER);

		pack();
	}
	

	protected void prepopulateWithValue(byte[] value) throws IOException {
		CRLDistributionPoints crlDistributionPoints = CRLDistributionPoints.getInstance(value);
		for (DistributionPoint row : crlDistributionPoints.getDistributionPointList()) {
			jgsDistributionPoints.getObjectTableModel().addRow(row);
		}
	}

	public ASN1Object getAsn1() {
		return new CRLDistributionPoints(jgsDistributionPoints.getObjectTableModel().getData());
	}
}
