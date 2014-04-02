/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.gui.net;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;

/**
 * Component to edit an IPv4 address.
 * 
 */
public class JIpAddress extends JPanel {
	private JSpinner jsFirstPart;
	private JLabel jlFirstSeparator;
	private JSpinner jsSecondPart;
	private JLabel jlSecondSeparator;
	private JSpinner jsThirdPart;
	private JLabel jlThirdSeparator;
	private JSpinner jsFourthPart;

	/**
	 * Construct a JIpAddress. Defaults to 0.0.0.0.
	 */
	public JIpAddress() {
		this(null);
	}

	/**
	 * Construct a JIpAddress.
	 * 
	 * @param ipAddress
	 *            IP address
	 */
	public JIpAddress(byte[] ipAddress) {
		initComponents(ipAddress);
	}

	private void initComponents(byte[] ipAddress) {
		jsFirstPart = new JSpinner(new SpinnerNumberModel(0, 0, 255, 1));

		GridBagConstraints gbc_jsFirstPart = new GridBagConstraints();
		gbc_jsFirstPart.gridwidth = 1;
		gbc_jsFirstPart.gridheight = 1;
		gbc_jsFirstPart.gridx = 0;
		gbc_jsFirstPart.gridy = 0;
		gbc_jsFirstPart.insets = new Insets(0, 0, 0, 5);

		jlFirstSeparator = new JLabel(".");

		GridBagConstraints gbc_jlFirstSeparator = new GridBagConstraints();
		gbc_jlFirstSeparator.gridwidth = 1;
		gbc_jlFirstSeparator.gridheight = 1;
		gbc_jlFirstSeparator.gridx = 1;
		gbc_jlFirstSeparator.gridy = 0;
		gbc_jlFirstSeparator.insets = new Insets(0, 0, 0, 5);

		jsSecondPart = new JSpinner(new SpinnerNumberModel(0, 0, 255, 1));

		GridBagConstraints gbc_jsSecondPart = new GridBagConstraints();
		gbc_jsSecondPart.gridwidth = 1;
		gbc_jsSecondPart.gridheight = 1;
		gbc_jsSecondPart.gridx = 2;
		gbc_jsSecondPart.gridy = 0;
		gbc_jsSecondPart.insets = new Insets(0, 0, 0, 5);

		jlSecondSeparator = new JLabel(".");

		GridBagConstraints gbc_jlSecondSeparator = new GridBagConstraints();
		gbc_jlSecondSeparator.gridwidth = 1;
		gbc_jlSecondSeparator.gridheight = 1;
		gbc_jlSecondSeparator.gridx = 3;
		gbc_jlSecondSeparator.gridy = 0;
		gbc_jlSecondSeparator.insets = new Insets(0, 0, 0, 5);

		jsThirdPart = new JSpinner(new SpinnerNumberModel(0, 0, 255, 1));

		GridBagConstraints gbc_jsThirdPart = new GridBagConstraints();
		gbc_jsThirdPart.gridwidth = 1;
		gbc_jsThirdPart.gridheight = 1;
		gbc_jsThirdPart.gridx = 4;
		gbc_jsThirdPart.gridy = 0;
		gbc_jsThirdPart.insets = new Insets(0, 0, 0, 5);

		jlThirdSeparator = new JLabel(".");

		GridBagConstraints gbc_jlThirdSeparator = new GridBagConstraints();
		gbc_jlThirdSeparator.gridwidth = 1;
		gbc_jlThirdSeparator.gridheight = 1;
		gbc_jlThirdSeparator.gridx = 5;
		gbc_jlThirdSeparator.gridy = 0;
		gbc_jlThirdSeparator.insets = new Insets(0, 0, 0, 5);

		jsFourthPart = new JSpinner(new SpinnerNumberModel(0, 0, 255, 1));

		GridBagConstraints gbc_jsFourthPart = new GridBagConstraints();
		gbc_jsFourthPart.gridwidth = 1;
		gbc_jsFourthPart.gridheight = 1;
		gbc_jsFourthPart.gridx = 6;
		gbc_jsFourthPart.gridy = 0;
		gbc_jsFourthPart.insets = new Insets(0, 0, 0, 0);

		setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));

		setLayout(new GridBagLayout());
		add(jsFirstPart, gbc_jsFirstPart);
		add(jlFirstSeparator, gbc_jlFirstSeparator);
		add(jsSecondPart, gbc_jsSecondPart);
		add(jlSecondSeparator, gbc_jlSecondSeparator);
		add(jsThirdPart, gbc_jsThirdPart);
		add(jlThirdSeparator, gbc_jlThirdSeparator);
		add(jsFourthPart, gbc_jsFourthPart);

		setIpAddress(ipAddress);
	}

	/**
	 * Get IP address.
	 * 
	 * @return IP address
	 */
	public byte[] getIpAddress() {
		int firstPart = (Integer) jsFirstPart.getValue();
		int secondPart = (Integer) jsSecondPart.getValue();
		int thirdPart = (Integer) jsThirdPart.getValue();
		int fourthPart = (Integer) jsFourthPart.getValue();

		return new byte[] { (byte) firstPart, (byte) secondPart, (byte) thirdPart, (byte) fourthPart };
	}

	/**
	 * Set IP address.
	 * 
	 * @param ipAddress
	 *            IP address
	 */
	public void setIpAddress(byte[] ipAddress) {
		if (ipAddress != null) {
			jsFirstPart.setValue((int) ipAddress[0]);
			jsSecondPart.setValue((int) ipAddress[1]);
			jsThirdPart.setValue((int) ipAddress[2]);
			jsFourthPart.setValue((int) ipAddress[3]);
		} else {
			jsFirstPart.setValue(0);
			jsSecondPart.setValue(0);
			jsThirdPart.setValue(0);
			jsFourthPart.setValue(0);
		}
	}

	/**
	 * Sets whether or not the component is enabled.
	 * 
	 * @param enabled
	 *            True if this component should be enabled, false otherwise
	 */
	public void setEnabled(boolean enabled) {
		jsFirstPart.setEnabled(enabled);
		jsSecondPart.setEnabled(enabled);
		jsThirdPart.setEnabled(enabled);
		jsFourthPart.setEnabled(enabled);
	}

	/**
	 * Set component's tooltip text.
	 * 
	 * @param toolTipText
	 *            Tooltip text
	 */
	public void setToolTipText(String toolTipText) {
		super.setToolTipText(toolTipText);
		jsFirstPart.setToolTipText(toolTipText);
		jlFirstSeparator.setToolTipText(toolTipText);
		jsSecondPart.setToolTipText(toolTipText);
		jlSecondSeparator.setToolTipText(toolTipText);
		jsThirdPart.setToolTipText(toolTipText);
		jlThirdSeparator.setToolTipText(toolTipText);
		jsFourthPart.setToolTipText(toolTipText);
	}
}
