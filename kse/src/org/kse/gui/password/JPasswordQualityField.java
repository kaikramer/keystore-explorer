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

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JPanel;
import javax.swing.JPasswordField;

/**
 * Password field with quality meter.
 *
 */
public class JPasswordQualityField extends JPanel {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/password/resources");

	private JPasswordField jpfPassword;
	private JPasswordQualityMeter jpqmQuality;

	private int minPasswordQuality = -1;
	private int passwordQuality = 0;

	/**
	 * Creates a new instance of JPasswordQualityField with no minimum quality.
	 *
	 * @param columns
	 *            Number of columns in password field
	 */
	public JPasswordQualityField(int columns) {
		initComponents(columns);
	}

	/**
	 * Creates a new instance of JPasswordQualityField with a minimum quality.
	 *
	 * @param columns
	 *            Number of columns in password field
	 * @param minPasswordQuality
	 *            Minimum password quality
	 * @throws IllegalArgumentException
	 *             If iMinimumQuality is not a value in the range 0-100
	 */
	public JPasswordQualityField(int columns, int minPasswordQuality) throws IllegalArgumentException {
		if ((minPasswordQuality < 0) || (minPasswordQuality > 100)) {
			throw new IllegalArgumentException(res.getString("MinimumPasswordQualityInvalid.message"));
		}

		this.minPasswordQuality = minPasswordQuality;

		initComponents(columns);
	}

	private void initComponents(int columns) {
		jpfPassword = new JPasswordField(columns);

		GridBagConstraints gbc_jpfPassword = new GridBagConstraints();
		gbc_jpfPassword.gridwidth = 1;
		gbc_jpfPassword.gridheight = 1;
		gbc_jpfPassword.gridx = 0;
		gbc_jpfPassword.gridy = 0;
		gbc_jpfPassword.insets = new Insets(0, 0, 1, 0);
		gbc_jpfPassword.fill = GridBagConstraints.HORIZONTAL;

		if (getMinPasswordQuality() >= 0) {
			jpqmQuality = new JPasswordQualityMeter(getMinPasswordQuality());
		} else {
			jpqmQuality = new JPasswordQualityMeter();
		}
		jpqmQuality.setPreferredSize(new Dimension(0, 6));

		initQualityBar();

		GridBagConstraints gbc_jpbQuality = new GridBagConstraints();
		gbc_jpbQuality.gridwidth = 1;
		gbc_jpbQuality.gridheight = 1;
		gbc_jpbQuality.gridx = 0;
		gbc_jpbQuality.gridy = 1;
		gbc_jpbQuality.insets = new Insets(0, 0, 0, 0);
		gbc_jpbQuality.fill = GridBagConstraints.HORIZONTAL;

		jpfPassword.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent evt) {
				passwordChanged();
			}
		});

		setLayout(new GridBagLayout());

		add(jpfPassword, gbc_jpfPassword);
		add(jpqmQuality, gbc_jpbQuality);
	}

	/**
	 * Get password or null if minimum password quality not met.
	 *
	 * @return Password
	 */
	public char[] getPassword() {
		if (getMinPasswordQuality() >= 0) {
			if (calculatePasswordQuality() < getMinPasswordQuality()) {
				return null;
			}
		}

		return jpfPassword.getPassword();
	}

	/**
	 * Get minimum password quality.
	 *
	 * @return Minimum password quality, -1 for none
	 */
	public int getMinPasswordQuality() {
		return minPasswordQuality;
	}

	/**
	 * Get password quality.
	 *
	 * @return Password quality
	 */
	public int getPasswordQuality() {
		return passwordQuality;
	}

	/**
	 * Set echo character.
	 *
	 * @param c
	 *            Echo character
	 */
	public void setEchoChar(char c) {
		jpfPassword.setEchoChar(c);
	}

	/**
	 * Get echo character.
	 *
	 * @return Echo character
	 */
	public char getEchoChar() {
		return jpfPassword.getEchoChar();
	}

	/**
	 * Is there an echo character set?
	 *
	 * @return True if there is
	 */
	public boolean echoCharIsSet() {
		return jpfPassword.echoCharIsSet();
	}

	/**
	 * Set whether or not the password quality field is enabled?
	 *
	 * @param enabled
	 *            Enabled?
	 */
	@Override
	public void setEnabled(boolean enabled) {
		jpfPassword.setEnabled(enabled);
		jpqmQuality.setEnabled(enabled);
	}

	/**
	 * Is the password quality field?
	 *
	 * @return Enabled?
	 */
	@Override
	public boolean isEnabled() {
		return jpfPassword.isEnabled();
	}

	/**
	 * Set the password quality field's text.
	 *
	 * @param text
	 *            Text
	 */
	public void setText(String text) {
		jpfPassword.setText(text);
		passwordChanged();
	}

	/**
	 * Set password quality field's tool tip text.
	 *
	 * @param toolTipText
	 *            Tool top text
	 */
	@Override
	public void setToolTipText(String toolTipText) {
		jpfPassword.setToolTipText(toolTipText);
	}

	/**
	 * Request input focus.
	 */
	@Override
	public void requestFocus() {
		jpfPassword.requestFocus();
	}

	private void passwordChanged() {
		passwordQuality = calculatePasswordQuality();
		jpqmQuality.setPasswordQuality(passwordQuality);
	}

	private void initQualityBar() {
		passwordChanged();
	}

	private int calculatePasswordQuality() {
		// @formatter:off

		/*
		 * Calculate password quality in range 0-100. Quality determined by: -
		 * Number of characters - Contains numbers - Non-alphanumeric characters
		 * - Contains both upper and lower case characters
		 */

		// @formatter:on

		char[] password = jpfPassword.getPassword();

		int length = password.length;

		if (length > 6) {
			length = 6; // Maximum score for length is six
		}

		/*
		 * Get number of digits and symbols in password and whether upper and
		 * lower case characters are used
		 */
		int digits = 0;
		int symbols = 0;

		boolean lower = false;
		boolean upper = false;

		for (char c : password) {
			if (Character.isDigit(c)) {
				digits++;
			}

			if (!Character.isLetterOrDigit(c)) {
				symbols++;
			}

			if (Character.isLowerCase(c)) {
				lower = true;
			}

			if (Character.isUpperCase(c)) {
				upper = true;
			}
		}

		if ((digits > 0) && (symbols == 0) && (!lower) && (!upper)) {
			return 0; // Password contains only digits - score zero
		}

		if ((digits == 0) && (symbols == 0) && (lower) && (!upper)) {
			return 0; // Password contains only lower case characters - score
			// zero
		}

		if ((digits == 0) && (symbols == 0) && (!lower) && (upper)) {
			return 0; // Password contains only upper case characters - score
			// zero
		}

		if (digits > 3) {
			digits = 3; // Maximum score for digits is three
		}

		if (symbols > 3) {
			symbols = 3; // Maximum score for symbols is three
		}

		int lowerUpper = 0;

		if (lower && upper) {
			lowerUpper = 3; // Presence of lower and upper case scores as three
		}

		// Calculate overall quality
		int quality = ((length * 10) - 30) + (digits * 10) + (symbols * 15) + (lowerUpper * 10);

		// Force into range 0-100
		if (quality < 0) {
			quality = 0;
		} else if (quality > 100) {
			quality = 100;
		}

		return quality;
	}

	private class JPasswordQualityMeter extends JPanel {
		/*
		 * Displays password quality as bar. The bar changes colour depending on
		 * whether or not the required password quality has been met
		 */

		private static final long serialVersionUID = 1L;
		private Color BACKGROUND_COLOUR = Color.WHITE;
		private Color BORDER_COLOUR = Color.LIGHT_GRAY;
		private Color QUALITY_SATISIFIED_COLOUR = new Color(129, 180, 88); // green
		private Color QUALITY_NOT_SATISFIED_COLOUR = new Color(192, 72, 56); // red

		private int passwordQuality;
		private int minPasswordQuality;
		private Color barColour;

		public JPasswordQualityMeter() {
			minPasswordQuality = -1;
			passwordQuality = 0;
		}

		public JPasswordQualityMeter(int minPasswordQuality) {
			this.minPasswordQuality = minPasswordQuality;
			passwordQuality = 0;
		}

		@Override
		public void paintComponent(Graphics g) {
			Rectangle bounds = new Rectangle(getSize());
			bounds.x = 0;
			bounds.y = 0;

			g.setColor(BORDER_COLOUR);
			g.drawRect(bounds.x, bounds.y, bounds.width - 1, bounds.height - 1);

			g.setColor(BACKGROUND_COLOUR);
			g.fillRect(bounds.x + 1, bounds.y + 1, bounds.width - 2, bounds.height - 2);

			if (passwordQuality > 0) {
				float filled = ((float) passwordQuality / 100);

				g.setColor(barColour);
				g.fillRect(bounds.x + 1, bounds.y + 1, (int) ((bounds.width - 2) * filled), bounds.height - 2);
			}
		}

		public void setPasswordQuality(int passwordQuality) {
			this.passwordQuality = passwordQuality;

			if (minPasswordQuality >= 0) {
				if (passwordQuality < minPasswordQuality) {
					barColour = QUALITY_NOT_SATISFIED_COLOUR;
				} else {
					barColour = QUALITY_SATISIFIED_COLOUR;
				}

				jpqmQuality.setToolTipText(MessageFormat.format(
						res.getString("JPasswordQualityField.jpbQuality.Min.tooltip"), passwordQuality,
						minPasswordQuality));
			} else {
				barColour = QUALITY_SATISIFIED_COLOUR;

				jpqmQuality.setToolTipText(MessageFormat.format(
						res.getString("JPasswordQualityField.jpbQuality.NoMin.tooltip"), passwordQuality));
			}

			repaint();
		}
	}
}
