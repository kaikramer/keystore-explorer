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

/**
 * Encapsulates password quality configuration for dialogs that accept new
 * passwords.
 *
 */
public class PasswordQualityConfig {
	private boolean enabled;
	private boolean enforced;
	private int minimumQuality;

	/**
	 * Construct password quality configuration.
	 *
	 * @param enabled
	 *            Is password quality enabled?
	 * @param minimumQualityEnforced
	 *            Is minimum password quality enforced?
	 * @param minimumQuality
	 *            Minimum password quality
	 */
	public PasswordQualityConfig(boolean enabled, boolean minimumQualityEnforced, int minimumQuality) {
		this.enabled = enabled;
		this.enforced = minimumQualityEnforced;
		this.minimumQuality = minimumQuality;
	}

	/**
	 * Is password quality enabled?
	 *
	 * @return True if it is
	 */
	public boolean getEnabled() {
		return enabled;
	}

	/**
	 * Set if password quality is enabled.
	 *
	 * @param enabled
	 *            Enabled?
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Is minimum password quality enforced?
	 *
	 * @return True if it is
	 */
	public boolean getEnforced() {
		return enforced;
	}

	/**
	 * Set if minimum password quality is enforced.
	 *
	 * @param enforced
	 *            Enforced?
	 */
	public void setEnforced(boolean enforced) {
		this.enforced = enforced;
	}

	/**
	 * Get minimum password quality
	 *
	 * @return Minimum password quality
	 */
	public int getMinimumQuality() {
		return minimumQuality;
	}

	/**
	 * Set minimum password quality
	 *
	 * @param minimumQuality
	 *            Minimum password quality
	 */
	public void setMinimumQuality(int minimumQuality) {
		this.minimumQuality = minimumQuality;
	}
}
