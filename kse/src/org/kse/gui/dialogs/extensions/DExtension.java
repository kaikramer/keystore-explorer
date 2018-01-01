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
package org.kse.gui.dialogs.extensions;

import javax.swing.JDialog;

import org.kse.gui.JEscDialog;

/**
 * Abstract base for all extension dialogs.
 *
 */
public abstract class DExtension extends JEscDialog {
	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new AbstractDExtension dialog.
	 *  @param parent
	 *            The parent dialog
	 *
	 */
	public DExtension(JDialog parent) {
		super(parent, ModalityType.DOCUMENT_MODAL);
	}

	/**
	 * Get extension value DER-encoded.
	 *
	 * @return Extension value
	 */
	public abstract byte[] getValue();
}
