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
package org.kse.gui;

import java.awt.Component;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;

import org.kse.utilities.os.OperatingSystem;

import net.miginfocom.swing.MigLayout;

/**
 * Platform specific GUI building utility methods. Takes care of differences
 * between Mac OS (and lnfs thereof) and other platforms. They
 * "Think Different", you see.
 *
 */
public class PlatformUtil {
	private PlatformUtil() {
	}

	/**
	 * Create a dialog button panel with the order and alignment dependant on
	 * the platform.
	 *
	 * @param jbPositive
	 *            Positive button
	 * @param resizable
	 *            Is the dialog resizable?
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton jbPositive, boolean resizable) {
		return createDialogButtonPanel((jbPositive == null ? null : new JButton[] { jbPositive }), resizable);
	}

	/**
	 * Create a dialog button panel with the order and alignment dependant on
	 * the platform.
	 *
	 * @param jbPositives
	 *            Positive buttons
	 * @param resizable
	 *            Is the dialog resizable?
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton[] jbPositives, boolean resizable) {
		return createDialogButtonPanel(jbPositives, null, null, resizable, null);
	}

	/**
	 * Create a dialog button panel with the order and alignment dependant on
	 * the platform.
	 *
	 * @param jbPositive
	 *            Positive button
	 * @param jbNegative
	 *            Negative button
	 * @param resizable
	 *            Is the dialog resizable?
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton jbPositive, JButton jbNegative, boolean resizable) {
		return createDialogButtonPanel((jbPositive == null ? null : new JButton[] { jbPositive }), jbNegative,
				resizable);
	}

	/**
	 * Create a dialog button panel with the order and alignment dependant on
	 * the platform.
	 *
	 * @param jbPositives
	 *            Positive buttons
	 * @param jbNegative
	 *            Negative button
	 * @param resizable
	 *            Is the dialog resizable?
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton[] jbPositives, JButton jbNegative, boolean resizable) {
		return createDialogButtonPanel(jbPositives, jbNegative, null, resizable, null);
	}

	/**
	 * Create a dialog button panel with the order and alignment dependant on
	 * the platform.
	 *
	 * @param jbPositive
	 *            Positive button
	 * @param jbNegative
	 *            Negative button
	 * @param jbOther
	 *            Other button
	 * @param resizable
	 *            Is the dialog resizable?
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton jbPositive, JButton jbNegative, JButton jbOther,
			boolean resizable) {
		return createDialogButtonPanel(jbPositive, jbNegative, (jbOther == null ? null : new JButton[] { jbOther }),
				resizable);
	}

	/**
	 * Create a dialog button panel with the order and alignment dependant on
	 * the platform.
	 *
	 * @param jbPositive
	 *            Positive button
	 * @param jbNegative
	 *            Negative button
	 * @param jbOther
	 *            Other button
	 * @param resizable
	 *            Is the dialog resizable?
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton jbPositive, JButton jbNegative, JButton[] jbOther,
			boolean resizable) {
		return createDialogButtonPanel((jbPositive == null ? null : new JButton[] { jbPositive }), jbNegative, jbOther,
				resizable, null);
	}

	/**
	 * Create a dialog button panel with the order and alignment dependent on
	 * the platform.
	 *
	 * @param jbPositives
	 *            Positive buttons
	 * @param jbNegative
	 *            Negative button
	 * @param jbOthers
	 *            Other buttons
	 * @param resizable
	 *            Is the dialog resizable?
	 * @param insets
	 *            Insets for panel (MiGLayout constraint)
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton[] jbPositives, JButton jbNegative, JButton[] jbOthers,
			boolean resizable, String insets) {

		if (insets == null) {
			insets = "";
		} else {
			insets += ",";
		}

		JPanel panel = new JPanel(new MigLayout(insets + "nogrid, fillx, aligny 100%"));

		if (jbPositives != null) {
			for (JButton jButton : jbPositives) {
				panel.add(jButton, "tag ok");
			}
		}

		if (jbOthers != null) {
			for (JButton jButton : jbOthers) {
				panel.add(jButton, "sgx");
			}
		}

		if (jbNegative != null) {
			panel.add(jbNegative, "tag cancel");
		}

		return panel;
	}

	/**
	 * Create a dialog button panel with the order and alignment dependent on
	 * the platform.
	 * <br>
	 * This method creates zero spacing around the buttons.
	 *
	 * @param jbPositive
	 *            Positive button
	 * @param jbNegative
	 *            Negative button
	 * @param jbOthers
	 *            Other buttons
	 * @return Dialog button panel
	 */
	public static JPanel createDialogButtonPanel(JButton jbPositive, JButton jbNegative) {

		JPanel panel = new JPanel(new MigLayout("insets 0, nogrid, fillx, aligny 100%"));

		if (jbPositive != null) {
			panel.add(jbPositive, "tag ok");
		}

		if (jbNegative != null) {
			panel.add(jbNegative, "tag cancel");
		}

		return panel;
	}

	/**
	 * Create a scroll pane whose scroll bar policy conforms with the current
	 * platform. i.e. on Mac OS l&f if a scroll bar's policy states that it may
	 * be shown as needed it should instead always be shown. For all other
	 * platforms obey policy as provided.
	 *
	 * @param vsbPolicy
	 *            Vertical scroll bar policy
	 * @param hsbPolicy
	 *            Horizontal scroll bar policy
	 * @return Scroll pane
	 */
	public static JScrollPane createScrollPane(int vsbPolicy, int hsbPolicy) {
		return createScrollPane(null, vsbPolicy, hsbPolicy);
	}

	/**
	 * Create a scroll pane whose scroll bar policy conforms with the current
	 * platform. i.e. on Mac OS l&f if a scroll bar's policy states that it may
	 * be shown as needed it should instead always be shown. For all other
	 * platforms obey policy as provided.
	 *
	 * @param view
	 *            Component to view
	 * @param vsbPolicy
	 *            Vertical scroll bar policy
	 * @param hsbPolicy
	 *            Horizontal scroll bar policy
	 * @return Scroll pane
	 */
	public static JScrollPane createScrollPane(Component view, int vsbPolicy, int hsbPolicy) {
		// If Mac l&f convert supplied "scroll bars as needed" to "scroll bars always"
		if (LnfUtil.usingMacLnf()) {
			if (vsbPolicy == ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED) {
				vsbPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS;
			}

			if (hsbPolicy == ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED) {
				hsbPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS;
			}
		}

		JScrollPane scrollPane;

		if (view != null) {
			scrollPane = new JScrollPane(view, vsbPolicy, hsbPolicy);
		} else {
			scrollPane = new JScrollPane(vsbPolicy, hsbPolicy);
		}

		return scrollPane;
	}

	/**
	 * Set mnemonic on button in a platform dependant manner.
	 *
	 * @param button
	 *            Button
	 * @param mnemonic
	 *            Mnemonic
	 */
	public static void setMnemonic(AbstractButton button, int mnemonic) {
		setMnemonic(button, (char) mnemonic, -1);
	}

	/**
	 * Set mnemonic on button in a platform dependant manner.
	 *
	 * @param button
	 *            Button
	 * @param mnemonic
	 *            Mnemonic
	 */
	public static void setMnemonic(AbstractButton button, char mnemonic) {
		setMnemonic(button, mnemonic, -1);
	}

	/**
	 * Set mnemonic on button in a platform dependant manner.
	 *
	 * @param button
	 *            Button
	 * @param mnemonic
	 *            Mnemonic
	 * @param index
	 *            Index of string to underline
	 */
	public static void setMnemonic(AbstractButton button, int mnemonic, int index) {
		setMnemonic(button, (char) mnemonic, index);
	}

	/**
	 * Set mnemonic on button in a platform dependant manner.
	 *
	 * @param button
	 *            Button
	 * @param mnemonic
	 *            Mnemonic
	 * @param index
	 *            Index of string to underline
	 */
	public static void setMnemonic(AbstractButton button, char mnemonic, int index) {
		/*
		 * Only set mnemonic if not using Mac OS - they are not recommended by
		 * the style guidelines there and clash with established commands
		 */
		if (!OperatingSystem.isMacOs()) {
			button.setMnemonic(mnemonic);

			if (index >= 0) {
				button.setDisplayedMnemonicIndex(index);
			}
		}
	}
}
