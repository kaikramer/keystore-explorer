/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.MsCapiStoreType;
import org.kse.gui.KseFrame;

/**
 * Action to open the Windows-MY (current user) MS CAPI KeyStore.
 */
public class OpenWindowsMyAction extends OpenMsCapiAction {

    private static final long serialVersionUID = 4500198622332006939L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public OpenWindowsMyAction(KseFrame kseFrame) {
        super(kseFrame, MsCapiStoreType.PERSONAL, "OpenWindowsMyAction.TabTitle");

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('M',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() +
                                                         InputEvent.SHIFT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("OpenWindowsMyAction.statusbar"));
        putValue(NAME, res.getString("OpenWindowsMyAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("OpenWindowsMyAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/openmscapi.png"))));
    }

}
