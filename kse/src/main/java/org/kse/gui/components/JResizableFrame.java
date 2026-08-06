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
package org.kse.gui.components;

import java.awt.Dimension;
import java.awt.GraphicsConfiguration;

import org.kse.gui.preferences.PreferencesManager;

/**
 * Extended JFrame class that retains its size in preferences.
 */
public class JResizableFrame extends JEscFrame {
    private static final long serialVersionUID = -3773740513817678414L;

    public JResizableFrame() {
        super();
    }

    public JResizableFrame(GraphicsConfiguration gc) {
        super(gc);
    }

    public JResizableFrame(String title) {
        super(title);
    }

    public JResizableFrame(String title, GraphicsConfiguration gc) {
        super(title, gc);
    }

    protected void restoreSize() {
        Dimension size = PreferencesManager.getPreferences().getDialogSizes().get(getClass().getSimpleName());
        if (size != null) {
            // It is technically better to use SwingUtilities.invokeLater, but that introduces
            // a visible flicker that is noticeable when the preferences size is restored.
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                // Just continue if interrupted during the brief sleep.
            }
            setSize(size);
        }
    }

    protected void closeFrame() {
        PreferencesManager.getPreferences().getDialogSizes().put(getClass().getSimpleName(), getSize());
        setVisible(false);
        dispose();
    }
}
