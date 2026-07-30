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

import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GraphicsConfiguration;
import java.awt.Window;

import org.kse.gui.preferences.PreferencesManager;

/**
 * Extended dialog class that retains its size in preferences.
 */
public class JResizableDialog extends JEscDialog {
    private static final long serialVersionUID = -3773740513817678414L;

    public JResizableDialog() {
        this((Frame) null, false);
    }

    public JResizableDialog(Frame owner) {
        this(owner, false);
    }

    public JResizableDialog(Frame owner, boolean modal) {
        this(owner, null, modal);
    }

    public JResizableDialog(Frame owner, String title) {
        this(owner, title, false);
    }

    public JResizableDialog(Frame owner, String title, boolean modal) {
        super(owner, title, modal);
    }

    public JResizableDialog(Frame owner, String title, boolean modal, GraphicsConfiguration gc) {
        super(owner, title, modal, gc);
    }

    public JResizableDialog(Dialog owner) {
        this(owner, false);
    }

    public JResizableDialog(Dialog owner, boolean modal) {
        this(owner, null, modal);
    }

    public JResizableDialog(Dialog owner, String title) {
        this(owner, title, false);
    }

    public JResizableDialog(Dialog owner, String title, boolean modal) {
        super(owner, title, modal);
    }

    public JResizableDialog(Dialog owner, String title, boolean modal, GraphicsConfiguration gc) {
        super(owner, title, modal, gc);
    }

    public JResizableDialog(Window owner, ModalityType modalityType) {
        this(owner, "", modalityType);
    }

    public JResizableDialog(Window owner, String title, Dialog.ModalityType modalityType) {
        super(owner, title, modalityType);
    }

    public JResizableDialog(Window owner, String title, Dialog.ModalityType modalityType, GraphicsConfiguration gc) {
        super(owner, title, modalityType, gc);
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

    protected void closeDialog() {
        PreferencesManager.getPreferences().getDialogSizes().put(getClass().getSimpleName(), getSize());
        setVisible(false);
        dispose();
    }
}
