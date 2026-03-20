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

package org.kse.gui;

import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;

import javax.swing.JTabbedPane;

import org.kse.gui.dnd.DroppedFileHandler;

/**
 * Drop target for opening KeyStore files.
 */
public class JKeyStoreTabbedPane extends JTabbedPane implements DropTargetListener {
    private static final long serialVersionUID = 1L;
    private KseFrame kseFrame;

    /**
     * Construct KeyStore tabbed pane.
     *
     * @param kseFrame KSE frame
     */
    public JKeyStoreTabbedPane(KseFrame kseFrame) {
        this.kseFrame = kseFrame;

        // Make this pane a drop target and its own listener
        new java.awt.dnd.DropTarget(this, this);

        java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(new java.awt.KeyEventDispatcher() {
            @Override
            public boolean dispatchKeyEvent(java.awt.event.KeyEvent e) {
                if (JKeyStoreTabbedPane.this.kseFrame.getUnderlyingFrame() != null &&
                    JKeyStoreTabbedPane.this.kseFrame.getUnderlyingFrame().isActive()) {

                    if (e.getID() == java.awt.event.KeyEvent.KEY_PRESSED && e.isControlDown()) {
                        
                        if (e.getKeyCode() == java.awt.event.KeyEvent.VK_PAGE_UP) {
                            int index = getSelectedIndex();
                            if (index > 0) {
                                setSelectedIndex(index - 1);
                            } else if (getTabCount() > 0) {
                                setSelectedIndex(getTabCount() - 1);
                            }
                            return true;
                        }
                        
                        if (e.getKeyCode() == java.awt.event.KeyEvent.VK_PAGE_DOWN) {
                            int index = getSelectedIndex();
                            if (index < getTabCount() - 1) {
                                setSelectedIndex(index + 1);
                            } else if (getTabCount() > 0) {
                                setSelectedIndex(0);
                            }
                            return true;
                        }

                        if (e.getKeyCode() == java.awt.event.KeyEvent.VK_F4) {
                            new org.kse.gui.actions.CloseAction(JKeyStoreTabbedPane.this.kseFrame).closeActiveKeyStore();
                            return true;
                        }
                    }
                }
                return false;
            }
        });
    }

    @Override
    public void drop(DropTargetDropEvent evt) {
        DroppedFileHandler.drop(evt, kseFrame);
    }

    @Override
    public void dragEnter(DropTargetDragEvent evt) {
    }

    @Override
    public void dragExit(DropTargetEvent evt) {
    }

    @Override
    public void dragOver(DropTargetDragEvent evt) {
    }

    @Override
    public void dropActionChanged(DropTargetDragEvent evt) {
    }
}
