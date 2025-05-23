/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import javax.swing.JTabbedPane;

import org.kse.gui.KseFrame;

/**
 * Action to change KeyStore tab style to wrap.
 */
public class TabStyleWrapAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public TabStyleWrapAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(LONG_DESCRIPTION, res.getString("TabStyleWrapAction.statusbar"));
        putValue(NAME, res.getString("TabStyleWrapAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("TabStyleWrapAction.tooltip"));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        kseFrame.setKeyStoreTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
    }
}
