/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DFindKeyStoreEntry;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to Find a KeyStore entry.
 */
public class FindAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public FindAction(KseFrame kseFrame) {
        super(kseFrame);
        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("FindAction.accelerator").charAt(0),
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
        putValue(LONG_DESCRIPTION, res.getString("FindAction.statusbar"));
        putValue(NAME, res.getString("FindAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("FindAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/find.png"))));
    }

    @Override
    protected void doAction() {

        DFindKeyStoreEntry dialog = new DFindKeyStoreEntry(frame);
        dialog.setLocationRelativeTo(frame);
        dialog.setVisible(true);

        if (dialog.isSuccess()) {
            try {
                String name = dialog.getEntryName();
                kseFrame.keyStoreclearSelection();
                Set<String> aliases = findEntryAlias(name);
                if (aliases.isEmpty()) {
                    JOptionPane.showMessageDialog(frame,
                                                  MessageFormat.format(res.getString("FindAction.NotFound.message"),
                                                                       name), res.getString("FindAction.Find.Title"),
                                                  JOptionPane.WARNING_MESSAGE);
                } else {
                    kseFrame.setSelectedEntriesByAliases(aliases);
                }
            } catch (KeyStoreException ex) {
                DError.displayError(frame, ex);
            }
        }
    }

    private Set<String> findEntryAlias(String name) throws KeyStoreException {
        Set<String> aliases = new HashSet<>();
        KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
        KeyStore keyStore = history.getCurrentState().getKeyStore();
        Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            if (alias.contains(name)) {
                aliases.add(alias);
            }
        }
        return aliases;
    }
}
