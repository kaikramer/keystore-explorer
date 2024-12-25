/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.gui.preferences;

import javax.swing.JDialog;
import javax.swing.JPanel;

import org.kse.gui.dnchooser.DistinguishedNameChooser;
import org.kse.gui.preferences.data.KsePreferences;

class PanelDefaultName {
    private final JDialog parent;
    private final KsePreferences preferences;

    private DistinguishedNameChooser distinguishedNameChooser;

    PanelDefaultName(JDialog parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }

    JPanel initDefaultNameCard() {
        distinguishedNameChooser = new DistinguishedNameChooser(null, true, preferences.getDefaultSubjectDN());
        return distinguishedNameChooser;
    }

    DistinguishedNameChooser getDistinguishedNameChooser() {
        return distinguishedNameChooser;
    }
}
