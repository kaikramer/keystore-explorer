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
package org.kse.gui.preferences;

import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JPanel;

import org.kse.gui.MiGUtil;
import org.kse.gui.dnchooser.DistinguishedNameChooser;
import org.kse.gui.preferences.data.KsePreferences;

import net.miginfocom.swing.MigLayout;

class PanelDefaultName {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private final JDialog parent;
    private final KsePreferences preferences;

    private DistinguishedNameChooser distinguishedNameChooser;

    PanelDefaultName(JDialog parent, KsePreferences preferences) {
        this.parent = parent;
        this.preferences = preferences;
    }

    JPanel initDefaultNameCard() {
        distinguishedNameChooser = new DistinguishedNameChooser(null, true, preferences.getDefaultSubjectDN());

        JPanel jpDefaultName = new JPanel();
        jpDefaultName.setLayout(new MigLayout("insets dialog", "20lp[]", "20lp[]"));

        MiGUtil.addSeparator(jpDefaultName, res.getString("DPreferences.defaultDNSettings.separator"));
        jpDefaultName.add(distinguishedNameChooser, "spanx, wrap");

        return jpDefaultName;
    }

    DistinguishedNameChooser getDistinguishedNameChooser() {
        return distinguishedNameChooser;
    }
}
