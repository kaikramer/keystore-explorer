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
import java.net.URL;
import java.text.MessageFormat;

import javax.swing.ImageIcon;

import org.kse.KSE;
import org.kse.gui.KseFrame;
import org.kse.gui.LnfUtil;
import org.kse.gui.about.DAbout;

/**
 * Action to show KeyStore Explorer about dialog.
 */
public class AboutAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public AboutAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(LONG_DESCRIPTION, res.getString("AboutAction.statusbar"));
        putValue(NAME, res.getString("AboutAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("AboutAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/about.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        showAbout();
    }

    /**
     * Display the about dialog.
     */
    public void showAbout() {

        String[] tickerItems = { "Copyright 2004 - 2013 Wayne Grant, 2013 - 2023 Kai Kramer",
                                 "Bouncy Castle JCE Provider Copyright 2000 - 2021 The Legion Of The Bouncy Castle " +
                                 "(www.bouncycastle.org)",
                                 "Apache Commons Copyright 2002 - 2021 The Apache Software Foundation (commons.apache" +
                                 ".org)",
                                 "MigLayout Copyright 2004, Mikael Grev, MiG InfoCom AB (www.miglayout.com)",
                                 "Fugue Icons Copyright 2013 Yusuke Kamiyamane (p.yusukekamiyamane.com)",
                                 "JNA Copyright 2007 Timothy Wall (github.com/java-native-access/jna)",
                                 "FlatLaf Copyright 2019 - 2021 FormDev Software GmbH (www.formdev.com/flatlaf/)",
                                 LnfUtil.isVAquaAvailable() ?
                                 "VAqua Copyright 2015 - 2019 Alan Snyder (violetlib.org)" : "",
                                 "Nimbus JOSE + JWT Copyright 2012 - 2022, Connect2id Ltd. (connect2id.com)",
                                 "Diff Utils library Copyright 2009-2022 java-diff-utils (github.com/java-diff-utils)"};

        URL aboutDialogImageURL = AboutAction.class.getResource("images/aboutdlg.png");
        DAbout dAbout = new DAbout(frame, MessageFormat.format(res.getString("AboutAction.About.Title"),
                                                               KSE.getApplicationName()),
                                   res.getString("AboutAction.License"),
                                   Toolkit.getDefaultToolkit().createImage(aboutDialogImageURL), tickerItems);
        dAbout.setLocationRelativeTo(frame);
        dAbout.setVisible(true);
    }
}
