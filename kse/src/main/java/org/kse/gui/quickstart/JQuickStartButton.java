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
package org.kse.gui.quickstart;

import java.awt.Color;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.Action;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.kse.gui.LnfUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Quick Start button. Undecorated image button with attached descriptive text
 * that each react to mouse roll-overs.
 */
public class JQuickStartButton extends JPanel {
    private static final long serialVersionUID = 1L;
    private JButton jbWelcome;
    private JLabel jlWelcome;
    private final Color lightForeground;
    private final Color darkForeground;

    /**
     * Initialise component and its subcomponents.
     *
     * @param action        Button action
     * @param test          Button text
     * @param icon          Button icon
     * @param rollOverIcon  Button rollover icon
     * @param lightForeground    Foreground color for text
     * @param lightRollOverColor Rollover color for text
     * @param darkForeground     Foreground color for text in dark LNF
     * @param darkRollOverColor  Rollover color for text in dark LNF
     */
    public JQuickStartButton(Action action, String test, final ImageIcon icon, final ImageIcon rollOverIcon,
                             final Color lightForeground, final Color lightRollOverColor,
                             final Color darkForeground, final Color darkRollOverColor) {
        this.lightForeground = lightForeground;
        this.darkForeground = darkForeground;

        jlWelcome = new JLabel(test);
        jlWelcome.setForeground(LnfUtil.isDarkLnf() ? darkForeground : lightForeground);

        jbWelcome = new JButton();
        jbWelcome.setAction(action);

        jbWelcome.setSize(icon.getImage().getWidth(null), icon.getImage().getHeight(null));
        jbWelcome.setIcon(icon);

        // We'll do our own roll-over using mouse and action event handlers
        jbWelcome.setRolloverEnabled(false);

        // Removed un-needed button functionality and decoration
        jbWelcome.setMargin(new Insets(0, 0, 0, 0));
        jbWelcome.setIconTextGap(0);
        jbWelcome.setBorderPainted(false);
        jbWelcome.setBorder(null);
        jbWelcome.setText(null);
        jbWelcome.setToolTipText(null);
        jbWelcome.setContentAreaFilled(false);
        jbWelcome.setFocusPainted(false);
        jbWelcome.setFocusable(false);

        // Add roll-over supporting events

        jbWelcome.addMouseListener(new MouseAdapter() {
            // Mouse entered - use roll-over color on text and image on button
            @Override
            public void mouseEntered(MouseEvent evt) {
                jlWelcome.setForeground(LnfUtil.isDarkLnf() ? darkRollOverColor : lightRollOverColor);
                jbWelcome.setIcon(rollOverIcon);
            }

            // Mouse exited - remove roll-over color on text and image on button
            @Override
            public void mouseExited(MouseEvent evt) {
                jlWelcome.setForeground(LnfUtil.isDarkLnf() ? darkForeground : lightForeground);
                jbWelcome.setIcon(icon);
            }
        });

        // Button activate - remove roll-over color on text and image on button
        jbWelcome.addActionListener(evt -> {
            jlWelcome.setForeground(LnfUtil.isDarkLnf() ? darkForeground : lightForeground);
            jbWelcome.setIcon(icon);
        });

        setLayout(new MigLayout("flowy, insets 0", "[center]", "[]rel[]"));
        add(jbWelcome);
        add(jlWelcome);
    }

    @Override
    public void repaint() {
        super.repaint();
        // for laf changes
        if (jlWelcome != null) {
            jlWelcome.setForeground(LnfUtil.isDarkLnf() ? darkForeground : lightForeground);
        }
    }
}
