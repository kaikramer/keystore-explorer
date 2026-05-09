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
package org.kse.gui.crypto;

import java.awt.Container;
import java.security.PublicKey;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.kse.crypto.CryptoException;
import org.kse.gui.CursorUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.io.HexUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Component to edit a key identifier.
 */
public class JKeyIdentifier extends JPanel {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

    private JTextField jtfKeyIdentifier;
    private JButton jbEditKeyIdentifier;
    private JButton jbClearKeyIdentifier;

    private String title;
    private PublicKey publicKey;
    private byte[] keyIdentifier;

    /**
     * Construct a JKeyIdentifier.
     *
     * @param title     Title of edit dialog
     * @param publicKey Public key
     */
    public JKeyIdentifier(String title, PublicKey publicKey) {
        this.title = title;
        this.publicKey = publicKey;
        initComponents();
    }

    private void initComponents() {
        jtfKeyIdentifier = new JTextField(40);
        jtfKeyIdentifier.setEditable(false);

        ImageIcon editIcon = new ImageIcon(getClass().getResource("images/edit_key_id.png"));
        jbEditKeyIdentifier = new JButton(editIcon);
        jbEditKeyIdentifier.setToolTipText(res.getString("JKeyIdentifier.jbEditKeyIdentifier.tooltip"));
        jbEditKeyIdentifier.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JKeyIdentifier.this);
                editKeyIdentifier();
            } finally {
                CursorUtil.setCursorFree(JKeyIdentifier.this);
            }
        });

        ImageIcon clearIcon = new ImageIcon(getClass().getResource("images/clear_key_id.png"));
        jbClearKeyIdentifier = new JButton(clearIcon);
        jbClearKeyIdentifier.setToolTipText(res.getString("JKeyIdentifier.jbClearKeyIdentifier.tooltip"));
        jbClearKeyIdentifier.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JKeyIdentifier.this);
                clearKeyIdentifier();
            } finally {
                CursorUtil.setCursorFree(JKeyIdentifier.this);
            }
        });

        setLayout(new MigLayout("insets 0", "[]", "[]"));
        add(jtfKeyIdentifier);
        add(jbEditKeyIdentifier);
        add(jbClearKeyIdentifier);

        populate();
    }

    /**
     * Get key identifier.
     *
     * @return Key identifier, or null if none chosen
     */
    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * Set key identifier.
     *
     * @param keyIdentifier Key identifier
     */
    public void setKeyIdentifier(byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
        populate();
    }

    /**
     * Sets whether or not the component is enabled.
     *
     * @param enabled True if this component should be enabled, false otherwise
     */
    @Override
    public void setEnabled(boolean enabled) {
        jbEditKeyIdentifier.setEnabled(enabled);
        jbClearKeyIdentifier.setEnabled(enabled);
    }

    /**
     * Set component's tooltip text.
     *
     * @param toolTipText Tooltip text
     */
    @Override
    public void setToolTipText(String toolTipText) {
        super.setToolTipText(toolTipText);
        jtfKeyIdentifier.setToolTipText(toolTipText);
    }

    private void populate() {
        if (keyIdentifier != null) {
            jtfKeyIdentifier.setText(HexUtil.getHexString(keyIdentifier));
            jbClearKeyIdentifier.setEnabled(true);
        } else {
            jtfKeyIdentifier.setText("");
            jbClearKeyIdentifier.setEnabled(false);
        }

        jtfKeyIdentifier.setCaretPosition(0);
    }

    private void editKeyIdentifier() {
        Container container = getTopLevelAncestor();

        try {
            DKeyIdentifierChooser dKeyIdentifierChooser = null;

            if (container instanceof JDialog) {
                dKeyIdentifierChooser = new DKeyIdentifierChooser((JDialog) container, title, publicKey, keyIdentifier);
            } else {
                dKeyIdentifierChooser = new DKeyIdentifierChooser((JFrame) container, title, publicKey, keyIdentifier);
            }
            dKeyIdentifierChooser.setLocationRelativeTo(container);
            dKeyIdentifierChooser.setVisible(true);

            byte[] newKeyIdentifier = dKeyIdentifierChooser.getKeyIdentifier();

            if (newKeyIdentifier == null) {
                return;
            }

            setKeyIdentifier(newKeyIdentifier);
        } catch (CryptoException ex) {
            DError dError = null;

            if (container instanceof JDialog) {
                dError = new DError((JDialog) container, ex);
            } else {
                dError = new DError((JFrame) container, ex);
            }

            dError.setLocationRelativeTo(container);
            dError.setVisible(true);
        }
    }

    private void clearKeyIdentifier() {
        setKeyIdentifier(null);
    }
}
