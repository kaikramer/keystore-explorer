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
package org.kse.gui.oid;

import java.awt.Container;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.CursorUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.oid.InvalidObjectIdException;
import org.kse.utilities.oid.ObjectIdUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Component to edit an object identifier.
 */
public class JObjectId extends JPanel {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/oid/resources");

    private JTextField jtfObjectId;
    private JButton jbEditObjectId;
    private JButton jbClearObjectId;

    private String title;
    private ASN1ObjectIdentifier objectId;

    /**
     * Construct a JObjectId.
     *
     * @param title Title of edit dialog
     */
    public JObjectId(String title) {
        this.title = title;
        initComponents();
    }

    private void initComponents() {
        jtfObjectId = new JTextField(25);
        jtfObjectId.setEditable(false);

        ImageIcon editIcon = new ImageIcon(getClass().getResource("images/edit_object_id.png"));
        jbEditObjectId = new JButton(editIcon);
        jbEditObjectId.setToolTipText(res.getString("JObjectId.jbEditObjectId.tooltip"));
        jbEditObjectId.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JObjectId.this);
                editObjectId();
            } finally {
                CursorUtil.setCursorFree(JObjectId.this);
            }
        });

        ImageIcon clearIcon = new ImageIcon(getClass().getResource("images/clear_object_id.png"));
        jbClearObjectId = new JButton(clearIcon);
        jbClearObjectId.setToolTipText(res.getString("JObjectId.jbClearObjectId.tooltip"));
        jbClearObjectId.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(JObjectId.this);
                clearObjectId();
            } finally {
                CursorUtil.setCursorFree(JObjectId.this);
            }
        });

        setLayout(new MigLayout("insets 0, fill", "[]", "[]"));
        add(jtfObjectId, "growx, pushx");
        add(jbEditObjectId, "");
        add(jbClearObjectId, "");

        populate();
    }

    /**
     * Get object identifier.
     *
     * @return Object identifier, or null if none chosen
     */
    public ASN1ObjectIdentifier getObjectId() {
        return objectId;
    }

    /**
     * Set object identifier.
     *
     * @param objectId Object identifier
     */
    public void setObjectId(ASN1ObjectIdentifier objectId) {
        this.objectId = objectId;
        populate();
    }

    /**
     * Sets whether or not the component is enabled.
     *
     * @param enabled True if this component should be enabled, false otherwise
     */
    @Override
    public void setEnabled(boolean enabled) {
        jbEditObjectId.setEnabled(enabled);
        jbClearObjectId.setEnabled(enabled);
    }

    /**
     * Set component's tooltip text.
     *
     * @param toolTipText Tooltip text
     */
    @Override
    public void setToolTipText(String toolTipText) {
        super.setToolTipText(toolTipText);
        jtfObjectId.setToolTipText(toolTipText);
    }

    private void populate() {
        if (objectId != null) {
            jtfObjectId.setText(ObjectIdUtil.toString(objectId));
            jbClearObjectId.setEnabled(true);
        } else {
            jtfObjectId.setText("");
            jbClearObjectId.setEnabled(false);
        }

        jtfObjectId.setCaretPosition(0);
    }

    private void editObjectId() {
        Container container = getTopLevelAncestor();

        try {
            DObjectIdChooser dObjectIdChooser = null;

            if (container instanceof JDialog) {
                dObjectIdChooser = new DObjectIdChooser((JDialog) container, title, objectId);
            } else {
                dObjectIdChooser = new DObjectIdChooser((JFrame) container, title, objectId);
            }
            dObjectIdChooser.setLocationRelativeTo(container);
            dObjectIdChooser.setVisible(true);

            ASN1ObjectIdentifier newObjectId = dObjectIdChooser.getObjectId();

            if (newObjectId == null) {
                return;
            }

            setObjectId(newObjectId);
        } catch (InvalidObjectIdException ex) {
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

    private void clearObjectId() {
        setObjectId(null);
    }
}
