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
package org.kse.gui.oid;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.kse.gui.JEscDialog;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.oid.InvalidObjectIdException;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to choose an object identifier.
 */
public class DObjectIdChooser extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/oid/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlObjectId;
    private JObjectIdEditor jObjectIdEditor;
    private JButton jbOK;
    private JButton jbCancel;

    private ASN1ObjectIdentifier objectId;

    /**
     * Constructs a new DObjectIdChooser dialog.
     *
     * @param parent   The parent frame
     * @param title    The dialog title
     * @param objectId Object identifier
     * @throws InvalidObjectIdException If there was a problem with the object identifier
     */
    public DObjectIdChooser(JFrame parent, String title, ASN1ObjectIdentifier objectId)
            throws InvalidObjectIdException {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        initComponents(objectId);
    }

    /**
     * Constructs a new DObjectIdChooser dialog.
     *
     * @param parent   The parent dialog
     * @param title    The dialog title
     * @param objectId Object identifier
     * @throws InvalidObjectIdException If there was a problem with the object identifier
     */
    public DObjectIdChooser(JDialog parent, String title, ASN1ObjectIdentifier objectId)
            throws InvalidObjectIdException {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents(objectId);
    }

    private void initComponents(ASN1ObjectIdentifier objectId) throws InvalidObjectIdException {
        jlObjectId = new JLabel(res.getString("DObjectIdChooser.jlObjectId.text"));

        jObjectIdEditor = new JObjectIdEditor(objectId);

        jbOK = new JButton(res.getString("DObjectIdChooser.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DObjectIdChooser.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]"));
        pane.add(jlObjectId, "");
        pane.add(jObjectIdEditor, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap rel:push");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void okPressed() {
        try {
            this.objectId = jObjectIdEditor.getObjectId();
        } catch (InvalidObjectIdException | IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), getTitle(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    /**
     * Get selected object identifier name.
     *
     * @return Object identifier, or null if none
     */
    public ASN1ObjectIdentifier getObjectId() {
        return objectId;
    }

    public static void main(String[] args)
            throws HeadlessException, InvalidObjectIdException, UnsupportedLookAndFeelException {
        DialogViewer.prepare();
        DObjectIdChooser dialog = new DObjectIdChooser(new JFrame(), "OID Chooser", new ASN1ObjectIdentifier("1.2.3"));
        DialogViewer.run(dialog);
    }
}
