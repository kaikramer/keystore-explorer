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

package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used to find a keystore entry
 */
public class DFindKeyStoreEntry extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlEntryName;
    private JTextField jtfEntryName;

    private JPanel jpButtons;
    private JButton jbOK;
    private JButton jbCancel;
    private boolean success = false;
    private String entryName;

    /**
     * Creates a new DFindKeyStoreEntry dialog.
     *
     * @param parent The parent frame
     */
    public DFindKeyStoreEntry(JFrame parent) {
        super(parent, res.getString("DFindKeyStoreEntry.Title"), Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    private void initComponents() {
        jlEntryName = new JLabel(res.getString("DFindKeyStoreEntry.jlEntryName.text"));

        jtfEntryName = new JTextField(10);

        jbOK = new JButton(res.getString("DFindKeyStoreEntry.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DFindKeyStoreEntry.jbCancel.text"));
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

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

        JPanel jpContent = new JPanel(new FlowLayout(FlowLayout.CENTER));
        jpContent.add(jlEntryName);
        jpContent.add(jtfEntryName);
        jpContent.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                               new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(jpContent, BorderLayout.CENTER);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    protected void closeDialog() {
        setVisible(false);
        dispose();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void okPressed() {
        if (jtfEntryName.getText().isEmpty()) {
            JOptionPane.showMessageDialog(getParent(), res.getString("DFindKeyStoreEntry.NotEmpty.message"),
                                          res.getString("DFindKeyStoreEntry.Title"), JOptionPane.INFORMATION_MESSAGE);
            jtfEntryName.requestFocus();
            return;
        }
        entryName = jtfEntryName.getText();
        success = true;
        closeDialog();
    }

    public boolean isSuccess() {
        return success;
    }

    public String getEntryName() {
        return entryName;
    }
}
