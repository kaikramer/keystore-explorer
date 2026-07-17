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
package org.kse.gui.crypto.generalsubtree;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.crypto.generalname.JGeneralName;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to choose a general subtree.
 */
public class DGeneralSubtreeChooser extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/generalsubtree/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlBase;
    private JGeneralName jgnBase;
    private JLabel jlMinimum;
    private JTextField jtfMinimum;
    private JLabel jlMaximum;
    private JTextField jtfMaximum;
    private JPanel jpButtons;
    private JButton jbOK;
    private JButton jbCancel;

    private GeneralSubtree generalSubtree;

    /**
     * Constructs a new DGeneralSubtreeChooser dialog.
     *
     * @param parent         The parent frame
     * @param title          The dialog title
     * @param generalSubtree General subtree
     */
    public DGeneralSubtreeChooser(JFrame parent, String title, GeneralSubtree generalSubtree) {
        super(parent, title, ModalityType.DOCUMENT_MODAL);
        initComponents(generalSubtree);
    }

    /**
     * Constructs a new DGeneralSubtreeChooser dialog.
     *
     * @param parent         The parent dialog
     * @param title          The dialog title
     * @param generalSubtree General subtree
     */
    public DGeneralSubtreeChooser(JDialog parent, String title, GeneralSubtree generalSubtree) {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents(generalSubtree);
    }

    private void initComponents(GeneralSubtree generalSubtree) {
        jlBase = new JLabel(res.getString("DGeneralSubtreeChooser.jlBase.text"));

        jgnBase = new JGeneralName(res.getString("DGeneralSubtreeChooser.Base.Title"));
        jgnBase.setToolTipText(res.getString("DGeneralSubtreeChooser.jgnBase.tooltip"));

        jlMinimum = new JLabel(res.getString("DGeneralSubtreeChooser.jlMinimum.text"));

        jtfMinimum = new JTextField(3);
        jtfMinimum.setToolTipText(res.getString("DGeneralSubtreeChooser.jtfMinimum.tooltip"));

        jlMaximum = new JLabel(res.getString("DGeneralSubtreeChooser.jlMaximum.text"));

        jtfMaximum = new JTextField(3);
        jtfMaximum.setToolTipText(res.getString("DGeneralSubtreeChooser.jtfMaximum.tooltip"));

        jbOK = new JButton(res.getString("DGeneralSubtreeChooser.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DGeneralSubtreeChooser.jbCancel.text"));
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

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[][]"));
        pane.add(jlBase, "");
        pane.add(jgnBase, "wrap");
        pane.add(jlMinimum, "");
        pane.add(jtfMinimum, "wrap");
        pane.add(jlMaximum, "");
        pane.add(jtfMaximum, "wrap unrel");
        pane.add(new JSeparator(), "spanx, growx, wrap 15:push");
        pane.add(jpButtons, "spanx, growx");

        populate(generalSubtree);

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void populate(GeneralSubtree generalSubtree) {
        if (generalSubtree != null) {
            jgnBase.setGeneralName(generalSubtree.getBase());

            if (generalSubtree.getMinimum() != null) {
                jtfMinimum.setText("" + generalSubtree.getMinimum().intValue());
                jtfMinimum.setCaretPosition(0);
            }

            if (generalSubtree.getMaximum() != null) {
                jtfMaximum.setText("" + generalSubtree.getMaximum().intValue());
                jtfMaximum.setCaretPosition(0);
            }
        }
    }

    /**
     * Get selected general subtree.
     *
     * @return General subtree, or null if none
     */
    public GeneralSubtree getGeneralSubtree() {
        return generalSubtree;
    }

    private void okPressed() {
        GeneralName base = jgnBase.getGeneralName();

        if (base == null) {
            JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.BaseValueReq.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        int minimum = -1;
        String minimumStr = jtfMinimum.getText().trim();

        if (minimumStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.MinimumValueReq.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (!minimumStr.isEmpty()) {
            try {
                minimum = Integer.parseInt(minimumStr);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.InvalidMinimumValue.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (minimum < 0) {
                JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.InvalidMinimumValue.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        int maximum = -1;
        String maximumStr = jtfMaximum.getText().trim();

        if (!maximumStr.isEmpty()) {
            try {
                maximum = Integer.parseInt(maximumStr);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.InvalidMaximumValue.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (maximum < 0) {
                JOptionPane.showMessageDialog(this, res.getString("DGeneralSubtreeChooser.InvalidMaximumValue.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        BigInteger asn1Minimum = (minimum != -1) ? BigInteger.valueOf(minimum) : null;
        BigInteger asn1Maximum = (maximum != -1) ? BigInteger.valueOf(maximum) : null;

        generalSubtree = new GeneralSubtree(base, asn1Minimum, asn1Maximum);

        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
