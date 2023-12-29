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

package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

public class DCustomClaim extends JEscDialog {
    private static final long serialVersionUID = 1L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlName;
    private JTextField jtfName;
    private JLabel jlValue;
    private JTextField jtfValue;
    private JButton jbOK;
    private JButton jbCancel;

    private boolean isOk = false;
    private String name;
    private String value;

    public DCustomClaim(JFrame parent, String name, String value) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.name = name;
        this.value = value;
        setTitle(res.getString("DCustomClaim.Title"));
        initComponents();
    }

    private void initComponents() {
        jlName = new JLabel(res.getString("DCustomClaim.jlName.text"));
        jtfName = new JTextField("", 23);
        jtfName.setToolTipText(res.getString("DCustomClaim.jtfName.tooltip"));

        jlValue = new JLabel(res.getString("DCustomClaim.jlValue.text"));
        jtfValue = new JTextField("", 23);
        jtfValue.setToolTipText(res.getString("DCustomClaim.jtfValue.tooltip"));

        jbOK = new JButton(res.getString("DCustomClaim.jbOK.text"));
        jbCancel = new JButton(res.getString("DCustomClaim.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));

        pane.add(jlName, "");
        pane.add(jtfName, "wrap");

        pane.add(jlValue, "");
        pane.add(jtfValue, "wrap");
        pane.add(jpButtons, "right, spanx");

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());

        populateFields();

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void populateFields() {
        jtfName.setText(name);
        jtfValue.setText(value);
    }

    public boolean isOk() {
        return isOk;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    private void okPressed() {
        name = jtfName.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DCustomClaim.ValName.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }
        value = jtfValue.getText().trim();
        if (value.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DCustomClaim.ValValue.message"), getTitle(),
                                          JOptionPane.WARNING_MESSAGE);
            return;
        }
        isOk = true;
        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DCustomClaim(new javax.swing.JFrame(), "", ""));
    }

}
