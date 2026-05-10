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
package org.kse.gui.dialogs.extensions;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit a Basic Constraints extension.
 */
public class DBasicConstraints extends DExtension {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlBasicConstraints;
    private JCheckBox jcbSubjectIsCa;
    private JLabel jlPathLengthConstraint;
    private JTextField jtfPathLengthConstraint;
    private JButton jbOK;
    private JButton jbCancel;

    private byte[] value;

    /**
     * Creates a new DBasicConstraints dialog.
     *
     * @param parent The parent dialog
     */
    public DBasicConstraints(JDialog parent) {
        super(parent);
        setTitle(res.getString("DBasicConstraints.Title"));
        initComponents();
    }

    /**
     * Creates a new DBasicConstraints dialog.
     *
     * @param parent The parent dialog
     * @param value  Basic Constraints DER-encoded
     * @throws IOException If value could not be decoded
     */
    public DBasicConstraints(JDialog parent, byte[] value) throws IOException {
        super(parent);
        setTitle(res.getString("DBasicConstraints.Title"));
        initComponents();
        prepopulateWithValue(value);
    }

    private void initComponents() {
        jlBasicConstraints = new JLabel(res.getString("DBasicConstraints.jlBasicConstraints.text"));

        jcbSubjectIsCa = new JCheckBox(res.getString("DBasicConstraints.jcbSubjectIsCa.text"));
        jcbSubjectIsCa.setSelected(false);
        jcbSubjectIsCa.setBorder(new EmptyBorder(0, 0, 5, 0));

        jlPathLengthConstraint = new JLabel(res.getString("DBasicConstraints.jlPathLengthConstraint.text"));

        jtfPathLengthConstraint = new JTextField(3);

        jbOK = new JButton(res.getString("DBasicConstraints.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbCancel = new JButton(res.getString("DBasicConstraints.jbCancel.text"));
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

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[][]", "[][]"));
        pane.add(jlBasicConstraints, "wrap");
        pane.add(jcbSubjectIsCa, "wrap");
        pane.add(jlPathLengthConstraint);
        pane.add(jtfPathLengthConstraint, "wrap");
        pane.add(new JSeparator(), "spanx, growx");
        pane.add(jbCancel, "spanx, split 2, tag cancel");
        pane.add(jbOK, "tag ok");

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    private void prepopulateWithValue(byte[] value) throws IOException {
        BasicConstraints basicConstraints = BasicConstraints.getInstance(value);

        jcbSubjectIsCa.setSelected(basicConstraints.isCA());

        if (basicConstraints.getPathLenConstraint() != null) {
            jtfPathLengthConstraint.setText("" + basicConstraints.getPathLenConstraint().intValue());
            jtfPathLengthConstraint.setCaretPosition(0);
        }
    }

    private void okPressed() {
        boolean ca = jcbSubjectIsCa.isSelected();

        int pathLengthConstraint = -1;

        String pathLengthConstraintStr = jtfPathLengthConstraint.getText().trim();

        if (!pathLengthConstraintStr.isEmpty()) {
            try {
                pathLengthConstraint = Integer.parseInt(pathLengthConstraintStr);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, res.getString("DBasicConstraints.InvalidLengthValue.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (pathLengthConstraint < 0) {
                JOptionPane.showMessageDialog(this, res.getString("DBasicConstraints.InvalidLengthValue.message"),
                                              getTitle(), JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        BasicConstraints basicConstraints;

        if (pathLengthConstraint != -1) {
            // pathLengthConstraint set automatically means ca=true
            basicConstraints = new BasicConstraints(pathLengthConstraint);
        } else {
            basicConstraints = new BasicConstraints(ca);
        }

        try {
            value = basicConstraints.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            DError.displayError(this, e);
            return;
        }

        closeDialog();
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public String getOid() {
        return X509ExtensionType.BASIC_CONSTRAINTS.oid();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
