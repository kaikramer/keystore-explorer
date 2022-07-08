/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to find a keystore entry
 */
public class DFindKeyStoreEntry extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlEntryName;
    private JTextField jtfEntryName;
    private JLabel jlSubjectCN;
    private JTextField jtfSubjectCN;
    private JLabel jlIssuerCN;
    private JTextField jtfIssuerCN;
    private JLabel jlSerialNumberHex;
    private JTextField jtfSerialNumberHex;
    private JLabel jlSerialNumberDec;
    private JTextField jtfSerialNumberDec;
    private JButton jbOK;
    private JButton jbCancel;
    private boolean success = false;
    private Map<String, String> mapValues = new HashMap<>();
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

		jlSubjectCN = new JLabel(res.getString("DFindKeyStoreEntry.jlSubjectCN.text"));
		jtfSubjectCN = new JTextField(20);
		jtfSubjectCN.setToolTipText(res.getString("DFindKeyStoreEntry.jdnSubjectCN.tooltip"));

		jlIssuerCN = new JLabel(res.getString("DFindKeyStoreEntry.jlIssuerCN.text"));
		jtfIssuerCN = new JTextField(20);
		jtfIssuerCN.setToolTipText(res.getString("DFindKeyStoreEntry.jtfIssuerCN.tooltip"));

		jlSerialNumberHex = new JLabel(res.getString("DFindKeyStoreEntry.jlSerialNumberHex.text"));
		jtfSerialNumberHex = new JTextField(20);
		jtfSerialNumberHex.setEditable(true);
		jtfSerialNumberHex.setToolTipText(res.getString("DFindKeyStoreEntry.jtfSerialNumberHex.tooltip"));
		jtfSerialNumberHex.setCaretPosition(0);

		jlSerialNumberDec = new JLabel(res.getString("DFindKeyStoreEntry.jlSerialNumberDec.text"));
		jtfSerialNumberDec = new JTextField(20);
		jtfSerialNumberDec.setEditable(true);
		jtfSerialNumberDec.setToolTipText(res.getString("DFindKeyStoreEntry.jtfSerialNumberDec.tooltip"));
		jtfSerialNumberDec.setCaretPosition(0);

		jbOK = new JButton(res.getString("DFindKeyStoreEntry.jbOK.text"));
		jbOK.addActionListener(evt -> okPressed());

		jbCancel = new JButton(res.getString("DFindKeyStoreEntry.jbCancel.text"));
		jbCancel.addActionListener(evt -> cancelPressed());
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));

		pane.add(jlEntryName, "");
		pane.add(jtfEntryName, "growx, pushx, wrap");
		pane.add(jlSubjectCN, "");
		pane.add(jtfSubjectCN, "growx, pushx, wrap");
		pane.add(jlIssuerCN, "");
		pane.add(jtfIssuerCN, "growx, pushx, wrap");
		pane.add(jlSerialNumberHex, "");
		pane.add(jtfSerialNumberHex, "growx, pushx, wrap");
		pane.add(jlSerialNumberDec, "");
		pane.add(jtfSerialNumberDec, "growx, pushx, wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap rel:push");
		pane.add(jbCancel, "spanx, split 2, tag cancel");
		pane.add(jbOK, "tag ok");
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
    	mapValues.clear();
    	if (!jtfEntryName.getText().isEmpty()) {
    		mapValues.put("EntryName", jtfEntryName.getText());
    	}
    	if (!jtfSubjectCN.getText().isEmpty()) {
    		mapValues.put("SubjectCN", jtfSubjectCN.getText());
    	}
    	if (!jtfIssuerCN.getText().isEmpty()) {
    		mapValues.put("IssuerCN", jtfIssuerCN.getText());
    	}
    	if (!jtfSerialNumberHex.getText().isEmpty()) {
    		mapValues.put("SerialNumberHex", jtfSerialNumberHex.getText());
    	}
    	if (!jtfSerialNumberDec.getText().isEmpty()) {
    		mapValues.put("SerialNumberDec", jtfSerialNumberDec.getText());
    	}
        if (mapValues.isEmpty()) {
            JOptionPane.showMessageDialog(getParent(), res.getString("DFindKeyStoreEntry.NotEmpty.message"),
                                          res.getString("DFindKeyStoreEntry.Title"), JOptionPane.INFORMATION_MESSAGE);
            jtfEntryName.requestFocus();
            return;
        }
        success = true;
        closeDialog();
    }

    public boolean isSuccess() {
        return success;
    }

    public Map<String, String> getMapValues()
    {
    	return mapValues;
    }
 
    public static void main(String[] args) throws UnsupportedLookAndFeelException {
    	DFindKeyStoreEntry dialog = new DFindKeyStoreEntry(new javax.swing.JFrame());
    	DialogViewer.run(dialog);
	}
}
