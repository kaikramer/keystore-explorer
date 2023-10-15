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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;

import org.kse.gui.JEscDialog;
import org.kse.gui.MiGUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * <h1> DH Parameters selection</h1>
 * The DGenerateDHParameters class provides the user
 * with the key size selection of DH Parameters to be
 * generated.
 * <p>
 * The parameter generation is through the provider Bouncy Castle which
 * uses a Sophie Germain search to identify a safe prime. The search
 * method takes an exceptionally lengthy time with a selection above a 2048 bit
 * key size. There is no technical limitation and the key size can be expanded
 * if there is a demand for additional settings.
 * <p>
 * An expansion of this class can allow specific key sizes and the inclusion
 * of DH standard RFC groups.
 */

public class DGenerateDHParameters extends JEscDialog {

    private static final long serialVersionUID = 5909033737483232104L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";
    private String[] keySizeSelection = { "1024", "2048" };
    private JLabel jlDHKeySize;
    private JComboBox<String> jcbDHKeySize;

    private JButton jbOK;
    private JButton jbCancel;
    private int dhKeySize;
    private boolean success = false;

    /**
     * Creates a new DGeneratingKeyPair dialog.
     *
     * @param parent The parent frame
     */
    public DGenerateDHParameters(JFrame parent) {
        super(parent, res.getString("DGenerateDHParameters.Title"), Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    /**
     * Initializes the dialogue panel and associated elements
     */
    private void initComponents() {

        //TODO Generate DH Parameters icon
        //ImageIcon icon = new ImageIcon(getClass().getResource("images/gendhp.png"));
        //jlGenDHParam.setIcon(icon);
        //jlGenDHParam.setHorizontalTextPosition(SwingConstants.LEADING);
        //jlGenDHParam.setIconTextGap(15);

        jlDHKeySize = new JLabel(res.getString("DGenerateDHParameters.jlDHKeySize.text"));

        jcbDHKeySize = new JComboBox<>();
        jcbDHKeySize.setModel(new DefaultComboBoxModel<>(keySizeSelection));
        jcbDHKeySize.setSelectedIndex(1);
        jcbDHKeySize.setToolTipText(res.getString("DGenerateDHParameters.jcbDHKeySize.tooltip"));

        JTextArea jtAreaFooter = new JTextArea();
        jtAreaFooter.setColumns(25);
        jtAreaFooter.setText(res.getString("DGenerateDHParameters.jtAreaFooter.text"));
        jtAreaFooter.setEditable(false);
        jtAreaFooter.setLineWrap(true);
        jtAreaFooter.setWrapStyleWord(true);
        jtAreaFooter.setBackground(getBackground());

        jbCancel = new JButton(res.getString("DGenerateDHParameters.jbCancel.text"));
        jbOK = new JButton(res.getString("DGenerateDHParameters.jbOK.text"));

        JPanel buttons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[indent][][]", ""));
        MiGUtil.addSeparator(pane, res.getString("DGenerateDHParameters.jpContent.text"));
        pane.add(jlDHKeySize, "skip, align right");
        pane.add(jcbDHKeySize, "wrap");
        pane.add(jtAreaFooter, "growx, spanx, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(buttons, "right, spanx");

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

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

    /**
     * Set the selected key size.
     */
    private void setKeySize() {
        dhKeySize = Integer.parseInt((String) jcbDHKeySize.getSelectedItem());
    }

    /**
     * Get the selected key size.
     *
     * @return The key size value
     */
    public int getKeySize() {
        return dhKeySize;
    }

    /**
     * Have the parameters been entered correctly?
     *
     * @return True if they have, false otherwise
     */
    public boolean isSuccessful() {
        return success;
    }

    /**
     * Calls the set key size
     * <p>
     * Sets the success value to true
     * <p>
     * Calls the close dialogue
     */
    private void okPressed() {
        setKeySize();
        success = true;
        closeDialog();
    }

    /**
     * Calls the close the dialogue
     */
    private void cancelPressed() {
        closeDialog();
    }

    /**
     * Closes the dialogue
     */
    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick UI testing
    public static void main(String[] args) throws Exception {
        DGenerateDHParameters dialog = new DGenerateDHParameters(new JFrame());
        DialogViewer.run(dialog);
    }

}
