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

package org.kse.gui.dialogs.importexport;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export a CRL file.
 */
public class DExportCrl extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JPanel jpOptions;
    private JLabel jlExportPem;
    private JCheckBox jcbExportPem;
    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JPanel jpButtons;
    private JButton jbExport;
    private JButton jbCancel;

    private String entryAlias;
    private boolean exportSelected = false;
    private File exportFile;
    private boolean pemEncode;

    /**
     * Creates a new DExportCrl dialog.
     *
     * @param parent     The parent frame
     * @param entryAlias The entry alias
     */
    public DExportCrl(JFrame parent, String entryAlias) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.entryAlias = entryAlias;
        initComponents();
    }

    private void initComponents() {
        jlExportPem = new JLabel(res.getString("DExportCrl.jlExportPem.text"));

        jcbExportPem = new JCheckBox();
        jcbExportPem.setSelected(true);
        jcbExportPem.setToolTipText(res.getString("DExportCrl.jcbExportPem.tooltip"));

        jlExportFile = new JLabel(res.getString("DExportCrl.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportCrl.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportCrl.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportCrl.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportCrl.jbBrowse.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DExportCrl.jbExport.text"));
        jbExport.setToolTipText(res.getString("DExportCrl.jbExport.tooltip"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DExportCrl.jbExport.mnemonic").charAt(0));

        jbCancel = new JButton(res.getString("DExportCrl.jbCancel.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));
        pane.add(jlExportPem, "");
        pane.add(jcbExportPem, "wrap");
        pane.add(jlExportFile, "");
        pane.add(jtfExportFile, "");
        pane.add(jbBrowse, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbExport, "right, spanx, split, tag ok");
        pane.add(jbCancel, "tag cancel");


        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportCrl.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportCrl.this);
            }
        });

        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportCrl.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportCrl.this);
            }
        });

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

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(MessageFormat.format(res.getString("DExportCrl.Title"), entryAlias));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
        File csrFile = new File(currentDirectory, sanitizedAlias + "." + FileChooserFactory.CRL_EXT);
        jtfExportFile.setText(csrFile.getPath());
    }

    /**
     * Has the user chosen to export?
     *
     * @return True if they have
     */
    public boolean exportSelected() {
        return exportSelected;
    }

    /**
     * Get chosen export file.
     *
     * @return Export file
     */
    public File getExportFile() {
        return exportFile;
    }

    /**
     * Was the option to PEM encode selected?
     *
     * @return True if it was
     */
    public boolean pemEncode() {
        return pemEncode;
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getPublicKeyFileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportCrl.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                       chooser.showSaveDialog(this) :
                       chooser.showDialog(this, res.getString("DExportCrl.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
        }
    }

    private void exportPressed() {
        pemEncode = jcbExportPem.isSelected();

        String exportFileStr = jtfExportFile.getText().trim();

        if (exportFileStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportCrl.ExportFileRequired.message"),
                                          res.getString("DExportCrl.Simple.Title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileStr);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportCrl.OverWriteExportFile.message"), exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message, res.getString("DExportCrl.Simple.Title"),
                                                         JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return;
            }
        }

        this.exportFile = exportFile;

        exportSelected = true;

        closeDialog();
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException {
        DialogViewer.run(new DExportCrl(new JFrame(), "test alias"));
    }
}
