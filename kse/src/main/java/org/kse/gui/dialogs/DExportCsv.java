/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to display options to export the KeyStore table as a CSV file.
 */
public class DExportCsv extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JButton jbExport;
    private JButton jbCancel;

    private String name;
    private boolean exportSelected = false;
    private File exportFile;

    /**
     * Creates a new DExportCsv dialog.
     *
     * @param parent     The parent frame
     * @param name       The KeyStore name
     */
    public DExportCsv(JFrame parent, String name) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.name = name;
        initComponents();
    }

    private void initComponents() {
        jlExportFile = new JLabel(res.getString("DExportCsv.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportCsv.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportCsv.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportCsv.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportCsv.jbBrowse.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DExportCsv.jbExport.text"));
        jbExport.setToolTipText(res.getString("DExportCsv.jbExport.tooltip"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DExportCsv.jbExport.mnemonic").charAt(0));

        jbCancel = new JButton(res.getString("DExportCsv.jbCancel.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));
        pane.add(jlExportFile, "");
        pane.add(jtfExportFile, "");
        pane.add(jbBrowse, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbExport, "right, spanx, split, tag ok");
        pane.add(jbCancel, "tag cancel");


        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportCsv.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportCsv.this);
            }
        });

        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportCsv.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportCsv.this);
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
                cancelPressed();
            }
        });

        setTitle(MessageFormat.format(res.getString("DExportCsv.Title"), name));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        // Not sanitizing. The keystore name is always a file name.
        File csrFile = new File(currentDirectory, name + "." + FileChooserFactory.CSV_EXT);
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

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getCsvFileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportCsv.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                       chooser.showSaveDialog(this) :
                       chooser.showDialog(this, res.getString("DExportCsv.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
        }
    }

    private void exportPressed() {
        String exportFileStr = jtfExportFile.getText().trim();

        if (exportFileStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportCsv.ExportFileRequired.message"),
                                          res.getString("DExportCsv.Simple.Title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileStr);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportCsv.OverWriteExportFile.message"), exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message, res.getString("DExportCsv.Simple.Title"),
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
        DialogViewer.run(new DExportCsv(new JFrame(), "test keystore"));
    }
}
