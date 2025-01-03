package org.kse.gui.dialogs.importexport;

import net.miginfocom.swing.MigLayout;
import org.kse.gui.*;
import org.kse.gui.components.JEscDialog;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.io.FileNameUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import static org.kse.gui.FileChooserFactory.JWK_EXT;
import static org.kse.gui.FileChooserFactory.OPENSSL_PVK_EXT;

public class DExportPrivateKeyJwk extends JEscDialog {
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/importexport/resources");
    public static final String JWK_FILE_EXT = '.' + OPENSSL_PVK_EXT + '.' + JWK_EXT;
    private static final String CANCEL_KEY = "CANCEL_KEY";
    private final String entryAlias;
    private File exportFile;
    private boolean exportSelected;
    private JLabel jlExportFile;
    private JTextField jtfExportFile;
    private JButton jbBrowse;
    private JButton jbExport;
    private JButton jbCancel;

    public DExportPrivateKeyJwk(JFrame parent, String entryAlias) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.entryAlias = entryAlias;
        initComponents();
    }

    private void initComponents() {

        jlExportFile = new JLabel(res.getString("DExportPrivateKeyJwk.jlExportFile.text"));

        jtfExportFile = new JTextField(30);
        jtfExportFile.setToolTipText(res.getString("DExportPrivateKeyJwk.jtfExportFile.tooltip"));

        jbBrowse = new JButton(res.getString("DExportPrivateKeyJwk.jbBrowse.text"));
        jbBrowse.setToolTipText(res.getString("DExportPrivateKeyJwk.jbBrowse.tooltip"));
        PlatformUtil.setMnemonic(jbBrowse, res.getString("DExportPrivateKeyJwk.jbBrowse.mnemonic").charAt(0));

        jbExport = new JButton(res.getString("DExportPrivateKeyJwk.jbExport.text"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DExportPrivateKeyJwk.jbExport.mnemonic").charAt(0));
        jbExport.setToolTipText(res.getString("DExportPrivateKeyJwk.jbExport.tooltip"));

        jbCancel = new JButton(res.getString("DExportPrivateKeyJwk.jbCancel.text"));

        // layout
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]rel[]", "[]unrel[]"));

        pane.add(jlExportFile, "");
        pane.add(jtfExportFile, "");
        pane.add(jbBrowse, "wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbExport, "right, spanx, split, tag ok");
        pane.add(jbCancel, "tag cancel");

        // actions

        jbBrowse.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyJwk.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyJwk.this);
            }
        });

        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DExportPrivateKeyJwk.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DExportPrivateKeyJwk.this);
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

        setTitle(MessageFormat.format(res.getString("DExportPrivateKeyJwk.Title"), entryAlias));
        setResizable(false);

        getRootPane().setDefaultButton(jbExport);

        populateExportFileName();

        pack();
    }

    public boolean exportSelected() {
        return exportSelected;
    }

    public File getExportFile() {
        return exportFile;
    }

    private void populateExportFileName() {
        File currentDirectory = CurrentDirectory.get();
        String sanitizedAlias = FileNameUtil.cleanFileName(entryAlias);
        File csrFile = new File(currentDirectory, sanitizedAlias + JWK_FILE_EXT);
        jtfExportFile.setText(csrFile.getPath());
    }

    private void exportPressed() {
        String exportFileChars = jtfExportFile.getText().trim();

        if (exportFileChars.isEmpty()) {
            JOptionPane.showMessageDialog(this, res.getString("DExportPrivateKeyJwk.ExportFileRequired.message"),
                    res.getString("DExportPrivateKeyJwk.Simple.Title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        File exportFile = new File(exportFileChars);

        if (exportFile.isFile()) {
            String message = MessageFormat.format(res.getString("DExportPrivateKeyJwk.OverWriteExportFile.message"),
                    exportFile);

            int selected = JOptionPane.showConfirmDialog(this, message,
                    res.getString("DExportPrivateKeyJwk.Simple.Title"),
                    JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return;
            }
        }

        this.exportFile = exportFile;

        exportSelected = true;

        closeDialog();
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getOpenSslPvkFileChooser();

        File currentExportFile = new File(jtfExportFile.getText().trim());

        if ((currentExportFile.getParentFile() != null) && (currentExportFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(currentExportFile.getParentFile());
            chooser.setSelectedFile(currentExportFile);
        } else {
            chooser.setCurrentDirectory(CurrentDirectory.get());
        }

        chooser.setDialogTitle(res.getString("DExportPrivateKeyJwk.ChooseExportFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                chooser.showSaveDialog(this) :
                chooser.showDialog(this, res.getString("DExportPrivateKeyJwk.ChooseExportFile.button"));
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File chosenFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(chosenFile);
            jtfExportFile.setText(chosenFile.toString());
            jtfExportFile.setCaretPosition(0);
        }
    }

    private void cancelPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.run(new DExportPrivateKeyJwk(new JFrame(), "alias"));
    }
}
