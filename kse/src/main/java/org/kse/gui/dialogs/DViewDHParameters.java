/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.kse.crypto.CryptoException;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

import net.miginfocom.swing.MigLayout;

/**
 * <h1>DH Parameters view</h1> The DViewDHParametersn class displays the results
 * of the generated DH Parameters.
 * <p>
 * The class provides the function to copy the content to the clip board and
 * export the content to PEM format.
 */
public class DViewDHParameters extends JEscDialog {

    private static final long serialVersionUID = -1711814777923997727L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JTextArea jtAreaPem;
    private JScrollPane jspAreaPem;
    private JButton jbExport;
    private JButton jbOK;
    private JButton jbCopy;
    private static int keySize;
    private byte[] dhParameters;
    private static final String FILE_SUFFIX = ".pem";
    private static final String EB = "DH PARAMETERS"; // Encapsulation Boundary

    /**
     * Creates a new DViewDHParameters dialog.
     *
     * @param parent   The parent frame
     * @param title    The title of the dialogue
     * @param dhParams The byte array of DER encoded DH Parameters
     */
    public DViewDHParameters(JFrame parent, String title, byte[] dhParams) throws CryptoException {

        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        this.dhParameters = dhParams;
        initComponents(dhParameters);
    }

    /**
     * Initializes the dialogue panel and associated elements
     *
     * @param dhParams The byte array for the DH Parameters
     * @throws CryptoException
     */
    private void initComponents(byte[] dhParams) throws CryptoException {
        // TODO Generate DH Parameters icon
        PemInfo pemInfo = new PemInfo(EB, null, dhParams);
        jtAreaPem = new JTextArea(PemUtil.encode(pemInfo));
        jtAreaPem.setToolTipText(res.getString("DViewDHParameters.jtAreaPem.tooltip"));
        jtAreaPem.setEditable(false);
        jtAreaPem.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
        // keep uneditable color same as editable
		jtAreaPem.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);

		jspAreaPem = PlatformUtil.createScrollPane(jtAreaPem, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		
        jbExport = new JButton(res.getString("DViewDHParameters.jbExport.export.text"));
        jbExport.setToolTipText(res.getString("DViewDHParameters.jbExport.export.tooltip"));
        PlatformUtil.setMnemonic(jbExport, res.getString("DViewDHParameters.jbExport.mnemonic").charAt(0));

        jbCopy = new JButton(res.getString("DViewDHParameters.jbCopy.text"));
        jbCopy.setToolTipText(res.getString("DViewDHParameters.jbCopy.tooltip"));
        PlatformUtil.setMnemonic(jbCopy, res.getString("DViewDHParameters.jbCopy.mnemonic").charAt(0));

        jbOK = new JButton(res.getString("DViewDHParameters.jbOK.text"));

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog"));
        pane.add(jspAreaPem, "span");
        pane.add(jbCopy, "tag Copy");
        pane.add(jbExport, "tag Export");
        pane.add(jbOK, "tag Ok");

        jbOK.addActionListener(evt -> okPressed());

        jbExport.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewDHParameters.this);
                exportPressed();
            } finally {
                CursorUtil.setCursorFree(DViewDHParameters.this);
            }
        });

        jbCopy.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewDHParameters.this);
                copyPressed();
            } finally {
                CursorUtil.setCursorFree(DViewDHParameters.this);
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbCopy);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    /**
     * Writes Base64 encoded PEM format to a specified file
     * <p>
     * See RFC 1421 for further information on PEM formatting
     * <p>
     *
     * @param filePath           Accepts a string file path
     * @param DEREncodedDHParams Accepts a byte array
     */
    private void writeDHParams(String filePath, byte[] DEREncodedDHParams) {
        PemWriter pemWrt;

        try {
            pemWrt = new PemWriter(new FileWriter(filePath));
            pemWrt.writeObject(new PemObject(EB, DEREncodedDHParams));
            pemWrt.flush();
            pemWrt.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Calls the close dialogue window
     */
    private void okPressed() {
        closeDialog();
    }

    /**
     * Closes the dialogue window
     */
    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    /**
     * Sets the file path of the exported file.
     * <p>
     * Validates .pem file suffix. Sets .pem file suffix if not typed.
     */
    private void exportPressed() {
        File chosenFile = null;

        String title = res.getString("DViewDHParameters.ExportPem.Title");

        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(title);
        chooser.setMultiSelectionEnabled(false);
        chooser.setFileFilter(new FileNameExtensionFilter("Pem files (*.pem)", "pem"));
        chooser.setAcceptAllFileFilterUsed(false);

        int rtnValue = JavaFXFileChooser.isFxAvailable() ?
                       chooser.showSaveDialog(this) :
                       chooser.showDialog(this, res.getString("DViewDHParameters.ChooseExportFile.button"));

        if (rtnValue != JFileChooser.APPROVE_OPTION) {
            return;
        }

        chosenFile = chooser.getSelectedFile();
        CurrentDirectory.updateForFile(chosenFile);

        if (chosenFile.isFile()) {
            String message = MessageFormat.format(res.getString("DViewDHParameters.OverWriteFile.message"), chosenFile);

            int selected = JOptionPane.showConfirmDialog(this, message, title, JOptionPane.YES_NO_OPTION);
            if (selected != JOptionPane.YES_OPTION) {
                return;
            }
        }

        if (!chosenFile.getAbsolutePath().endsWith(FILE_SUFFIX)) {
            writeDHParams(chosenFile.getAbsolutePath() + FILE_SUFFIX, dhParameters);
        } else {
            writeDHParams(chosenFile.getAbsolutePath(), dhParameters);
        }

        JOptionPane.showMessageDialog(this, res.getString("DViewDHParameters.ExportPemSuccessful.message"), title,
                                      JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Copies the contents of the text area to the clip board.
     */
    private void copyPressed() {
        String policy = jtAreaPem.getText();

        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection copy = new StringSelection(policy);
        clipboard.setContents(copy, copy);
    }

    // Quick UI test
    public static void main(String[] args) throws Exception, IOException, GeneralSecurityException {
        DialogViewer.prepare();
        keySize = 512;

        DGeneratingDHParameters testDH = new DGeneratingDHParameters(new javax.swing.JFrame(), keySize);
        testDH.startDHParametersGeneration();
        testDH.setVisible(true);

        DViewDHParameters dialog = new DViewDHParameters(new javax.swing.JFrame(), "Title", testDH.getDHParameters());
        DialogViewer.run(dialog);
    }

}
