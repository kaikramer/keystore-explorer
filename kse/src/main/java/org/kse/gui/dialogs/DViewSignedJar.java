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
import java.awt.Dimension;
import java.awt.Point;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.jar.JarEntry;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.kse.crypto.CryptoException;
import org.kse.crypto.signing.CmsSignatureStatus;
import org.kse.crypto.signing.KseJarEntry;
import org.kse.crypto.signing.KseSignerInformation;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.error.DError;
import org.kse.utilities.StringUtils;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a signed JAR file.
 */
public class DViewSignedJar extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JButton jbOK;
    private JButton jbSignatures;
    private JLabel jlVerifyStatus;
    private JTextField jtfVerifyStatus;
    private JScrollPane jspJarEntryTable;
    private JTable jtJarEntries;
    private JButton jbJarEntryCertificates;

    private List<KseJarEntry> jarEntries;
    private Map<String, Collection<KseSignerInformation>> jarSigners;
    private Store<X509CertificateHolder> tsaTrustedCerts;
    private KseFrame kseFrame;

    /**
     * Creates a new DViewSignedJar dialog.
     *
     * @param parent          Parent frame
     * @param title           The dialog title
     * @param jarEntries      JAR entries to display
     * @param jarSigners      JAR signers
     * @param tsaTrustedCerts All trusted certs suitable for verifying TSA signatures
     * @param kseFrame        Reference to main class with currently opened keystores and their contents
     */
    public DViewSignedJar(Window parent, String title, List<KseJarEntry> jarEntries,
            Map<String, Collection<KseSignerInformation>> jarSigners, Store<X509CertificateHolder> tsaTrustedCerts,
            KseFrame kseFrame) {
        super(parent, title, Dialog.ModalityType.MODELESS);
        this.jarEntries = jarEntries;
        this.jarSigners = jarSigners;
        this.tsaTrustedCerts = tsaTrustedCerts;
        this.kseFrame = kseFrame;
        initComponents();
    }

    private static class DateRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;

        @Override
        protected void setValue(Object value) {
            setText(StringUtils.formatDate((Date) value));
        }
    }


    private static final String[] COLUMN_TOOL_TIPS = { //
            "SignedJarTableModel.FlagsColumn.tooltip", //
            "SignedJarTableModel.SizeColumn.tooltip", //
            "SignedJarTableModel.DateColumn.tooltip", //
            "SignedJarTableModel.NameColumn.tooltip" //
    };

    private static class ToolTipTable extends JTable {
        // https://docs.oracle.com/javase/tutorial/uiswing/components/table.html#headertooltip
        private static final long serialVersionUID = 1L;

        private String[] columnToolTips;

        public ToolTipTable(TableModel tableModel, String[] columnToolTips) {
            super(tableModel);
            this.columnToolTips = columnToolTips;
        }

        @Override
        protected JTableHeader createDefaultTableHeader() {
            return new JTableHeader(columnModel) {
                @Override
                public String getToolTipText(MouseEvent event) {
                    Point p = event.getPoint();
                    int index = columnModel.getColumnIndexAtX(p.x);
                    int realIndex = columnModel.getColumn(index).getModelIndex();
                    return res.getString(columnToolTips[realIndex]);
                }
            };
        }
    }

    private void initComponents() {

        jlVerifyStatus = new JLabel(res.getString("DViewSignedJar.jlVerifyStatus.text"));

        jtfVerifyStatus = new JTextField(40);
        jtfVerifyStatus.setEditable(false);

        SignedJarTableModel tableModel = new SignedJarTableModel();

        jtJarEntries = new ToolTipTable(tableModel, COLUMN_TOOL_TIPS);

        RowSorter<SignedJarTableModel> sorter = new TableRowSorter<>(tableModel);
        jtJarEntries.setRowSorter(sorter);

        jtJarEntries.setShowGrid(false);
        jtJarEntries.setRowMargin(0);
        jtJarEntries.getColumnModel().setColumnMargin(0);
        jtJarEntries.getTableHeader().setReorderingAllowed(false);
        jtJarEntries.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        for (int i = 0; i < jtJarEntries.getColumnCount(); i++) {
            TableColumn column = jtJarEntries.getColumnModel().getColumn(i);

            column.setPreferredWidth(tableModel.getColumnSize(i));
            if (i == SignedJarTableModel.COL_DATE) {
                column.setCellRenderer(new DateRenderer());
            }
        }

        ListSelectionModel listSelectionModel = jtJarEntries.getSelectionModel();
        listSelectionModel.addListSelectionListener(evt -> {
            if (!evt.getValueIsAdjusting())  { // Ignore spurious events
                try {
                    CursorUtil.setCursorBusy(DViewSignedJar.this);
                    entrySelection();
                } finally {
                    CursorUtil.setCursorFree(DViewSignedJar.this);
                }
            }
        });

        jtJarEntries.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent evt) {
                maybeDisplayJarEntryCertificates(evt);
            }
        });

        jspJarEntryTable = PlatformUtil.createScrollPane(jtJarEntries,
                                                             ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                             ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspJarEntryTable.getViewport().setBackground(jtJarEntries.getBackground());
        jspJarEntryTable.setPreferredSize(new Dimension(600, 200));

        jbJarEntryCertificates = new JButton(res.getString("DViewSignedJar.jbJarEntryCertificates.text"));

        PlatformUtil.setMnemonic(jbJarEntryCertificates,
                                 res.getString("DViewSignedJar.jbJarEntryCertificates.mnemonic").charAt(0));
        jbJarEntryCertificates.setToolTipText(res.getString("DViewSignedJar.jbJarEntryCertificates.tooltip"));
        jbJarEntryCertificates.setEnabled(false);
        jbJarEntryCertificates.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewSignedJar.this);
                jarEntryCertificatesPressed();
            } finally {
                CursorUtil.setCursorFree(DViewSignedJar.this);
            }
        });

        jbOK = new JButton(res.getString("DViewSignedJar.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jbSignatures = new JButton(res.getString("DViewSignedJar.jbSignatures.text"));
        jbSignatures.addActionListener(evt -> signaturesPressed());
        PlatformUtil.setMnemonic(jbSignatures,
                res.getString("DViewSignedJar.jbSignatures.mnemonic").charAt(0));
        jbSignatures.setToolTipText(res.getString("DViewSignedJar.jbSignatures.tooltip"));

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", ""));

        pane.add(jlVerifyStatus, "");
        pane.add(jtfVerifyStatus, "growx, wrap");
        pane.add(jspJarEntryTable, "split, spanx, growx, wrap");
        pane.add(jbSignatures, "split, spanx");
        pane.add(jbJarEntryCertificates, "split, spanx, right, wrap");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jbOK, "split, spanx, right, tag ok");

        populateDialog();

        setResizable(false);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private void populateDialog() {

        // This dialog is only for displaying verified signatures. Default to not trusted.
        CmsSignatureStatus jarStatus = CmsSignatureStatus.VALID_NOT_TRUSTED;
        for (Collection<KseSignerInformation> jarSigner : jarSigners.values()) {
            CmsSignatureStatus signerStatus = jarSigner.iterator().next().getStatus();

            if (signerStatus == CmsSignatureStatus.VALID_TRUSTED && jarStatus == CmsSignatureStatus.VALID_NOT_TRUSTED) {
                jarStatus = signerStatus;
            }
        }
        jtfVerifyStatus.setText(res.getString("DViewSignedJar." + jarStatus + ".text"));
        jtfVerifyStatus.setToolTipText(res.getString("DViewSignedJar." + jarStatus + ".tooltip"));

        SignedJarTableModel signedJarTableModel = (SignedJarTableModel) jtJarEntries.getModel();
        signedJarTableModel.load(jarEntries);

        if (signedJarTableModel.getRowCount() > 0) {
            jtJarEntries.changeSelection(0, 0, false, false);
        }
    }

    private void entrySelection() {
        int row = jtJarEntries.getSelectedRow();

        if (row != -1) {
            KseJarEntry jarEntry = jarEntries.get(row);

            if (hasCertificates(jarEntry)) {
                jbJarEntryCertificates.setEnabled(true);
                return;
            }
        }

        jbJarEntryCertificates.setEnabled(false);
    }

    private boolean hasCertificates(JarEntry jarEntry) {
        return !Arrays.isNullOrEmpty(jarEntry.getCertificates());
    }

    private void jarEntryCertificatesPressed() {
        displayJarEntryCertificates();
    }

    private void maybeDisplayJarEntryCertificates(MouseEvent evt) {
        if (evt.getClickCount() > 1) {
            Point point = new Point(evt.getX(), evt.getY());
            int row = jtJarEntries.rowAtPoint(point);

            if (row != -1) {
                try {
                    CursorUtil.setCursorBusy(DViewSignedJar.this);
                    jtJarEntries.setRowSelectionInterval(row, row);
                    if (hasCertificates(jarEntries.get(row))) {
                        displayJarEntryCertificates();
                    }
                } finally {
                    CursorUtil.setCursorFree(DViewSignedJar.this);
                }
            }
        }
    }

    private void displayJarEntryCertificates() {
        int row = jtJarEntries.getSelectedRow();

        if (row != -1) {
            KseJarEntry jarEntry = jarEntries.get(row);

            try {
                DViewCertificate dViewExtensions = new DViewCertificate(this,
                        res.getString("DViewSignedJar.ViewCertificate.Title"),
                        X509CertUtil.convertCertificates(jarEntry.getCertificates()), kseFrame, DViewCertificate.NONE);
                dViewExtensions.setLocationRelativeTo(this);
                dViewExtensions.setVisible(true);
            } catch (CryptoException e) {
                DError.displayError(this, e);
            }
        }
    }

    private void signaturesPressed() {
        DViewSignature dViewSignature = new DViewSignature(this, res.getString("DViewSignedJar.SignatureDetals.Title"),
                jarSigners, tsaTrustedCerts, kseFrame);
        dViewSignature.setLocationRelativeTo(this);
        dViewSignature.setVisible(true);
    }

    private void okPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
