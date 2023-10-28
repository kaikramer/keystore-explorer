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

import java.awt.Color;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.text.MessageFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.dialogs.extensions.DViewExtensions;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.StringUtils;
import org.kse.utilities.asn1.Asn1Exception;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a Certificate Revocation List (CRL).
 */
public class DViewCrl extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private JButton jbOK;
    private JLabel jlVersion;
    private JTextField jtfVersion;
    private JLabel jlIssuer;
    private JDistinguishedName jdnIssuer;
    private JLabel jlEffectiveDate;
    private JTextField jtfEffectiveDate;
    private JLabel jlNextUpdate;
    private JTextField jtfNextUpdate;
    private JLabel jlSignatureAlgorithm;
    private JTextField jtfSignatureAlgorithm;
    private JButton jbCrlExtensions;
    private JButton jbCrlAsn1;
    private JLabel jlRevokedCerts;
    private JScrollPane jspRevokedCertsTable;
    private JTable jtRevokedCerts;
    private JButton jbCrlEntryExtensions;

    private X509CRL crl;

    /**
     * Creates a new DViewCrl dialog.
     *
     * @param parent Parent frame
     * @param title  The dialog title
     * @param crl    CRL to display
     */
    public DViewCrl(JFrame parent, String title, X509CRL crl) {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        this.crl = crl;
        initComponents();
    }

    /**
     * Creates new DViewCrl dialog where the parent is a dialog.
     *
     * @param parent   Parent dialog
     * @param title    The dialog title
     * @param modality Dialog modality
     * @param crl      CRL to display
     */
    public DViewCrl(JDialog parent, String title, Dialog.ModalityType modality, X509CRL crl) {
        super(parent, title, modality);
        this.crl = crl;
        initComponents();
    }

    private void initComponents() {
        jlVersion = new JLabel(res.getString("DViewCrl.jlVersion.text"));

        jtfVersion = new JTextField(30);
        jtfVersion.setEditable(false);
        jtfVersion.setToolTipText(res.getString("DViewCrl.jtfVersion.tooltip"));

        jlIssuer = new JLabel(res.getString("DViewCrl.jlIssuer.text"));

        jdnIssuer = new JDistinguishedName(res.getString("DViewCrl.Issuer.Title"), 30, false);
        jdnIssuer.setToolTipText(res.getString("DViewCrl.jdnIssuer.tooltip"));

        jlEffectiveDate = new JLabel(res.getString("DViewCrl.jlEffectiveDate.text"));

        jtfEffectiveDate = new JTextField(30);
        jtfEffectiveDate.setEditable(false);
        jtfEffectiveDate.setToolTipText(res.getString("DViewCrl.jtfEffectiveDate.tooltip"));

        jlNextUpdate = new JLabel(res.getString("DViewCrl.jlNextUpdate.text"));

        jtfNextUpdate = new JTextField(30);
        jtfNextUpdate.setEditable(false);
        jtfNextUpdate.setToolTipText(res.getString("DViewCrl.jtfNextUpdate.tooltip"));

        jlSignatureAlgorithm = new JLabel(res.getString("DViewCrl.jlSignatureAlgorithm.text"));

        jtfSignatureAlgorithm = new JTextField(30);
        jtfSignatureAlgorithm.setEditable(false);
        jtfSignatureAlgorithm.setToolTipText(res.getString("DViewCrl.jtfSignatureAlgorithm.tooltip"));

        jbCrlExtensions = new JButton(res.getString("DViewCrl.jbCrlExtensions.text"));

        PlatformUtil.setMnemonic(jbCrlExtensions, res.getString("DViewCrl.jbCrlExtensions.mnemonic").charAt(0));
        jbCrlExtensions.setToolTipText(res.getString("DViewCrl.jbCrlExtensions.tooltip"));
        jbCrlExtensions.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewCrl.this);
                crlExtensionsPressed();
            } finally {
                CursorUtil.setCursorFree(DViewCrl.this);
            }
        });

        jbCrlAsn1 = new JButton(res.getString("DViewCrl.jbCrlAsn1.text"));

        PlatformUtil.setMnemonic(jbCrlAsn1, res.getString("DViewCrl.jbCrlAsn1.mnemonic").charAt(0));
        jbCrlAsn1.setToolTipText(res.getString("DViewCrl.jbCrlAsn1.tooltip"));
        jbCrlAsn1.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewCrl.this);
                asn1DumpPressed();
            } finally {
                CursorUtil.setCursorFree(DViewCrl.this);
            }
        });

        jlRevokedCerts = new JLabel(MessageFormat.format(res.getString("DViewCrl.jlRevokedCerts.text"),
                                                         getCrlEntrySize()));

        RevokedCertsTableModel rcModel = new RevokedCertsTableModel();

        jtRevokedCerts = new JTable(rcModel);

        RowSorter<RevokedCertsTableModel> sorter = new TableRowSorter<>(rcModel);
        jtRevokedCerts.setRowSorter(sorter);

        jtRevokedCerts.setShowGrid(false);
        jtRevokedCerts.setRowMargin(0);
        jtRevokedCerts.getColumnModel().setColumnMargin(0);
        jtRevokedCerts.getTableHeader().setReorderingAllowed(false);
        jtRevokedCerts.setAutoResizeMode(JTable.AUTO_RESIZE_NEXT_COLUMN);

        for (int i = 0; i < jtRevokedCerts.getColumnCount(); i++) {
            TableColumn column = jtRevokedCerts.getColumnModel().getColumn(i);

            if (i == 0) {
                column.setPreferredWidth(150);
            }

            column.setHeaderRenderer(
                    new RevokedCertsTableHeadRend(jtRevokedCerts.getTableHeader().getDefaultRenderer()));
            column.setCellRenderer(new RevokedCertsTableCellRend());
        }

        ListSelectionModel listSelectionModel = jtRevokedCerts.getSelectionModel();
        listSelectionModel.addListSelectionListener(evt -> {
            if (!evt.getValueIsAdjusting())  { // Ignore spurious events
                try {
                    CursorUtil.setCursorBusy(DViewCrl.this);
                    crlEntrySelection();
                } finally {
                    CursorUtil.setCursorFree(DViewCrl.this);
                }
            }
        });

        jtRevokedCerts.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent evt) {
                maybeDisplayCrlEntryExtensions(evt);
            }
        });

        jspRevokedCertsTable = PlatformUtil.createScrollPane(jtRevokedCerts,
                                                             ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                             ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspRevokedCertsTable.getViewport().setBackground(jtRevokedCerts.getBackground());
        jspRevokedCertsTable.setPreferredSize(new Dimension(300, 200));

        jbCrlEntryExtensions = new JButton(res.getString("DViewCrl.jbCrlEntryExtensions.text"));

        PlatformUtil.setMnemonic(jbCrlEntryExtensions,
                                 res.getString("DViewCrl.jbCrlEntryExtensions.mnemonic").charAt(0));
        jbCrlEntryExtensions.setToolTipText(res.getString("DViewCrl.jbCrlEntryExtensions.tooltip"));
        jbCrlEntryExtensions.setEnabled(false);
        jbCrlEntryExtensions.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DViewCrl.this);
                crlEntryExtensionsPressed();
            } finally {
                CursorUtil.setCursorFree(DViewCrl.this);
            }
        });

        jbOK = new JButton(res.getString("DViewCrl.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", ""));

        pane.add(jlVersion, "");
        pane.add(jtfVersion, "wrap");
        pane.add(jlIssuer, "");
        pane.add(jdnIssuer, "wrap");
        pane.add(jlEffectiveDate, "");
        pane.add(jtfEffectiveDate, "wrap");
        pane.add(jlNextUpdate, "");
        pane.add(jtfNextUpdate, "wrap");
        pane.add(jlSignatureAlgorithm, "");
        pane.add(jtfSignatureAlgorithm, "wrap");
        pane.add(jbCrlExtensions, "split, spanx, right");
        pane.add(jbCrlAsn1, "wrap unrel");
        pane.add(new JSeparator(), "spanx, growx, wrap");
        pane.add(jlRevokedCerts, "split, wrap");
        pane.add(jspRevokedCertsTable, "split, spanx, growx, wrap");
        pane.add(jbCrlEntryExtensions, "split, spanx, right, wrap");
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

    private int getCrlEntrySize() {
        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();
        if (revokedCertificates == null) {
            return 0;
        }
        return revokedCertificates.size();
    }

    private void populateDialog() {
        Date currentDate = new Date();

        Date effectiveDate = crl.getThisUpdate();
        Date updateDate = crl.getNextUpdate();

        boolean effective = currentDate.before(effectiveDate);

        boolean updateAvailable = false;

        if (updateDate != null) {
            updateAvailable = currentDate.after(updateDate);
        }

        jtfVersion.setText(Integer.toString(crl.getVersion()));
        jtfVersion.setCaretPosition(0);

        jdnIssuer.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(crl.getIssuerX500Principal()));

        jtfEffectiveDate.setText(StringUtils.formatDate(effectiveDate));

        if (effective) {
            jtfEffectiveDate.setText(MessageFormat.format(res.getString("DViewCrl.jtfEffectiveDate.noteffective.text"),
                                                          jtfEffectiveDate.getText()));
            jtfEffectiveDate.setForeground(Color.red);
        } else {
            jtfEffectiveDate.setForeground(jtfVersion.getForeground());
        }
        jtfEffectiveDate.setCaretPosition(0);

        if (updateDate != null) {
            jtfNextUpdate.setText(StringUtils.formatDate(updateDate));
        } else {
            jtfNextUpdate.setText(res.getString("DViewCrl.jtfNextUpdate.none.text"));
        }

        if (updateAvailable) {
            jtfNextUpdate.setText(MessageFormat.format(res.getString("DViewCrl.jtfNextUpdate.updateavailable.text"),
                                                       jtfNextUpdate.getText()));
            jtfNextUpdate.setForeground(Color.red);
        } else {
            jtfNextUpdate.setForeground(jtfVersion.getForeground());
        }
        jtfNextUpdate.setCaretPosition(0);

        SignatureType sigAlg = SignatureType.resolveOid(crl.getSigAlgOID(), crl.getSigAlgParams());
        String sigAlgName = (sigAlg != null) ? sigAlg.friendly() : crl.getSigAlgName();

        jtfSignatureAlgorithm.setText(sigAlgName);
        jtfSignatureAlgorithm.setCaretPosition(0);

        Set<?> critExts = crl.getCriticalExtensionOIDs();
        Set<?> nonCritExts = crl.getNonCriticalExtensionOIDs();

        jbCrlExtensions.setEnabled(
                (critExts != null && !critExts.isEmpty()) || (nonCritExts != null && !nonCritExts.isEmpty()));

        Set<? extends X509CRLEntry> revokedCertsSet = crl.getRevokedCertificates();
        if (revokedCertsSet == null) {
            revokedCertsSet = new HashSet<>();
        }
        X509CRLEntry[] revokedCerts = revokedCertsSet.toArray(new X509CRLEntry[0]);
        RevokedCertsTableModel revokedCertsTableModel = (RevokedCertsTableModel) jtRevokedCerts.getModel();
        revokedCertsTableModel.load(revokedCerts);

        if (revokedCertsTableModel.getRowCount() > 0) {
            jtRevokedCerts.changeSelection(0, 0, false, false);
        }
    }

    private void crlEntrySelection() {
        int row = jtRevokedCerts.getSelectedRow();

        if (row != -1) {
            BigInteger serialNumber = (BigInteger) jtRevokedCerts.getValueAt(row, 0);

            Set<?> revokedCertsSet = crl.getRevokedCertificates();

            X509CRLEntry x509CrlEntry = null;

            for (Object o : revokedCertsSet) {
                X509CRLEntry entry = (X509CRLEntry) o;
                if (serialNumber.equals(entry.getSerialNumber())) {
                    x509CrlEntry = entry;
                    break;
                }
            }

            if (x509CrlEntry.hasExtensions()) {
                jbCrlEntryExtensions.setEnabled(true);
                return;
            }
        }

        jbCrlEntryExtensions.setEnabled(false);
    }

    private void crlExtensionsPressed() {
        DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DViewCrl.Extensions.Title"), crl);
        dViewExtensions.setLocationRelativeTo(this);
        dViewExtensions.setVisible(true);
    }

    private void asn1DumpPressed() {
        try {
            DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, crl);
            dViewAsn1Dump.setLocationRelativeTo(this);
            dViewAsn1Dump.setVisible(true);
        } catch (Asn1Exception | IOException e) {
            DError.displayError(this, e);
        }
    }

    private void crlEntryExtensionsPressed() {
        displayCrlEntryExtensions();
    }

    private void maybeDisplayCrlEntryExtensions(MouseEvent evt) {
        if (evt.getClickCount() > 1) {
            Point point = new Point(evt.getX(), evt.getY());
            int row = jtRevokedCerts.rowAtPoint(point);

            if (row != -1) {
                try {
                    CursorUtil.setCursorBusy(DViewCrl.this);
                    jtRevokedCerts.setRowSelectionInterval(row, row);
                    displayCrlEntryExtensions();
                } finally {
                    CursorUtil.setCursorFree(DViewCrl.this);
                }
            }
        }
    }

    private void displayCrlEntryExtensions() {
        int row = jtRevokedCerts.getSelectedRow();

        if (row != -1) {
            BigInteger serialNumber = (BigInteger) jtRevokedCerts.getValueAt(row, 0);

            Set<?> revokedCertsSet = crl.getRevokedCertificates();

            X509CRLEntry x509CrlEntry = null;

            for (Object o : revokedCertsSet) {
                X509CRLEntry entry = (X509CRLEntry) o;
                if (serialNumber.equals(entry.getSerialNumber())) {
                    x509CrlEntry = entry;
                    break;
                }
            }

            if (x509CrlEntry.hasExtensions()) {
                DViewExtensions dViewExtensions = new DViewExtensions(this,
                                                                      res.getString("DViewCrl.EntryExtensions.Title"),
                                                                      x509CrlEntry);
                dViewExtensions.setLocationRelativeTo(this);
                dViewExtensions.setVisible(true);
            }
        }
    }

    private void okPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();

        String crl = "-----BEGIN X509 CRL-----\n" +
                     "MIIBtTCBngIBATANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdzbiB0ZXN0Fw0y\n" +
                     "MzEwMjgxNzA3NTNaFw0yMzExMjcxNzA3NTNaMCcwJQIUSXX6U4SXixlXQ1f2L/sB\n" +
                     "i3dBWaUXDTIzMTAyODE3MDc1OFqgLzAtMB8GA1UdIwQYMBaAFIxZhDgaOqA0MAui\n" +
                     "yg21310lZe5LMAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBCwUAA4IBAQCP86Weka+q\n" +
                     "+RHsqKAh2qswKY6fMkCnKGg6ru0wC7sDWBTxl6+ycgJNrhiTDIWciMR+aPWOz0lC\n" +
                     "ktyU6UwwtFuXUmPSFYtAoqGN5k6yXI5bYwIlQG7eJ5emawxKbvUGwhS1etJA0BCN\n" +
                     "mYwQEYNvoiOmSmbQyhP7sUz6mIPqSwGokHrfCl2hG3xGOjeSN/SbwG5bAGcmWUie\n" +
                     "xKzh538xuGi49tJoIn51u4lZGHytM1KGInCKbs8zqqcJJJIFAc3PgeJv2VdUFJ2O\n" +
                     "vUqtA1loeTXTzHRvjE0PgyfSiIeKRdcvJ4rLvdYz11utUmq9PEICkExWZdR/7CY8\n" +
                     "NnDBrnJ3rf7k\n" +
                     "-----END X509 CRL-----";

        DialogViewer.run(new DViewCrl(new JFrame(), "CRL", X509CertUtil.loadCRL(crl.getBytes())));
    }
}
