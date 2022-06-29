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

package org.kse.gui.dialogs.sign;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ResourceBundle;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.kse.ApplicationSettings;
import org.kse.crypto.CryptoException;
import org.kse.gui.JKseTable;
import org.kse.gui.KeyStoreTableCellRend;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.KeyStoreTableHeadRend;
import org.kse.gui.KeyStoreTableModel;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Component to show the list of certificates of a keystore
 */
public class JListCertificates extends JPanel {

    private static final long serialVersionUID = 1L;
    private JScrollPane jspListCertsTable;
    private JKseTable jtListCerts;
    private ApplicationSettings applicationSettings = ApplicationSettings.getInstance();
    private KeyStoreTableColumns keyStoreTableColumns = new KeyStoreTableColumns();
    private int autoResizeMode = JTable.AUTO_RESIZE_OFF;
    private static final double FF = 0.7; // fudge factor for font size to column size
    private static int iFontSize = (int) (LnfUtil.getDefaultFontSize() * FF);
    private KeyStore keyStore;
    private static final int ICON_SIZE = 28;
    /**
     * Creates a new JListCertificates
     */
    public JListCertificates() {
        super();
        initComponents();
    }

    private void initComponents() {

        keyStoreTableColumns = applicationSettings.getKeyStoreTableColumns();
        KeyStoreTableModel ksModel = new KeyStoreTableModel(keyStoreTableColumns);
        
        jtListCerts = new JKseTable(ksModel);
        RowSorter<KeyStoreTableModel> sorter = new TableRowSorter<>(ksModel);
        jtListCerts.setRowSorter(sorter);

        jtListCerts.setShowGrid(false);
        jtListCerts.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        jtListCerts.getTableHeader().setReorderingAllowed(false);
        jtListCerts.setAutoResizeMode(autoResizeMode);
        jtListCerts.setRowHeight(Math.max(18, jtListCerts.getRowHeight())); // min. height of 18 because of 16x16 icons
        setColumnsToIconSize(jtListCerts, 0, 1, 2);
        colAdjust(jtListCerts);
        
        jspListCertsTable = PlatformUtil.createScrollPane(jtListCerts, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                          ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspListCertsTable.getViewport().setBackground(jtListCerts.getBackground());

        this.setLayout(new BorderLayout(5, 5));
        this.setPreferredSize(new Dimension(800, 300));
        this.add(jspListCertsTable, BorderLayout.CENTER);
        this.setBorder(new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5)));
    }

    public void load(KeyStoreHistory keyStoreHistory) {

        if (keyStoreHistory != null) {
        	keyStore = keyStoreHistory.getCurrentState().getKeyStore();
            KeyStoreTableModel rcModel = (KeyStoreTableModel) jtListCerts.getModel();
            try {
				rcModel.load(keyStoreHistory);
			} catch (GeneralSecurityException | CryptoException e) {
				//ignore
			}
        }
    }

    public String getSelectedEntryAlias() {
        int row = jtListCerts.getSelectedRow();

        if (row == -1) {
            return null;
        }

        return (String) jtListCerts.getValueAt(row, 3);
    }
    
    public X509Certificate getCertSelected() {
        int pos = jtListCerts.getSelectedRow();
        if (pos >= 0) {
        	String alias = getSelectedEntryAlias();
        	try {
				return (X509Certificate) keyStore.getCertificate(alias);
			} catch (KeyStoreException e) {
				//ignore
			}
        }
        return null;
    }
    
    private void setColumnsToIconSize(JTable keyStoreTable, int... columnNumbers) {
        for (int i : columnNumbers) {
            TableColumn typeCol = keyStoreTable.getColumnModel().getColumn(i);
            typeCol.setResizable(false);
            typeCol.setMinWidth(ICON_SIZE);
            typeCol.setMaxWidth(ICON_SIZE);
            typeCol.setPreferredWidth(ICON_SIZE);
        }
    }
    
    private void colAdjust(JTable jtKeyStore) {
        ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");
        jtKeyStore.setAutoResizeMode(autoResizeMode);
        // Add custom renderers for headers and cells
        for (int i = 0; i < jtKeyStore.getColumnCount(); i++) {
            int width = 0;
            TableColumn column = jtKeyStore.getColumnModel().getColumn(i);

            // new, size columns based on title. Columns are resizable by default
            // http://www.java2s.com/Tutorial/Java/0240__Swing/Setcolumnwidthbasedoncellrenderer.htm
            for (int row = 0; row < jtKeyStore.getRowCount(); row++) {
                width = 0;
                TableCellRenderer renderer = jtKeyStore.getCellRenderer(row, i);
                Component comp = renderer.getTableCellRendererComponent(jtKeyStore, jtKeyStore.getValueAt(row, i),
                                                                        false, false, row, i);
                width = Math.max(width, comp.getPreferredSize().width);
            }
            int l = width;

            if (i == keyStoreTableColumns.colEntryName()) {
                column.setMinWidth((2 + res.getString("KeyStoreTableModel.NameColumn")).length() * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.NameColumn").length(), 20) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.NameColumn").length(), 50) * iFontSize);
            }
            if (i == keyStoreTableColumns.colAlgorithm()) {
                column.setMinWidth((4) * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.AlgorithmColumn").length(), 4) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.AlgorithmColumn").length(), 5) * iFontSize);
            }
            if (i == keyStoreTableColumns.colKeySize()) {
                column.setMinWidth((4) * iFontSize);
                column.setPreferredWidth(
                        Math.max(1 + res.getString("KeyStoreTableModel.KeySizeColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.KeySizeColumn").length(), l + 1) * iFontSize);
            }
            if (i == keyStoreTableColumns.colCurve()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.CurveColumn").length(), l) * iFontSize);
                column.setMaxWidth(2 + Math.max("brainpool999r1".length(),
                                                res.getString("KeyStoreTableModel.CurveColumn").length()) * iFontSize);
            }
            if (i == keyStoreTableColumns.colCertificateExpiry()) {
                l = "20.00.2000 00:00:00 MESZ".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        2 + Math.max(res.getString("KeyStoreTableModel.CertExpiryColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colLastModified()) {
                l = "20.09.2000 00:00:00 MESZ".length();
                column.setMinWidth("20.00.2000".length() * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.LastModifiedColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        2 + Math.max(res.getString("KeyStoreTableModel.LastModifiedColumn").length(), l) * iFontSize);
            }
            if (i == keyStoreTableColumns.colAKI()) {
                l = 41;
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        1 + Math.max(res.getString("KeyStoreTableModel.AKIColumn").length(), l) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.AKIColumn").length(), (l + 1)) * iFontSize);
            }
            if (i == keyStoreTableColumns.colSKI()) {
                l = 41;
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.SKIColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.SKIColumn").length(), (l + 1)) * iFontSize);
            }
            if (i == keyStoreTableColumns.colIssuerCN()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.IssuerCNColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(100 * iFontSize);
            }
            if (i == keyStoreTableColumns.colIssuerDN()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.IssuerDNColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(100 * iFontSize);
            }
            if (i == keyStoreTableColumns.colIssuerO()) {
                column.setMinWidth(8 * iFontSize);
                column.setPreferredWidth(
                        Math.max(2 + res.getString("KeyStoreTableModel.IssuerOColumn").length(), (l + 1)) * iFontSize);
                column.setMaxWidth(100 * iFontSize);
            }
            column.setHeaderRenderer(
                    new KeyStoreTableHeadRend(jtKeyStore.getTableHeader().getDefaultRenderer(), keyStoreTableColumns));
            column.setCellRenderer(new KeyStoreTableCellRend());
        }
    }
}
