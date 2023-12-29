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

package org.kse.gui.dialogs.sign;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.TableRowSorter;

import org.kse.crypto.CryptoException;
import org.kse.gui.JKseTable;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.KeyStoreTableModel;
import org.kse.gui.PlatformUtil;
import org.kse.gui.preferences.ApplicationSettings;
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
    private KeyStore keyStore;
    private int autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN;
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
        jtListCerts.setColumnsToIconSize(0, 1, 2);
        jtListCerts.colAdjust(keyStoreTableColumns, autoResizeMode);

        jspListCertsTable = PlatformUtil.createScrollPane(jtListCerts, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                          ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspListCertsTable.getViewport().setBackground(jtListCerts.getBackground());

        this.setLayout(new BorderLayout());
        this.setPreferredSize(new Dimension(800, 300));
        this.add(jspListCertsTable, BorderLayout.CENTER);
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

    public X509Certificate getSelectedCert() {
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

    public JKseTable getJtListCerts() {
        return jtListCerts;
    }
}
