/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.TreeMap;

import org.kse.gui.dialogs.sign.RevokedEntry;
import org.kse.gui.table.ToolTipTableModel;

/**
 * The table model used to display an array of X.509 CRL entries sorted by
 * serial number.
 */
public class RevokedCertsTableModel extends ToolTipTableModel {
    private static final long serialVersionUID = 1L;

    static final int COL_SERIAL_NUMBER = 0;
    static final int COL_REVOCATION_DATE = 1;
    static final int COL_REASON = 2;
    private static final int COLUMN_COUNT = 3;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");
    private static ResourceBundle resCryptoX509 = ResourceBundle.getBundle("org/kse/crypto/x509/resources");

    private static final String[] COLUMN_TOOL_TIPS = { //
            "RevokedCertsTableModel.SerialNumberColumn.tooltip", //
            "RevokedCertsTableModel.RevocationDateColumn.tooltip", //
            "RevokedCertsTableModel.ReasonColumn.tooltip" //
    };

    private String[] columnNames;
    private Object[][] data;

    /**
     * Construct a new RevokedCertsTableModel.
     */
    public RevokedCertsTableModel() {
        super(res, COLUMN_TOOL_TIPS);
        columnNames = new String[COLUMN_COUNT];
        columnNames[COL_SERIAL_NUMBER] = res.getString("RevokedCertsTableModel.SerialNumberColumn");
        columnNames[COL_REVOCATION_DATE] = res.getString("RevokedCertsTableModel.RevocationDateColumn");
        columnNames[COL_REASON] = res.getString("RevokedCertsTableModel.ReasonColumn");

        data = new Object[0][0];
    }

    /**
     * Load the RevokedCertsTableModel with an array of X.509 CRL entries.
     *
     * @param revokedCerts The X.509 CRL entries
     */
    public void load(X509CRLEntry[] revokedCerts) {
        TreeMap<BigInteger, X509CRLEntry> sortedRevokedCerts = new TreeMap<>();

        for (X509CRLEntry revokedCert : revokedCerts) {
            sortedRevokedCerts.put(revokedCert.getSerialNumber(), revokedCert);
        }

        data = new Object[sortedRevokedCerts.size()][COLUMN_COUNT];

        int i = 0;
        for (Iterator<?> itr = sortedRevokedCerts.entrySet().iterator(); itr.hasNext(); i++) {
            X509CRLEntry x509CrlEntry = (X509CRLEntry) ((Map.Entry<?, ?>) itr.next()).getValue();

            data[i][COL_SERIAL_NUMBER] = x509CrlEntry.getSerialNumber();
            data[i][COL_REVOCATION_DATE] = x509CrlEntry.getRevocationDate();
            data[i][COL_REASON] = getReasonString(x509CrlEntry.getRevocationReason());
        }

        fireTableDataChanged();
    }

    /**
     * Load the RevokedCertsTableModel with a map of RevokedEntry.
     *
     * @param mapRevokedEntry The X.509 CRL entries
     */
    public void load(Map<BigInteger, RevokedEntry> mapRevokedEntry) {
        data = new Object[mapRevokedEntry.size()][COLUMN_COUNT];

        int i = 0;
        for (Map.Entry<BigInteger, RevokedEntry> pair : mapRevokedEntry.entrySet()) {
            RevokedEntry entry = pair.getValue();
            data[i][COL_SERIAL_NUMBER] = entry.getUserCertificateSerial();
            data[i][COL_REVOCATION_DATE] = entry.getRevocationDate();
            data[i][COL_REASON] = getReasonString(entry.getReason());
            i++;
        }
        fireTableDataChanged();
    }

    private String getReasonString(CRLReason reason) {
        String reasonString = "";
        if (reason != null) {
            final String text = resCryptoX509.getString("CrlReason." + reason.ordinal() + ".text");
            reasonString = MessageFormat.format(resCryptoX509.getString("CrlReason.format.column"), text, reason.ordinal());
        }
        return reasonString;
    }

    /**
     * Get the number of columns in the table.
     *
     * @return The number of columns
     */
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * Get the number of rows in the table.
     *
     * @return The number of rows
     */
    @Override
    public int getRowCount() {
        return data.length;
    }

    /**
     * Get the name of the column at the given position.
     *
     * @param col The column position
     * @return The column name
     */
    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    /**
     * Get the cell value at the given row and column position.
     *
     * @param row The row position
     * @param col The column position
     * @return The cell value
     */
    @Override
    public Object getValueAt(int row, int col) {
        return data[row][col];
    }

    /**
     * Get the class at of the cells at the given column position.
     *
     * @param col The column position
     * @return The column cells' class
     */
    @Override
    public Class<?> getColumnClass(int col) {
        switch (col) {
            case COL_SERIAL_NUMBER:
                return BigInteger.class;
            case COL_REVOCATION_DATE:
                return Date.class;
            case COL_REASON:
                return String.class;
        }
        throw new IndexOutOfBoundsException(String.valueOf(col));
    }

    /**
     * Is the cell at the given row and column position editable?
     *
     * @param row The row position
     * @param col The column position
     * @return True if the cell is editable, false otherwise
     */
    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }
}
