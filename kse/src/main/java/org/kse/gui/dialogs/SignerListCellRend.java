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

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JLabel;
import javax.swing.JList;

import org.bouncycastle.cert.X509CertificateHolder;
import org.kse.crypto.signing.KseSignerInformation;

/**
 * Custom cell renderer for the cells of the DViewSignature list.
 */
public class SignerListCellRend extends DefaultListCellRenderer {
    private static final long serialVersionUID = 1L;

    /**
     * Returns the rendered cell for the supplied value.
     *
     * @param list         The JList
     * @param value        The value to assign to the cell
     * @param index        The row index of the cell to render
     * @param isSelected   True if cell is selected
     * @param cellHasFocus If true, render cell appropriately
     * @return The rendered cell
     */
    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected,
            boolean cellHasFocus) {
        JLabel cell = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

        if (value instanceof KseSignerInformation) {

            KseSignerInformation signer = (KseSignerInformation) value;
            X509CertificateHolder cert = signer.getCertificate();

            cell.setText(signer.getShortName());

            // TODO JW Is an icon for signer list cell renderer desired?
//            ImageIcon icon = new ImageIcon(getClass().getResource("images/certificate_node.png"));
//            cell.setIcon(icon);

            String tooltip;
            if (cert != null) {
                tooltip = cert.getSubject().toString();
            } else {
                tooltip = signer.getSID().getIssuer() + " / " + signer.getShortName();
            }

            cell.setToolTipText(tooltip);
        }

        return cell;
    }
}
