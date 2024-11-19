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
import java.util.Collection;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JLabel;
import javax.swing.JList;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.utilities.StringUtils;

/**
 * Custom cell renderer for the cells of the DViewSignature list.
 */
public class SignerListCellRend extends DefaultListCellRenderer {
    private static final long serialVersionUID = 1L;
    private CMSSignedData signedData;

    public SignerListCellRend(CMSSignedData signedData) {
        this.signedData = signedData;
    }

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

        if (value instanceof SignerInformation) {
            SignerInformation signer = (SignerInformation) value;
            // TODO JW Need to move cert lookup to a utility class.
            X509CertificateHolder cert = null;
            Collection<X509CertificateHolder> matchedCerts = signedData.getCertificates().getMatches(signer.getSID());
            if (!matchedCerts.isEmpty()) {
                cert = matchedCerts.iterator().next();
            }

            if (cert == null) {
                // TODO JW - what type of error handling
            }

            X500Name subject = cert.getSubject();

            String shortName = X500NameUtils.extractCN(subject);

            if (StringUtils.isBlank(shortName)) {
                shortName = subject.toString();
            }

            // subject DN can be empty in some cases
            if (StringUtils.isBlank(shortName)) {
                shortName = cert.getSerialNumber().toString();
            }

            cell.setText(shortName);

            // TODO JW - need icon for signer list cell renderer
//            ImageIcon icon = new ImageIcon(getClass().getResource("images/certificate_node.png"));
//            cell.setIcon(icon);

            cell.setToolTipText(subject.toString());
        }

        return cell;
    }
}
