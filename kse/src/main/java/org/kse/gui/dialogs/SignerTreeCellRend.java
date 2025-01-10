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

import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;

import org.bouncycastle.cert.X509CertificateHolder;
import org.kse.crypto.signing.KseSignerInformation;

/**
 * Custom cell renderer for the cells of the DViewSignature list.
 */
public class SignerTreeCellRend extends DefaultTreeCellRenderer {
    private static final long serialVersionUID = 1L;

    /**
     * Returns the rendered cell for the supplied value.
     *
     * @param jtrHSigners  The JTree
     * @param value        The value to assign to the cell
     * @param isSelected   True if cell is selected
     * @param isExpanded   True if cell is expanded
     * @param leaf         True if cell is a leaf
     * @param row          The row of the cell to render
     * @param hasFocus     If true, render cell appropriately
     * @return The rendered cell
     */
    @Override
    public Component getTreeCellRendererComponent(JTree jtrHSigners, Object value, boolean isSelected,
                                                  boolean isExpanded, boolean leaf, int row, boolean hasFocus) {
        JLabel cell = (JLabel) super.getTreeCellRendererComponent(jtrHSigners, value, isSelected, isExpanded, leaf,
                                                                  row, hasFocus);

        DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) value;

        Object userObject = treeNode.getUserObject();

        if (userObject instanceof KseSignerInformation) {

            KseSignerInformation signer = (KseSignerInformation) userObject;
            X509CertificateHolder cert = signer.getCertificate();

            cell.setText(signer.getShortName());

            // TODO JW Is an icon for signer tree cell renderer desired?
//            String iconResource;
//            if (signer.isCounterSignature()) {
//                iconResource = "images/counter_signature_node.png";
//            } else {
//                iconResource = "images/signature_node.png";
//            }
//            ImageIcon icon = new ImageIcon(getClass().getResource(iconResource));
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
