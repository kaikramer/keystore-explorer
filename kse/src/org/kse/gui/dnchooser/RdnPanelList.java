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
package org.kse.gui.dnchooser;

import java.awt.Component;
import java.awt.Container;
import java.awt.FocusTraversalPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.kse.crypto.x509.KseX500NameStyle;
import org.kse.utilities.StringUtils;

import net.miginfocom.swing.MigLayout;

/**
 * GUI item for a DN (which is a list of RDNs)
 */
public class RdnPanelList extends JPanel {

    private static final long serialVersionUID = 1L;

    private final List<RdnPanel> entries = new ArrayList<>();

    private boolean editable;

    private static final String[] comboBoxEntries = OidDisplayNameMapping.getDisplayNames();

    public RdnPanelList(X500Name x500Name, boolean editable) {
        setLayout(new MigLayout("insets dialog, flowy", "[right]", "[]rel[]"));
        setFocusCycleRoot(true);

        // we have to reverse RDN order for dialog
        List<RDN> rdnsAsList = Arrays.asList(x500Name.getRDNs());
        Collections.reverse(rdnsAsList);

        for (RDN rdn : rdnsAsList) {
            this.editable = editable;
            for (AttributeTypeAndValue atav : rdn.getTypesAndValues()) {
                String type = OidDisplayNameMapping.getDisplayNameForOid(atav.getType().getId());
                String value = atav.getValue().toString();
                RdnPanel rdnPanel = new RdnPanel(new JComboBox<Object>(comboBoxEntries), type, value, this, editable);
                addItem(rdnPanel);
            }
        }
    }


    public static class RdnFocusTraversalPolicy extends FocusTraversalPolicy {
        List<Component> order;

        public RdnFocusTraversalPolicy(List<Component> order) {
            this.order = new ArrayList<>(order.size());
            this.order.addAll(order);
        }

        public Component getComponentAfter(Container focusCycleRoot, Component aComponent) {
            int idx = (order.indexOf(aComponent) + 1) % order.size();
            return order.get(idx);
        }

        public Component getComponentBefore(Container focusCycleRoot, Component aComponent) {
            int idx = order.indexOf(aComponent) - 1;
            if (idx < 0) {
                idx = order.size() - 1;
            }
            return order.get(idx);
        }

        public Component getDefaultComponent(Container focusCycleRoot) {
            return order.get(0);
        }

        public Component getLastComponent(Container focusCycleRoot) {
            return !order.isEmpty() ? order.get(order.size() - 1) : null;
        }

        public Component getFirstComponent(Container focusCycleRoot) {
            return order.get(0);
        }
    }

    public void cloneEntry(RdnPanel entry) {
        Object selected = entry.getComboBox().getSelectedItem();
        RdnPanel clone = new RdnPanel(new JComboBox<Object>(comboBoxEntries), selected.toString(), "", this, editable);

        addItemAfter(clone, entry);
    }

    private void addItem(RdnPanel entry) {
        entries.add(entry);
        add(entry);
        updateFocusPolicy();
        refresh();
    }

    private void updateFocusPolicy() {
        // set focus order to top-down and column after column
        List<Component> focusOrder = new ArrayList<>();
        for (RdnPanel rdnPanel : entries) {
            JComboBox<?> comboBox = rdnPanel.getComboBox();
            if (comboBox != null) {
                focusOrder.add(comboBox);
            }
        }
        for (RdnPanel rdnPanel : entries) {
            focusOrder.add(rdnPanel.getTextField());
        }
        for (RdnPanel rdnPanel : entries) {
            focusOrder.add(rdnPanel.getPlus());
        }
        for (RdnPanel rdnPanel : entries) {
            focusOrder.add(rdnPanel.getMinus());
        }
        setFocusTraversalPolicy(new RdnFocusTraversalPolicy(focusOrder));
    }

    private void addItemAfter(RdnPanel entryToAdd, RdnPanel afterThisEntry) {
        entries.add(entries.indexOf(afterThisEntry) + 1, entryToAdd);
        removeAll();
        for (RdnPanel entry : entries) {
            add(entry);
        }
        refresh();
    }

    public void removeItem(RdnPanel entry) {
        entries.remove(entry);
        remove(entry);
        updateFocusPolicy();
        refresh();
    }

    public List<RDN> getRdns(boolean noEmptyRdns) {
        List<RDN> rdns = new ArrayList<>();
        for (RdnPanel rdnPanel : entries) {
            ASN1ObjectIdentifier attrType = OidDisplayNameMapping.getOidForDisplayName(rdnPanel.getAttributeName());
            if (noEmptyRdns && StringUtils.trimAndConvertEmptyToNull(rdnPanel.getAttributeValue()) == null) {
                continue;
            }
            ASN1Encodable attrValue = KseX500NameStyle.INSTANCE.stringToValue(attrType, rdnPanel.getAttributeValue());
            rdns.add(new RDN(new AttributeTypeAndValue(attrType, attrValue)));
        }
        return rdns;
    }

    public JTextField getFirstTextField() {
        RdnPanel rdnPanel = entries.get(0);
        if (rdnPanel != null) {
            return rdnPanel.getTextField();
        }
        return new JTextField();
    }

    private void refresh() {
        revalidate();
        repaint(50L);

        if (entries.size() == 1) {
            entries.get(0).enableMinus(false);
        } else {
            for (RdnPanel e : entries) {
                e.enableMinus(true);
            }
        }
    }

}