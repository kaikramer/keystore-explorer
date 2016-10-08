/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package net.sf.keystore_explorer.gui.dnchooser;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JPanel;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

import net.miginfocom.swing.MigLayout;
import net.sf.keystore_explorer.crypto.x509.KseX500NameStyle;
import net.sf.keystore_explorer.utilities.StringUtils;

public class RdnPanelList extends JPanel {

	private static final long serialVersionUID = 1L;

	private List<RdnPanel> entries = new ArrayList<RdnPanel>();

	private boolean editable;

	private static final String[] comboBoxEntries = OidDisplayNameMapping.getDisplayNames();

	public RdnPanelList(X500Name x500Name, boolean editable) {
		setLayout(new MigLayout("insets dialog, flowy", "[right]", "[]rel[]"));

		for (RDN rdn : x500Name.getRDNs()) {
			this.editable = editable;
			for (AttributeTypeAndValue atav : rdn.getTypesAndValues()) {
				String type = OidDisplayNameMapping.getDisplayNameForOid(atav.getType().getId());
				String value = atav.getValue().toString();
				addItem(new RdnPanel(new JComboBox<Object>(comboBoxEntries), type, value, this, editable));
			}
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
		refresh();
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
		refresh();
	}

	public List<RDN> getRdns(boolean noEmptyRdns) {
		List<RDN> rdns = new ArrayList<RDN>();
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