package org.kse.gui.crypto.crlDistributionPoints;

import java.awt.Component;
import java.util.BitSet;
import java.util.ResourceBundle;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.kse.crypto.x509.GeneralNameUtil;
import org.kse.gui.dnchooser.RdnPanel;

public class CrlDistributionPointsTableCellRend extends DefaultTableCellRenderer {

	private static final long serialVersionUID = -3628688448979008883L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/crlDistributionPoints/resources");
	
	private static final String[] REASON_OPTIONS_TEXT = {
			res.getString("DDistributionPoints.Reasons.unused"), 
			res.getString("DDistributionPoints.Reasons.keyCompromise"), 
			res.getString("DDistributionPoints.Reasons.cACompromise"), 
			res.getString("DDistributionPoints.Reasons.affiliationChanged"), 
			res.getString("DDistributionPoints.Reasons.superseded"), 
			res.getString("DDistributionPoints.Reasons.cessationOfOperation"), 
			res.getString("DDistributionPoints.Reasons.certificateHold"), 
			res.getString("DDistributionPoints.Reasons.privilegeWithdrawn"), 
			res.getString("DDistributionPoints.Reasons.aACompromise")
		};
	
	private static final int[] REASON_OPTIONS = {
			ReasonFlags.unused, 
			ReasonFlags.keyCompromise, 
			ReasonFlags.cACompromise, 
			ReasonFlags.affiliationChanged, 
			ReasonFlags.superseded, 
			ReasonFlags.cessationOfOperation, 
			ReasonFlags.certificateHold, 
			ReasonFlags.privilegeWithdrawn, 
			ReasonFlags.aACompromise
		};
	
	@Override
	public Component getTableCellRendererComponent(JTable jtAccessDescriptions, Object value, boolean isSelected,
			boolean hasFocus, int row, int col) {
		JLabel cell = (JLabel) super.getTableCellRendererComponent(jtAccessDescriptions, value, isSelected, hasFocus,
				row, col);


		if (col == 0) {
			DistributionPointName distributionPointName = (DistributionPointName) value;
			if (distributionPointName != null) {
				if (distributionPointName.getType() == DistributionPointName.FULL_NAME) {
					GeneralNames distPointName = GeneralNames.getInstance(distributionPointName.getName());
					cell.setText(createGeneralNameCell(distPointName));
				} else if (distributionPointName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER) {
					RDN rdn = RDN.getInstance(distributionPointName.getName());
					cell.setText(RdnPanel.toString(rdn));
				}
			}
		} else if (col == 1) {
			String string = createReasonFlagsText((ReasonFlags) value);
			cell.setText(string);
		} else if (col == 2) {
			GeneralNames crlIssuer = (GeneralNames) value;
			cell.setText(createGeneralNameCell(crlIssuer));
		}

		cell.setHorizontalAlignment(LEFT);
		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}

	private String createReasonFlagsText(ReasonFlags reasonFlags) {
		StringBuilder text = new StringBuilder();
		BitSet flags = BitSet.valueOf(reasonFlags.getOctets());
		for (int i = 0; i < REASON_OPTIONS.length; i++) {
			if (flags.get(i)) {
				text.append(REASON_OPTIONS_TEXT[i]).append(",");
			}
		}
		text.setLength(text.length()-1);
		
		return text.toString();
	}

	protected String createGeneralNameCell(GeneralNames names) {
		StringBuilder builder = new StringBuilder();
		for (GeneralName name : names.getNames()) {
			builder.append(GeneralNameUtil.safeToString(name, false)).append(",");
		}
		if (builder.length() > 0) {
			builder.setLength(builder.length()-1);
		}
		return builder.toString();
	}
}
