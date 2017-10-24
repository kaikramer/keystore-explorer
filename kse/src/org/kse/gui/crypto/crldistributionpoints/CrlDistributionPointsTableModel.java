package org.kse.gui.crypto.crldistributionpoints;

import java.util.List;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.kse.gui.crypto.GeneralTableModel;

public class CrlDistributionPointsTableModel extends GeneralTableModel<DistributionPoint> {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/crldistributionpoints/resources");
	
	public CrlDistributionPointsTableModel(List<DistributionPoint> data) {
		super(data, res.getString("CrlDistributionPointsTableModel.DistributionPoint"), res.getString("CrlDistributionPointsTableModel.Reasons"), res.getString("CrlDistributionPointsTableModel.CrlIssuer"));
	}
	
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		DistributionPoint rowValue = getRow(rowIndex);
		switch (columnIndex) {
		case 0: return rowValue.getDistributionPoint();
		case 1: return rowValue.getReasons();
		case 2: return rowValue.getCRLIssuer();
		default:
			return null;
		}
	}
	
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
		case 0: return DistributionPointName.class;
		case 1: return ReasonFlags.class;
		case 2: return GeneralNames.class;
		default:
			return null;
		}
	}
}
