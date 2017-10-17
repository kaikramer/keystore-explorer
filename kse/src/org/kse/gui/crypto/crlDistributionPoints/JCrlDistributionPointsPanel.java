package org.kse.gui.crypto.crlDistributionPoints;

import java.awt.Container;
import java.util.ArrayList;
import java.util.ResourceBundle;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;

import org.bouncycastle.asn1.x509.DistributionPoint;
import org.kse.gui.JKseTable;
import org.kse.gui.crypto.JAsn1List;

public class JCrlDistributionPointsPanel extends JAsn1List<DistributionPoint> {
	private static final long serialVersionUID = -4833901517557531554L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/crlDistributionPoints/resources");

	private CrlDistributionPointsTableModel jtCrlDistributionPointsTableModel;

	public JCrlDistributionPointsPanel() {
		super("JCrlDistributionPointsPanel", res);
	}
	
	@Override
	protected JKseTable createTable() {
		jtCrlDistributionPointsTableModel = new CrlDistributionPointsTableModel(new ArrayList<DistributionPoint>());
		JKseTable jKseTable = new JKseTable(jtCrlDistributionPointsTableModel);

		for (int i = 0; i < jtCrlDistributionPointsTableModel.getColumnCount(); i++) {
			TableColumn column = jKseTable.getColumnModel().getColumn(i);
			column.setCellRenderer(new CrlDistributionPointsTableCellRend());
		}
		
		jKseTable.setShowGrid(false);
		jKseTable.setRowMargin(0);
		jKseTable.getColumnModel().setColumnMargin(0);
		jKseTable.getTableHeader().setReorderingAllowed(false);
		jKseTable.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jKseTable.setRowHeight(Math.max(18, jKseTable.getRowHeight()));

		ListSelectionModel selectionModel = jKseTable.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					updateButtonControls();
				}
			}
		});
		return jKseTable;
	}
	
	@Override
	public void addPressed() {
		DistributionPoint newDistPoint = editObject(null);

		if (newDistPoint == null) {
			return;
		}

		jtCrlDistributionPointsTableModel.addRow(newDistPoint);

		selectObjectInTable(newDistPoint);
		updateButtonControls();
	}
	
	@Override
	public DistributionPoint editObject(DistributionPoint obj) {
		Container container = getTopLevelAncestor();
		DDistributionPoint dObjectEditor = null;
		String title = res.getString("CrlDistributionPoint.Title");
		
		if (container instanceof JDialog) {
			dObjectEditor = new DDistributionPoint((JDialog) container, title, obj);
			dObjectEditor.setLocationRelativeTo(container);
			dObjectEditor.setVisible(true);
		} else if (container instanceof JFrame) {
			dObjectEditor = new DDistributionPoint((JFrame) container, title, obj);
			dObjectEditor.setLocationRelativeTo(container);
			dObjectEditor.setVisible(true);
		}

		return dObjectEditor.getObject();
	}
}
