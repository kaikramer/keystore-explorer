/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.gui.about;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.kse.gui.JEscDialog;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;

/**
 * A dialog that displays the Java System Properties.
 *
 */
public class DSystemProperties extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/about/resources");

	private JButton jbOK;
	private JPanel jpOK;
	private JPanel jpSystemPropertiesTable;
	private JScrollPane jspSystemPropertiesTable;
	private JKseTable jtSystemProperties;

	/**
	 * Creates new DSystemProperties dialog where the parent is a dialog.
	 *  @param parent
	 *            Parent dialog
	 *
	 */
	public DSystemProperties(JDialog parent) {
		this(parent, res.getString("DSystemProperties.Title"), ModalityType.DOCUMENT_MODAL);
	}

	/**
	 * Creates new DSystemProperties dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The title of the dialog
	 * @param modality
	 *            Dialog modality
	 */
	public DSystemProperties(JDialog parent, String title, Dialog.ModalityType modality) {
		super(parent, title, modality);
		initComponents();
	}

	private void initComponents() {
		SystemPropertiesTableModel spModel = new SystemPropertiesTableModel();
		spModel.load();

		jtSystemProperties = new JKseTable(spModel);

		jtSystemProperties.setRowMargin(0);
		jtSystemProperties.getColumnModel().setColumnMargin(0);
		jtSystemProperties.getTableHeader().setReorderingAllowed(false);
		jtSystemProperties.setAutoResizeMode(JKseTable.AUTO_RESIZE_OFF);

		RowSorter<TableModel> sorter = new TableRowSorter<TableModel>(spModel);
		jtSystemProperties.setRowSorter(sorter);

		for (int i = 0; i < jtSystemProperties.getColumnCount(); i++) {
			TableColumn column = jtSystemProperties.getColumnModel().getColumn(i);

			if (i == 0) {
				column.setPreferredWidth(200);
			} else {
				column.setPreferredWidth(300);
			}

			column.setCellRenderer(new SystemPropertiesTableCellRend());
		}

		jspSystemPropertiesTable = PlatformUtil.createScrollPane(jtSystemProperties,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspSystemPropertiesTable.getViewport().setBackground(jtSystemProperties.getBackground());

		jpSystemPropertiesTable = new JPanel(new BorderLayout(10, 10));
		jpSystemPropertiesTable.setPreferredSize(new Dimension(500, 300));
		jpSystemPropertiesTable.add(jspSystemPropertiesTable, BorderLayout.CENTER);
		jpSystemPropertiesTable.setBorder(new EmptyBorder(5, 5, 5, 5));

		jbOK = new JButton(res.getString("DSystemProperties.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().add(jpSystemPropertiesTable, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		setResizable(false);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				jbOK.requestFocus();
			}
		});
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
