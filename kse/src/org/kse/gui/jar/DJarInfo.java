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
package org.kse.gui.jar;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import javax.swing.JButton;
import javax.swing.JFrame;
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
 * A dialog that displays information about the JAR files on the classpath.
 *
 */
public class DJarInfo extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/jar/resources");

	private JButton jbOK;
	private JPanel jpOK;
	private JPanel jpJarInfoTable;
	private JScrollPane jspJarInfoTable;
	private JKseTable jtJarInfo;

	/**
	 * Creates new DJarInfo dialog where the parent is a frame.
	 *
	 * @param parent
	 *            Parent frame
	 * @throws IOException
	 *             Problem occurred getting JAR information
	 */
	public DJarInfo(JFrame parent) throws IOException {
		this(parent, res.getString("DJarInfo.Title"), ModalityType.DOCUMENT_MODAL);
	}

	/**
	 * Creates new DJarInfo dialog where the parent is a frame.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The title of the dialog
	 * @param modality
	 *            Dialog modality
	 * @throws IOException
	 *             Problem occurred getting JAR information
	 */
	public DJarInfo(JFrame parent, String title, Dialog.ModalityType modality) throws IOException {
		super(parent, title, modality);
		initComponents();
	}

	private void initComponents() throws IOException {
		JarFile[] jarFiles = getClassPathJars();

		JarInfoTableModel jiModel = new JarInfoTableModel();
		jiModel.load(jarFiles);

		jtJarInfo = new JKseTable(jiModel);

		jtJarInfo.setRowMargin(0);
		jtJarInfo.getColumnModel().setColumnMargin(0);
		jtJarInfo.getTableHeader().setReorderingAllowed(false);
		jtJarInfo.setAutoResizeMode(JKseTable.AUTO_RESIZE_OFF);

		RowSorter<TableModel> sorter = new TableRowSorter<TableModel>(jiModel);
		jtJarInfo.setRowSorter(sorter);

		for (int i = 0; i < jtJarInfo.getColumnCount(); i++) {
			TableColumn column = jtJarInfo.getColumnModel().getColumn(i);

			column.setPreferredWidth(150);
			column.setCellRenderer(new JarInfoTableCellRend());
		}

		jspJarInfoTable = PlatformUtil.createScrollPane(jtJarInfo, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspJarInfoTable.getViewport().setBackground(jtJarInfo.getBackground());

		jpJarInfoTable = new JPanel(new BorderLayout(10, 10));
		jpJarInfoTable.setPreferredSize(new Dimension(500, 200));
		jpJarInfoTable.add(jspJarInfoTable, BorderLayout.CENTER);
		jpJarInfoTable.setBorder(new EmptyBorder(5, 5, 5, 5));

		jbOK = new JButton(res.getString("DJarInfo.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, true);

		getContentPane().add(jpJarInfoTable, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		setResizable(true);

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

	private JarFile[] getClassPathJars() throws IOException {
		Vector<JarFile> jars = new Vector<JarFile>();

		String classPath = System.getProperty("java.class.path");
		String pathSeparator = System.getProperty("path.separator");

		StringTokenizer strTok = new StringTokenizer(classPath, pathSeparator);

		while (strTok.hasMoreTokens()) {
			String classPathEntry = strTok.nextToken();

			File file = new File(classPathEntry);

			if (isJarFile(file)) {
				jars.add(new JarFile(file));
			}
		}

		/*
		 * If only one JAR was found assume that application was started using
		 * "jar" option - look in JAR manifest's Class-Path entry for the rest
		 * of the JARs
		 */
		if (jars.size() == 1) {
			JarFile jarFile = jars.get(0);
			Manifest manifest = jarFile.getManifest();

			if (manifest != null) {
				Attributes attributes = manifest.getMainAttributes();
				String jarClassPath = attributes.getValue("Class-Path");

				if (jarClassPath != null) {
					strTok = new StringTokenizer(jarClassPath, " ");

					while (strTok.hasMoreTokens()) {
						String jarClassPathEntry = strTok.nextToken();

						File file = new File(new File(jarFile.getName()).getParent(), jarClassPathEntry);

						if (isJarFile(file)) {
							jars.add(new JarFile(file));
						}
					}
				}
			}
		}

		return jars.toArray(new JarFile[jars.size()]);
	}

	private boolean isJarFile(File file) {
		if (file.isFile()) {
			String name = file.getName();

			if ((name.endsWith(".jar")) || (name.endsWith(".JAR")) || (name.endsWith(".zip"))
					|| (name.endsWith(".ZIP"))) // Consider
				// zips
				// to
				// be
				// jars
			{
				return true;
			}
		}

		return false;
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
