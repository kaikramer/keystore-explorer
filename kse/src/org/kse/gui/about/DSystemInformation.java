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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * A dialog which displays general system information: OS, Locale, Java version,
 * Java vendor, Java vendor URL, JVM total memory and JVM free memory.
 *
 */
public class DSystemInformation extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/about/resources");

	private static final int TEXT_FIELD_WIDTH = 30;

	private JPanel jpSystemInformation;
	private JLabel jlHostname;
	private JTextField jtfHostname;
	private JLabel jlOperatingSystem;
	private JTextField jtfOperatingSystem;
	private JLabel jlLocale;
	private JTextField jtfLocale;
	private JLabel jlJavaVersion;
	private JTextField jtfJavaVersion;
	private JLabel jlJavaVendor;
	private JTextField jtfJavaVendor;
	private JLabel jlJavaHome;
	private JTextField jtfJavaHome;
	private JLabel jlJvmMaximumMemory;
	private JTextField jtfJvmMaximumMemory;
	private JLabel jlJvmTotalMemory;
	private JTextField jtfJvmTotalMemory;
	private JLabel jlJvmFreeMemory;
	private JTextField jtfJvmFreeMemory;
	private JLabel jlAvailableProcessors;
	private JTextField jtfAvailableProcessors;
	private JPanel jpButtons;
	private JButton jbEnvironmentVariables;
	private JButton jbSystemProperties;
	private JPanel jpOK;
	private JButton jbOK;

	private Thread memoryUpdater;

	/**
	 * Creates new DSystemInformation dialog where the parent is a frame.
	 *  @param parent
	 *            Parent dialog
	 *
	 */
	public DSystemInformation(JFrame parent) {
		super(parent, res.getString("DSystemInformation.Title"), ModalityType.DOCUMENT_MODAL);
		initComponents();
	}

	/**
	 * Creates new DSystemInformation dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The title of the dialog
	 * @param modality
	 *            Dialog modality
	 */
	public DSystemInformation(JDialog parent, String title, Dialog.ModalityType modality) {
		super(parent, title, modality);
		initComponents();
	}

	private void initComponents() {
		getContentPane().setLayout(new BorderLayout());

		Properties sysProps = java.lang.System.getProperties();
		Runtime runtime = Runtime.getRuntime();

		GridBagConstraints gbcLabel = new GridBagConstraints();
		gbcLabel.gridx = 0;
		gbcLabel.gridwidth = 3;
		gbcLabel.gridheight = 1;
		gbcLabel.insets = new Insets(5, 5, 5, 5);
		gbcLabel.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcTextField = new GridBagConstraints();
		gbcTextField.gridx = 3;
		gbcTextField.gridwidth = 3;
		gbcTextField.gridheight = 1;
		gbcTextField.insets = new Insets(5, 5, 5, 5);
		gbcTextField.anchor = GridBagConstraints.WEST;

		jpSystemInformation = new JPanel(new GridBagLayout());
		jpSystemInformation.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		String hostname = null;

		try {
			InetAddress localAddr = InetAddress.getLocalHost();

			String host = localAddr.getCanonicalHostName();
			String address = localAddr.getHostAddress();

			if (host.equals(address)) {
				hostname = address;
			} else {
				hostname = MessageFormat.format(res.getString("DSystemInformation.jtfHostname.text"), host, address);
			}
		} catch (UnknownHostException e) {
			hostname = res.getString("DSystemInformation.jtfHostname.unknown.text");
		}

		jlHostname = new JLabel(res.getString("DSystemInformation.jlHostname.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlHostname = (GridBagConstraints) gbcLabel.clone();
		gbc_jlHostname.gridy = 0;
		jpSystemInformation.add(jlHostname, gbc_jlHostname);

		jtfHostname = new JTextField(hostname, TEXT_FIELD_WIDTH);
		jtfHostname.setEditable(false);
		jtfHostname.setCaretPosition(0);

		GridBagConstraints gbc_jtfHostname = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfHostname.gridy = 0;
		jpSystemInformation.add(jtfHostname, gbc_jtfHostname);

		jlOperatingSystem = new JLabel(res.getString("DSystemInformation.jlOperatingSystem.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlOperatingSystem = (GridBagConstraints) gbcLabel.clone();
		gbc_jlOperatingSystem.gridy = 1;
		jpSystemInformation.add(jlOperatingSystem, gbc_jlOperatingSystem);

		jtfOperatingSystem = new JTextField(MessageFormat.format(
				res.getString("DSystemInformation.jtfOperatingSystem.text"), sysProps.getProperty("os.name", ""),
				sysProps.getProperty("os.version", ""), sysProps.getProperty("os.arch", "")), TEXT_FIELD_WIDTH);
		jtfOperatingSystem.setEditable(false);
		jtfOperatingSystem.setCaretPosition(0);

		GridBagConstraints gbc_jtfOperatingSystem = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfOperatingSystem.gridy = 1;
		jpSystemInformation.add(jtfOperatingSystem, gbc_jtfOperatingSystem);

		jlLocale = new JLabel(res.getString("DSystemInformation.jlLocale.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlLocale = (GridBagConstraints) gbcLabel.clone();
		gbc_jlLocale.gridy = 2;
		jpSystemInformation.add(jlLocale, gbc_jlLocale);

		jtfLocale = new JTextField(Locale.getDefault().getDisplayName(), TEXT_FIELD_WIDTH);
		jtfLocale.setEditable(false);
		jtfLocale.setCaretPosition(0);

		GridBagConstraints gbc_jtfLocale = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfLocale.gridy = 2;
		jpSystemInformation.add(jtfLocale, gbc_jtfLocale);

		jlJavaVersion = new JLabel(res.getString("DSystemInformation.jlJavaVersion.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlJavaVersion = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJavaVersion.gridy = 3;
		jpSystemInformation.add(jlJavaVersion, gbc_jlJavaVersion);

		jtfJavaVersion = new JTextField(sysProps.getProperty("java.version", ""), TEXT_FIELD_WIDTH);
		jtfJavaVersion.setEditable(false);
		jtfJavaVersion.setCaretPosition(0);

		GridBagConstraints gbc_jtfJavaVersion = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJavaVersion.gridy = 3;
		jpSystemInformation.add(jtfJavaVersion, gbc_jtfJavaVersion);

		jlJavaVendor = new JLabel(res.getString("DSystemInformation.jlJavaVendor.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlJavaVendor = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJavaVendor.gridy = 4;
		jpSystemInformation.add(jlJavaVendor, gbc_jlJavaVendor);

		jtfJavaVendor = new JTextField(MessageFormat.format(res.getString("DSystemInformation.jtfJavaVendor.text"),
				sysProps.getProperty("java.vendor", ""), sysProps.getProperty("java.vendor.url", "")), TEXT_FIELD_WIDTH);
		jtfJavaVendor.setEditable(false);
		jtfJavaVendor.setCaretPosition(0);

		GridBagConstraints gbc_jtfJavaVendor = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJavaVendor.gridy = 4;
		jpSystemInformation.add(jtfJavaVendor, gbc_jtfJavaVendor);

		jlJavaHome = new JLabel(res.getString("DSystemInformation.jlJavaHome.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlJavaHome = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJavaHome.gridy = 5;
		jpSystemInformation.add(jlJavaHome, gbc_jlJavaHome);

		jtfJavaHome = new JTextField(sysProps.getProperty("java.home", ""), TEXT_FIELD_WIDTH);
		jtfJavaHome.setEditable(false);
		jtfJavaHome.setCaretPosition(0);

		GridBagConstraints gbc_jtfJavaHome = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJavaHome.gridy = 5;
		jpSystemInformation.add(jtfJavaHome, gbc_jtfJavaHome);

		jlJvmMaximumMemory = new JLabel(res.getString("DSystemInformation.jlJvmMaximumMemory.text"),
				SwingConstants.RIGHT);

		GridBagConstraints gbc_jlJvmMaximumMemory = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJvmMaximumMemory.gridy = 6;
		jpSystemInformation.add(jlJvmMaximumMemory, gbc_jlJvmMaximumMemory);

		jtfJvmMaximumMemory = new JTextField(TEXT_FIELD_WIDTH);
		jtfJvmMaximumMemory.setEditable(false);

		GridBagConstraints gbc_jtfJvmMaximumMemory = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJvmMaximumMemory.gridy = 6;
		jpSystemInformation.add(jtfJvmMaximumMemory, gbc_jtfJvmMaximumMemory);

		jlJvmTotalMemory = new JLabel(res.getString("DSystemInformation.jlJvmTotalMemory.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlJvmTotalMemory = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJvmTotalMemory.gridy = 7;
		jpSystemInformation.add(jlJvmTotalMemory, gbc_jlJvmTotalMemory);

		jtfJvmTotalMemory = new JTextField(TEXT_FIELD_WIDTH);
		jtfJvmTotalMemory.setEditable(false);

		GridBagConstraints gbc_jtfJvmTotalMemory = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJvmTotalMemory.gridy = 7;
		jpSystemInformation.add(jtfJvmTotalMemory, gbc_jtfJvmTotalMemory);

		jlJvmFreeMemory = new JLabel(res.getString("DSystemInformation.jlJvmFreeMemory.text"), SwingConstants.RIGHT);

		GridBagConstraints gbc_jlJvmFreeMemory = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJvmFreeMemory.gridy = 8;
		jpSystemInformation.add(jlJvmFreeMemory, gbc_jlJvmFreeMemory);

		jtfJvmFreeMemory = new JTextField(TEXT_FIELD_WIDTH);
		jtfJvmFreeMemory.setEditable(false);

		GridBagConstraints gbc_jtfJvmFreeMemory = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJvmFreeMemory.gridy = 8;
		jpSystemInformation.add(jtfJvmFreeMemory, gbc_jtfJvmFreeMemory);

		jlAvailableProcessors = new JLabel(res.getString("DSystemInformation.jlAvailableProcessors.text"),
				SwingConstants.RIGHT);

		GridBagConstraints gbc_jlAvailableProcessors = (GridBagConstraints) gbcLabel.clone();
		gbc_jlAvailableProcessors.gridy = 9;
		jpSystemInformation.add(jlAvailableProcessors, gbc_jlAvailableProcessors);

		jtfAvailableProcessors = new JTextField("" + runtime.availableProcessors(), TEXT_FIELD_WIDTH);
		jtfAvailableProcessors.setEditable(false);
		jtfAvailableProcessors.setCaretPosition(0);

		GridBagConstraints gbc_jtfAvailableProcessors = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfAvailableProcessors.gridy = 9;
		jpSystemInformation.add(jtfAvailableProcessors, gbc_jtfAvailableProcessors);

		jbEnvironmentVariables = new JButton(res.getString("DSystemInformation.jbEnvironmentVariables.text"));
		PlatformUtil.setMnemonic(jbEnvironmentVariables,
				res.getString("DSystemInformation.jbEnvironmentVariables.mnemonic").charAt(0));
		jbEnvironmentVariables.setToolTipText(res.getString("DSystemInformation.jbEnvironmentVariables.tooltip"));
		jbEnvironmentVariables.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSystemInformation.this);
					environmentVariablesPressed();
				} finally {
					CursorUtil.setCursorFree(DSystemInformation.this);
				}
			}
		});

		jbSystemProperties = new JButton(res.getString("DSystemInformation.jbSystemProperties.text"));
		PlatformUtil.setMnemonic(jbSystemProperties, res.getString("DSystemInformation.jbSystemProperties.mnemonic")
				.charAt(0));
		jbSystemProperties.setToolTipText(res.getString("DSystemInformation.jbSystemProperties.tooltip"));
		jbSystemProperties.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DSystemInformation.this);
					systemPropertiesPressed();
				} finally {
					CursorUtil.setCursorFree(DSystemInformation.this);
				}
			}
		});

		jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

		jpButtons.add(jbEnvironmentVariables);
		jpButtons.add(jbSystemProperties);

		GridBagConstraints gbc_jpButtons = new GridBagConstraints();
		gbc_jpButtons.gridx = 0;
		gbc_jpButtons.gridy = 10;
		gbc_jpButtons.gridwidth = 6;
		gbc_jpButtons.gridheight = 1;
		gbc_jpButtons.anchor = GridBagConstraints.EAST;

		jpSystemInformation.add(jpButtons, gbc_jpButtons);

		jbOK = new JButton(res.getString("DSystemInformation.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().add(jpSystemInformation, BorderLayout.CENTER);
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

		startMemoryUpdater();
	}

	private void startMemoryUpdater() {
		memoryUpdater = new Thread(new UpdateMemoryFields());
		memoryUpdater.setPriority(Thread.MIN_PRIORITY);
		memoryUpdater.start();
	}

	private void stopMemoryUpdater() {
		if (memoryUpdater != null && memoryUpdater.isAlive()) {
			memoryUpdater.interrupt();
		}
	}

	private void systemPropertiesPressed() {
		DSystemProperties dSystemProperties = new DSystemProperties(this);
		dSystemProperties.setResizable(true);
		dSystemProperties.setLocationRelativeTo(this);
		dSystemProperties.setVisible(true);
	}

	private void environmentVariablesPressed() {
		DEnvironmentVariables dEnvironmentVariables = new DEnvironmentVariables(this);
		dEnvironmentVariables.setResizable(true);
		dEnvironmentVariables.setLocationRelativeTo(this);
		dEnvironmentVariables.setVisible(true);
	}

	private void updateMemoryFields(Runtime runtime) {
		jtfJvmMaximumMemory.setText(MessageFormat.format(res.getString("DSystemInformation.jtfJvmMaximumMemory.text"),
				Math.round(runtime.maxMemory() / 1024)));
		jtfJvmMaximumMemory.setCaretPosition(0);

		jtfJvmTotalMemory.setText(MessageFormat.format(res.getString("DSystemInformation.jtfJvmTotalMemory.text"),
				Math.round(runtime.totalMemory() / 1024)));
		jtfJvmTotalMemory.setCaretPosition(0);

		jtfJvmFreeMemory.setText(MessageFormat.format(res.getString("DSystemInformation.jtfJvmFreeMemory.text"),
				Math.round(runtime.freeMemory() / 1024)));
		jtfJvmFreeMemory.setCaretPosition(0);
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		stopMemoryUpdater();

		setVisible(false);
		dispose();
	}

	private class UpdateMemoryFields implements Runnable {
		@Override
		public void run() {
			for (;;) {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {

						Runtime runtime = Runtime.getRuntime();

						updateMemoryFields(runtime);
					}
				});

				try {
					Thread.sleep(1000);
				} catch (InterruptedException ex) {
				}
			}
		}
	}
}
