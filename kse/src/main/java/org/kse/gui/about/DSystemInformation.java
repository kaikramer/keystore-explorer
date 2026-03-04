/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
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
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.gui.CursorUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.net.IpAddress;

import net.miginfocom.swing.MigLayout;

/**
 * A dialog which displays general system information: OS, Locale, Java version,
 * Java vendor, Java vendor URL, JVM total memory and JVM free memory.
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
    private JButton jbEnvironmentVariables;
    private JButton jbSystemProperties;
    private JButton jbOK;

    private Thread memoryUpdater;

    /**
     * Creates new DSystemInformation dialog where the parent is a frame.
     *
     * @param parent Parent dialog
     */
    public DSystemInformation(JFrame parent) {
        super(parent, res.getString("DSystemInformation.Title"), ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    /**
     * Creates new DSystemInformation dialog where the parent is a dialog.
     *
     * @param parent   Parent dialog
     * @param title    The title of the dialog
     * @param modality Dialog modality
     */
    public DSystemInformation(JDialog parent, String title, Dialog.ModalityType modality) {
        super(parent, title, modality);
        initComponents();
    }

    private void initComponents() {
        Properties sysProps = java.lang.System.getProperties();
        Runtime runtime = Runtime.getRuntime();

        jlHostname = new JLabel(res.getString("DSystemInformation.jlHostname.text"));
        jtfHostname = new JTextField(getHostname(), TEXT_FIELD_WIDTH);
        jtfHostname.setEditable(false);
        jtfHostname.setCaretPosition(0);

        jlOperatingSystem = new JLabel(res.getString("DSystemInformation.jlOperatingSystem.text"));
        jtfOperatingSystem = new JTextField(
                MessageFormat.format(res.getString("DSystemInformation.jtfOperatingSystem.text"),
                                     sysProps.getProperty("os.name", ""), sysProps.getProperty("os.version", ""),
                                     sysProps.getProperty("os.arch", "")), TEXT_FIELD_WIDTH);
        jtfOperatingSystem.setEditable(false);
        jtfOperatingSystem.setCaretPosition(0);

        jlLocale = new JLabel(res.getString("DSystemInformation.jlLocale.text"));
        jtfLocale = new JTextField(Locale.getDefault().getDisplayName(), TEXT_FIELD_WIDTH);
        jtfLocale.setEditable(false);
        jtfLocale.setCaretPosition(0);

        jlJavaVersion = new JLabel(res.getString("DSystemInformation.jlJavaVersion.text"));
        jtfJavaVersion = new JTextField(sysProps.getProperty("java.version", ""), TEXT_FIELD_WIDTH);
        jtfJavaVersion.setEditable(false);
        jtfJavaVersion.setCaretPosition(0);

        jlJavaVendor = new JLabel(res.getString("DSystemInformation.jlJavaVendor.text"));
        jtfJavaVendor = new JTextField(MessageFormat.format(res.getString("DSystemInformation.jtfJavaVendor.text"),
                                                            sysProps.getProperty("java.vendor", ""),
                                                            sysProps.getProperty("java.vendor.url", "")),
                                       TEXT_FIELD_WIDTH);
        jtfJavaVendor.setEditable(false);
        jtfJavaVendor.setCaretPosition(0);

        jlJavaHome = new JLabel(res.getString("DSystemInformation.jlJavaHome.text"));
        jtfJavaHome = new JTextField(sysProps.getProperty("java.home", ""), TEXT_FIELD_WIDTH);
        jtfJavaHome.setEditable(false);
        jtfJavaHome.setCaretPosition(0);

        jlJvmMaximumMemory = new JLabel(res.getString("DSystemInformation.jlJvmMaximumMemory.text"));
        jtfJvmMaximumMemory = new JTextField(TEXT_FIELD_WIDTH);
        jtfJvmMaximumMemory.setEditable(false);

        jlJvmTotalMemory = new JLabel(res.getString("DSystemInformation.jlJvmTotalMemory.text"));
        jtfJvmTotalMemory = new JTextField(TEXT_FIELD_WIDTH);
        jtfJvmTotalMemory.setEditable(false);

        jlJvmFreeMemory = new JLabel(res.getString("DSystemInformation.jlJvmFreeMemory.text"));
        jtfJvmFreeMemory = new JTextField(TEXT_FIELD_WIDTH);
        jtfJvmFreeMemory.setEditable(false);

        jlAvailableProcessors = new JLabel(res.getString("DSystemInformation.jlAvailableProcessors.text"));
        jtfAvailableProcessors = new JTextField("" + runtime.availableProcessors(), TEXT_FIELD_WIDTH);
        jtfAvailableProcessors.setEditable(false);
        jtfAvailableProcessors.setCaretPosition(0);

        jbEnvironmentVariables = new JButton(res.getString("DSystemInformation.jbEnvironmentVariables.text"));
        PlatformUtil.setMnemonic(jbEnvironmentVariables,
                                 res.getString("DSystemInformation.jbEnvironmentVariables.mnemonic").charAt(0));
        jbEnvironmentVariables.setToolTipText(res.getString("DSystemInformation.jbEnvironmentVariables.tooltip"));
        jbEnvironmentVariables.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSystemInformation.this);
                environmentVariablesPressed();
            } finally {
                CursorUtil.setCursorFree(DSystemInformation.this);
            }
        });

        jbSystemProperties = new JButton(res.getString("DSystemInformation.jbSystemProperties.text"));
        PlatformUtil.setMnemonic(jbSystemProperties,
                                 res.getString("DSystemInformation.jbSystemProperties.mnemonic").charAt(0));
        jbSystemProperties.setToolTipText(res.getString("DSystemInformation.jbSystemProperties.tooltip"));
        jbSystemProperties.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DSystemInformation.this);
                systemPropertiesPressed();
            } finally {
                CursorUtil.setCursorFree(DSystemInformation.this);
            }
        });

        jbOK = new JButton(res.getString("DSystemInformation.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jpSystemInformation = new JPanel(new MigLayout("", "[right]unrel[grow]", ""));
        jpSystemInformation.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

        jpSystemInformation.add(jlHostname, "");
        jpSystemInformation.add(jtfHostname, "growx, wrap");
        jpSystemInformation.add(jlOperatingSystem, "");
        jpSystemInformation.add(jtfOperatingSystem, "growx, wrap");
        jpSystemInformation.add(jlLocale, "");
        jpSystemInformation.add(jtfLocale, "growx, wrap");
        jpSystemInformation.add(jlJavaVersion, "");
        jpSystemInformation.add(jtfJavaVersion, "growx, wrap");
        jpSystemInformation.add(jlJavaVendor, "");
        jpSystemInformation.add(jtfJavaVendor, "growx, wrap");
        jpSystemInformation.add(jlJavaHome, "");
        jpSystemInformation.add(jtfJavaHome, "growx, wrap");
        jpSystemInformation.add(jlJvmMaximumMemory, "");
        jpSystemInformation.add(jtfJvmMaximumMemory, "growx, wrap");
        jpSystemInformation.add(jlJvmTotalMemory, "");
        jpSystemInformation.add(jtfJvmTotalMemory, "growx, wrap");
        jpSystemInformation.add(jlJvmFreeMemory, "");
        jpSystemInformation.add(jtfJvmFreeMemory, "growx, wrap");
        jpSystemInformation.add(jlAvailableProcessors, "");
        jpSystemInformation.add(jtfAvailableProcessors, "growx, wrap");
        jpSystemInformation.add(jbEnvironmentVariables, "spanx, split 2, gapleft push");
        jpSystemInformation.add(jbSystemProperties, "");

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets 0, fill", "[grow]", ""));
        pane.add(jpSystemInformation, "grow, wrap");
        pane.add(PlatformUtil.createDialogButtonPanel(jbOK), "growx");

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

    private String getHostname() {
        String host = IpAddress.getHostName();
        String address = IpAddress.getIpAddress();

        String hostname = null;
        if (host.isEmpty() && address.isEmpty()) {
            hostname = res.getString("DSystemInformation.jtfHostname.unknown.text");
        } else if (host.equals(address)) {
            hostname = address;
        } else {
            hostname = MessageFormat.format(res.getString("DSystemInformation.jtfHostname.text"), host, address);
        }

        return hostname;
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
                                                         runtime.maxMemory() / 1024));
        jtfJvmMaximumMemory.setCaretPosition(0);

        jtfJvmTotalMemory.setText(MessageFormat.format(res.getString("DSystemInformation.jtfJvmTotalMemory.text"),
                                                       runtime.totalMemory() / 1024));
        jtfJvmTotalMemory.setCaretPosition(0);

        jtfJvmFreeMemory.setText(MessageFormat.format(res.getString("DSystemInformation.jtfJvmFreeMemory.text"),
                                                      runtime.freeMemory() / 1024));
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
            for (; ; ) {
                SwingUtilities.invokeLater(() -> {

                    Runtime runtime = Runtime.getRuntime();

                    updateMemoryFields(runtime);
                });

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }
}
