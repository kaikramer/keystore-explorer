/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.net.ProxySelector;
import java.security.Security;
import java.util.ArrayList;
import java.util.ResourceBundle;
import java.util.TreeSet;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSlider;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import net.miginfocom.swing.MigLayout;
import net.sf.keystore_explorer.crypto.SecurityProvider;
import net.sf.keystore_explorer.crypto.x509.KseX500NameStyle;
import net.sf.keystore_explorer.crypto.x509.X500NameUtils;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.password.PasswordQualityConfig;
import net.sf.keystore_explorer.utilities.StringUtils;
import net.sf.keystore_explorer.utilities.net.ManualProxySelector;
import net.sf.keystore_explorer.utilities.net.NoProxySelector;
import net.sf.keystore_explorer.utilities.net.PacProxySelector;
import net.sf.keystore_explorer.utilities.net.ProxyAddress;
import net.sf.keystore_explorer.utilities.os.OperatingSystem;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Dialog to allow the users to configure KeyStore Explorer's preferences.
 * 
 */
public class DPreferences extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JTabbedPane jtpPreferences;
	private JPanel jpAuthorityCertificates;
	private JPanel jpCaCertificatesFile;
	private JLabel jlCaCertificatesFile;
	private JTextField jtfCaCertificatesFile;
	private JButton jbBrowseCaCertificatesFile;
	private JPanel jpUseCaCertificates;
	private JCheckBox jcbUseCaCertificates;
	private JPanel jpUseWinTrustedRootCertificates;
	private JCheckBox jcbUseWinTrustedRootCertificates;
	private JPanel jpTrustChecks;
	private JLabel jlTrustChecks;
	private JCheckBox jcbEnableImportTrustedCertTrustCheck;
	private JCheckBox jcbEnableImportCaReplyTrustCheck;
	private JPanel jpPasswordQuality;
	private JCheckBox jcbEnablePasswordQuality;
	private JCheckBox jcbEnforceMinimumPasswordQuality;
	private JLabel jlMinimumPasswordQuality;
	private JSlider jsMinimumPasswordQuality;
	private JPanel jpLookFeel;
	private JPanel jpLookFeelNote;
	private JLabel jlLookFeelNote;
	private JPanel jpLookFeelControls;
	private JLabel jlLookFeel;
	private JComboBox jcbLookFeel;
	private JPanel jpLookFeelDecoratedControls;
	private JCheckBox jcbLookFeelDecorated;
	private JPanel jpInternetProxy;
	private JRadioButton jrbNoProxy;
	private JRadioButton jrbManualProxyConfig;
	private JLabel jlHttpHost;
	private JTextField jtfHttpHost;
	private JLabel jlHttpPort;
	private JTextField jtfHttpPort;
	private JLabel jlHttpsHost;
	private JTextField jtfHttpsHost;
	private JLabel jlHttpsPort;
	private JTextField jtfHttpsPort;
	private JLabel jlSocksHost;
	private JTextField jtfSocksHost;
	private JLabel jlSocksPort;
	private JTextField jtfSocksPort;
	private JRadioButton jrbAutomaticProxyConfig;
	private JLabel jlPacUrl;
	private JTextField jtfPacUrl;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;
	
	private JPanel jpDefaultName;
	private JLabel jlCommonName;
	private JTextField jtfCommonName;
	private JLabel jlOrganisationUnit;
	private JTextField jtfOrganisationUnit;
	private JLabel jlOrganisationName;
	private JTextField jtfOrganisationName;
	private JLabel jlLocalityName;
	private JTextField jtfLocalityName;
	private JLabel jlStateName;
	private JTextField jtfStateName;
	private JLabel jlCountryCode;
	private JTextField jtfCountryCode;
	private JLabel jlEmailAddress;
	private JTextField jtfEmailAddress;

	private boolean useCaCertificates;
	private File caCertificatesFile;
	private boolean useWinTrustRootCertificates;
	private boolean enableImportTrustedCertTrustCheck;
	private boolean enableImportCaReplyTrustCheck;
	private PasswordQualityConfig passwordQualityConfig;
	private ArrayList<UIManager.LookAndFeelInfo> lookFeelInfoList = new ArrayList<UIManager.LookAndFeelInfo>();
	private UIManager.LookAndFeelInfo lookFeelInfo;
	private boolean lookFeelDecorated;
	private String defaultDN;
	private boolean cancelled = false;


	/**
	 * Creates a new DPreferences dialog.
	 * 
	 * @param parent
	 *            The parent frame
	 * @param useCaCertificates
	 *            Use CA Certificates keystore file?
	 * @param caCertificatesFile
	 *            CA Certificates keystore file
	 * @param useWinTrustedRootCertificates
	 *            Use Windows Trusted Root Certificates?
	 * @param enableImportTrustedCertTrustCheck
	 *            Enable trust checks when importing Trusted Certificates?
	 * @param enableImportCaReplyTrustCheck
	 *            Enable trust checks when importing CA replies?
	 * @param passwordQualityConfig
	 *            Password quality configuration
	 */
	public DPreferences(JFrame parent, boolean useCaCertificates, File caCertificatesFile,
			boolean useWinTrustedRootCertificates, boolean enableImportTrustedCertTrustCheck,
			boolean enableImportCaReplyTrustCheck, PasswordQualityConfig passwordQualityConfig,
			String defaultDN) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.useCaCertificates = useCaCertificates;
		this.caCertificatesFile = caCertificatesFile;
		this.useWinTrustRootCertificates = useWinTrustedRootCertificates;
		this.enableImportTrustedCertTrustCheck = enableImportTrustedCertTrustCheck;
		this.enableImportCaReplyTrustCheck = enableImportCaReplyTrustCheck;
		this.passwordQualityConfig = passwordQualityConfig;
		this.defaultDN = defaultDN;
		initComponents();
	}

	private void initComponents() {
		initAuthorityCertificatesTab();
		initTrustChecksTab();
		initPasswordQualityTab();
		initLookFeelTab();
		initInternetProxyTab();
		initDefaultNameTab();

		jtpPreferences = new JTabbedPane();
		jtpPreferences.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);

		jtpPreferences.addTab(res.getString("DPreferences.jpAuthorityCertificates.text"), new ImageIcon(getClass()
				.getResource(res.getString("DPreferences.jpAuthorityCertificates.image"))), jpAuthorityCertificates,
				res.getString("DPreferences.jpAuthorityCertificates.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpTrustChecks.text"),
				new ImageIcon(getClass().getResource(res.getString("DPreferences.jpTrustChecks.image"))),
				jpTrustChecks, res.getString("DPreferences.jpTrustChecks.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpPasswordQuality.text"), new ImageIcon(getClass()
				.getResource(res.getString("DPreferences.jpPasswordQuality.image"))), jpPasswordQuality, res
				.getString("DPreferences.jpPasswordQuality.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpLookFeel.text"),
				new ImageIcon(getClass().getResource(res.getString("DPreferences.jpLookFeel.image"))), jpLookFeel,
				res.getString("DPreferences.jpLookFeel.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpInternetProxy.text"),
				new ImageIcon(getClass().getResource(res.getString("DPreferences.jpInternetProxy.image"))),
				jpInternetProxy, res.getString("DPreferences.jpInternetProxy.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpDefaultName.text"), 
				new ImageIcon(getClass().getResource(res.getString("DPreferences.jpDefaultName.image"))), 
				jpDefaultName, res.getString("DPreferences.jpDefaultName.tooltip"));
		
		jtpPreferences.setBorder(new EmptyBorder(5, 5, 5, 5));

		if (!OperatingSystem.isMacOs()) {
			jtpPreferences.setMnemonicAt(0, res.getString("DPreferences.jpAuthorityCertificates.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(1, res.getString("DPreferences.jpTrustChecks.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(2, res.getString("DPreferences.jpPasswordQuality.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(3, res.getString("DPreferences.jpLookFeel.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(4, res.getString("DPreferences.jpInternetProxy.mnemonic").charAt(0));
		}

		jbOK = new JButton(res.getString("DPreferences.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DPreferences.this);
					okPressed();
				} finally {
					CursorUtil.setCursorFree(DPreferences.this);
				}
			}
		});

		jbCancel = new JButton(res.getString("DPreferences.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jtpPreferences, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				cancelPressed(); // No save of settings
			}
		});

		setTitle(res.getString("DPreferences.Title"));
		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void initAuthorityCertificatesTab() {
		jcbUseCaCertificates = new JCheckBox(res.getString("DPreferences.jcbUseCaCertificates.text"), useCaCertificates);
		jcbUseCaCertificates.setToolTipText(res.getString("DPreferences.jcbUseCaCertificates.tooltip"));
		PlatformUtil.setMnemonic(jcbUseCaCertificates, res.getString("DPreferences.jcbUseCaCertificates.mnemonic")
				.charAt(0));

		jlCaCertificatesFile = new JLabel(res.getString("DPreferences.jlCaCertificatesFile.text"));
		jtfCaCertificatesFile = new JTextField(caCertificatesFile.toString(), 25);
		jtfCaCertificatesFile.setToolTipText(res.getString("DPreferences.jtfCaCertificatesFile.tooltip"));
		jtfCaCertificatesFile.setCaretPosition(0);
		jtfCaCertificatesFile.setEditable(false);
		jpCaCertificatesFile = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpCaCertificatesFile.add(jlCaCertificatesFile);
		jpCaCertificatesFile.add(jtfCaCertificatesFile);

		jbBrowseCaCertificatesFile = new JButton(res.getString("DPreferences.jbBrowseCaCertificatesFile.text"));
		PlatformUtil.setMnemonic(jbBrowseCaCertificatesFile,
				res.getString("DPreferences.jbBrowseCaCertificatesFile.mnemonic").charAt(0));
		jbBrowseCaCertificatesFile.setToolTipText(res.getString("DPreferences.jbBrowseCaCertificatesFile.tooltip"));
		jbBrowseCaCertificatesFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DPreferences.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DPreferences.this);
				}
			}
		});
		jpCaCertificatesFile.add(jbBrowseCaCertificatesFile);

		GridBagConstraints gbcCaCertificatesFile = new GridBagConstraints();
		gbcCaCertificatesFile.gridx = 0;
		gbcCaCertificatesFile.gridwidth = 1;
		gbcCaCertificatesFile.gridy = 0;
		gbcCaCertificatesFile.gridheight = 1;
		gbcCaCertificatesFile.anchor = GridBagConstraints.WEST;

		jpUseCaCertificates = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpUseCaCertificates.add(jcbUseCaCertificates);

		GridBagConstraints gbcUseCaCertificates = new GridBagConstraints();
		gbcUseCaCertificates.gridx = 0;
		gbcUseCaCertificates.gridwidth = 1;
		gbcUseCaCertificates.gridy = 1;
		gbcUseCaCertificates.gridheight = 1;
		gbcUseCaCertificates.anchor = GridBagConstraints.WEST;

		jpAuthorityCertificates = new JPanel(new GridBagLayout());
		jpAuthorityCertificates.add(jpCaCertificatesFile, gbcCaCertificatesFile);
		jpAuthorityCertificates.add(jpUseCaCertificates, gbcUseCaCertificates);

		if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
			jcbUseWinTrustedRootCertificates = new JCheckBox(
					res.getString("DPreferences.jcbUseWinTrustRootCertificates.text"), useWinTrustRootCertificates);
			jcbUseWinTrustedRootCertificates.setToolTipText(res
					.getString("DPreferences.jcbUseWinTrustRootCertificates.tooltip"));
			PlatformUtil.setMnemonic(jcbUseWinTrustedRootCertificates,
					res.getString("DPreferences.jcbUseWinTrustRootCertificates.menmonic").charAt(0));

			jpUseWinTrustedRootCertificates = new JPanel(new FlowLayout(FlowLayout.LEFT));
			jpUseWinTrustedRootCertificates.add(jcbUseWinTrustedRootCertificates);

			GridBagConstraints gbcUseWinTrustRootCertificates = new GridBagConstraints();
			gbcUseWinTrustRootCertificates.gridx = 0;
			gbcUseWinTrustRootCertificates.gridwidth = 1;
			gbcUseWinTrustRootCertificates.gridy = 2;
			gbcUseWinTrustRootCertificates.gridheight = 1;
			gbcUseWinTrustRootCertificates.anchor = GridBagConstraints.WEST;

			jpAuthorityCertificates.add(jpUseWinTrustedRootCertificates, gbcUseWinTrustRootCertificates);
		}

		jpAuthorityCertificates.setBorder(new EmptyBorder(10, 10, 10, 10));
	}

	private void initTrustChecksTab() {
		jlTrustChecks = new JLabel(res.getString("DPreferences.jlTrustChecks.text"));

		GridBagConstraints gbc_jlTrustChecks = new GridBagConstraints();
		gbc_jlTrustChecks.gridx = 0;
		gbc_jlTrustChecks.gridwidth = 1;
		gbc_jlTrustChecks.gridy = 0;
		gbc_jlTrustChecks.gridheight = 1;
		gbc_jlTrustChecks.anchor = GridBagConstraints.WEST;
		gbc_jlTrustChecks.insets = new Insets(5, 5, 0, 0);

		jcbEnableImportTrustedCertTrustCheck = new JCheckBox(
				res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.text"),
				enableImportTrustedCertTrustCheck);
		jcbEnableImportTrustedCertTrustCheck.setToolTipText(res
				.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.tooltip"));
		jcbEnableImportTrustedCertTrustCheck.setMnemonic(res.getString(
				"DPreferences.jcbEnableImportTrustedCertTrustCheck.mnemonic").charAt(0));

		GridBagConstraints gbc_jcbEnableImportTrustedCertTrustCheck = new GridBagConstraints();
		gbc_jcbEnableImportTrustedCertTrustCheck.gridx = 0;
		gbc_jcbEnableImportTrustedCertTrustCheck.gridwidth = 1;
		gbc_jcbEnableImportTrustedCertTrustCheck.gridy = 1;
		gbc_jcbEnableImportTrustedCertTrustCheck.gridheight = 1;
		gbc_jcbEnableImportTrustedCertTrustCheck.anchor = GridBagConstraints.WEST;
		gbc_jcbEnableImportTrustedCertTrustCheck.insets = new Insets(5, 5, 0, 0);

		jcbEnableImportCaReplyTrustCheck = new JCheckBox(
				res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.text"), enableImportCaReplyTrustCheck);
		jcbEnableImportCaReplyTrustCheck.setToolTipText(res
				.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.tooltip"));
		jcbEnableImportCaReplyTrustCheck.setMnemonic(res.getString(
				"DPreferences.jcbEnableImportCaReplyTrustCheck.mnemonic").charAt(0));

		GridBagConstraints gbc_jcbEnableImportCaReplyTrustCheck = new GridBagConstraints();
		gbc_jcbEnableImportCaReplyTrustCheck.gridx = 0;
		gbc_jcbEnableImportCaReplyTrustCheck.gridwidth = 1;
		gbc_jcbEnableImportCaReplyTrustCheck.gridy = 2;
		gbc_jcbEnableImportCaReplyTrustCheck.gridheight = 1;
		gbc_jcbEnableImportCaReplyTrustCheck.anchor = GridBagConstraints.WEST;
		gbc_jcbEnableImportCaReplyTrustCheck.insets = new Insets(5, 5, 0, 0);

		jpTrustChecks = new JPanel(new GridBagLayout());

		jpTrustChecks.add(jlTrustChecks, gbc_jlTrustChecks);
		jpTrustChecks.add(jcbEnableImportTrustedCertTrustCheck, gbc_jcbEnableImportTrustedCertTrustCheck);
		jpTrustChecks.add(jcbEnableImportCaReplyTrustCheck, gbc_jcbEnableImportCaReplyTrustCheck);

		jpTrustChecks.setBorder(new EmptyBorder(10, 10, 10, 10));
	}

	private void initPasswordQualityTab() {
		jcbEnablePasswordQuality = new JCheckBox(res.getString("DPreferences.jcbEnablePasswordQuality.text"));
		jcbEnablePasswordQuality.setMnemonic(res.getString("DPreferences.jcbEnablePasswordQuality.mnemonic").charAt(0));
		jcbEnablePasswordQuality.setToolTipText(res.getString("DPreferences.jcbEnablePasswordQuality.tooltip"));

		jcbEnablePasswordQuality.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				jcbEnforceMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected());
				jlMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
				jsMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
			}
		});

		GridBagConstraints gbcEnablePasswordQuality = new GridBagConstraints();
		gbcEnablePasswordQuality.gridx = 0;
		gbcEnablePasswordQuality.gridwidth = 1;
		gbcEnablePasswordQuality.gridy = 0;
		gbcEnablePasswordQuality.gridheight = 1;
		gbcEnablePasswordQuality.anchor = GridBagConstraints.WEST;
		gbcEnablePasswordQuality.insets = new Insets(5, 5, 0, 0);

		jcbEnforceMinimumPasswordQuality = new JCheckBox(
				res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.text"));
		jcbEnforceMinimumPasswordQuality.setMnemonic(res.getString(
				"DPreferences.jcbEnforceMinimumPasswordQuality.mnemonic").charAt(0));
		jcbEnforceMinimumPasswordQuality.setToolTipText(res
				.getString("DPreferences.jcbEnforceMinimumPasswordQuality.tooltip"));

		jcbEnforceMinimumPasswordQuality.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				jlMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
				jsMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
			}
		});

		GridBagConstraints gbcEnforceMinimumPasswordQuality = new GridBagConstraints();
		gbcEnforceMinimumPasswordQuality.gridx = 0;
		gbcEnforceMinimumPasswordQuality.gridwidth = 1;
		gbcEnforceMinimumPasswordQuality.gridy = 1;
		gbcEnforceMinimumPasswordQuality.gridheight = 1;
		gbcEnforceMinimumPasswordQuality.anchor = GridBagConstraints.WEST;
		gbcEnforceMinimumPasswordQuality.insets = new Insets(5, 30, 0, 0);

		jlMinimumPasswordQuality = new JLabel(res.getString("DPreferences.jlMinimumPasswordQuality.text"));

		GridBagConstraints gbcMinimumPasswordQualityLabel = new GridBagConstraints();
		gbcMinimumPasswordQualityLabel.gridx = 0;
		gbcMinimumPasswordQualityLabel.gridwidth = 1;
		gbcMinimumPasswordQualityLabel.gridy = 2;
		gbcMinimumPasswordQualityLabel.gridheight = 1;
		gbcMinimumPasswordQualityLabel.anchor = GridBagConstraints.NORTHWEST;
		gbcMinimumPasswordQualityLabel.insets = new Insets(10, 60, 0, 0);

		jsMinimumPasswordQuality = new JSlider(0, 100);
		jsMinimumPasswordQuality.setPaintLabels(true);
		jsMinimumPasswordQuality.setMajorTickSpacing(25);
		jsMinimumPasswordQuality.setToolTipText(res.getString("DPreferences.jsMinimumPasswordQuality.tooltip"));

		GridBagConstraints gbcMinimumPasswordQualitySlider = new GridBagConstraints();
		gbcMinimumPasswordQualitySlider.gridx = 1;
		gbcMinimumPasswordQualitySlider.gridwidth = 1;
		gbcMinimumPasswordQualitySlider.gridy = 2;
		gbcMinimumPasswordQualitySlider.gridheight = 1;
		gbcMinimumPasswordQualitySlider.anchor = GridBagConstraints.WEST;
		gbcMinimumPasswordQualitySlider.insets = new Insets(5, 5, 0, 0);

		jpPasswordQuality = new JPanel(new GridBagLayout());

		jpPasswordQuality.add(jcbEnablePasswordQuality, gbcEnablePasswordQuality);
		jpPasswordQuality.add(jcbEnforceMinimumPasswordQuality, gbcEnforceMinimumPasswordQuality);
		jpPasswordQuality.add(jlMinimumPasswordQuality, gbcMinimumPasswordQualityLabel);
		jpPasswordQuality.add(jsMinimumPasswordQuality, gbcMinimumPasswordQualitySlider);

		jpPasswordQuality.setBorder(new EmptyBorder(10, 10, 10, 10));

		boolean passwordQualityEnabled = passwordQualityConfig.getEnabled();
		boolean passwordQualityEnforced = passwordQualityConfig.getEnforced();
		int minimumPasswordQuality = passwordQualityConfig.getMinimumQuality();

		jcbEnablePasswordQuality.setSelected(passwordQualityEnabled);
		jcbEnforceMinimumPasswordQuality.setSelected(passwordQualityEnforced);
		jsMinimumPasswordQuality.setValue(minimumPasswordQuality);

		jcbEnforceMinimumPasswordQuality.setEnabled(passwordQualityEnabled);

		jlMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);
		jsMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);
	}

	private void initLookFeelTab() {
		jlLookFeelNote = new JLabel(res.getString("DPreferences.jlLookFeelNote.text"));

		jpLookFeelNote = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpLookFeelNote.add(jlLookFeelNote);

		GridBagConstraints gbcLookFeelNote = new GridBagConstraints();
		gbcLookFeelNote.gridx = 0;
		gbcLookFeelNote.gridwidth = 1;
		gbcLookFeelNote.gridy = 0;
		gbcLookFeelNote.gridheight = 1;
		gbcLookFeelNote.anchor = GridBagConstraints.WEST;

		jlLookFeel = new JLabel(res.getString("DPreferences.jlLookFeel.text"));

		jcbLookFeel = new JComboBox();
		jcbLookFeel.setToolTipText(res.getString("DPreferences.jcbLookFeel.tooltip"));

		// This may contain duplicates
		UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();

		LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

		TreeSet<String> lookFeelClasses = new TreeSet<String>();

		for (UIManager.LookAndFeelInfo lookFeelInfo : lookFeelInfos) {
			// Avoid duplicates
			if (!lookFeelClasses.contains(lookFeelInfo.getClassName())) {
				lookFeelClasses.add(lookFeelInfo.getClassName());

				lookFeelInfoList.add(lookFeelInfo);
				jcbLookFeel.addItem(lookFeelInfo.getName());

				// Pre-select current look & feel - compare by class as the look
				// and feel name can differ from the look and feel info name
				if ((currentLookAndFeel != null)
						&& (currentLookAndFeel.getClass().getName().equals(lookFeelInfo.getClassName()))) {
					this.lookFeelInfo = lookFeelInfo;
					jcbLookFeel.setSelectedIndex(jcbLookFeel.getItemCount() - 1);
				}
			}
		}

		jpLookFeelControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpLookFeelControls.add(jlLookFeel);
		jpLookFeelControls.add(jcbLookFeel);

		GridBagConstraints gbcLookFeelControls = new GridBagConstraints();
		gbcLookFeelControls.gridx = 0;
		gbcLookFeelControls.gridwidth = 1;
		gbcLookFeelControls.gridy = 1;
		gbcLookFeelControls.gridheight = 1;
		gbcLookFeelControls.anchor = GridBagConstraints.WEST;

		// Create and populate check box with look & feel decorated setting
		jcbLookFeelDecorated = new JCheckBox(res.getString("DPreferences.jcbLookFeelDecorated.text"),
				JFrame.isDefaultLookAndFeelDecorated());
		jcbLookFeelDecorated.setToolTipText(res.getString("DPreferences.jcbLookFeelDecorated.tooltip"));
		PlatformUtil.setMnemonic(jcbLookFeelDecorated, res.getString("DPreferences.jcbLookFeelDecorated.menmonic")
				.charAt(0));

		jpLookFeelDecoratedControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpLookFeelDecoratedControls.add(jcbLookFeelDecorated);

		GridBagConstraints gbcLookFeelDecoratedControls = new GridBagConstraints();
		gbcLookFeelDecoratedControls.gridx = 0;
		gbcLookFeelDecoratedControls.gridwidth = 1;
		gbcLookFeelDecoratedControls.gridy = 2;
		gbcLookFeelDecoratedControls.gridheight = 1;
		gbcLookFeelDecoratedControls.anchor = GridBagConstraints.WEST;

		jpLookFeel = new JPanel(new GridBagLayout());
		jpLookFeel.add(jpLookFeelNote, gbcLookFeelNote);
		jpLookFeel.add(jpLookFeelControls, gbcLookFeelControls);
		jpLookFeel.add(jpLookFeelDecoratedControls, gbcLookFeelDecoratedControls);

		jpLookFeel.setBorder(new EmptyBorder(10, 10, 10, 10));
	}

	private void initInternetProxyTab() {
		jrbNoProxy = new JRadioButton(res.getString("DPreferences.jrbNoProxy.text"), true);
		jrbNoProxy.setToolTipText(res.getString("DPreferences.jrbNoProxy.tooltip"));
		PlatformUtil.setMnemonic(jrbNoProxy, res.getString("DPreferences.jrbNoProxy.mnemonic").charAt(0));

		GridBagConstraints gbc_jrbNoProxy = new GridBagConstraints();
		gbc_jrbNoProxy.gridx = 0;
		gbc_jrbNoProxy.gridwidth = 4;
		gbc_jrbNoProxy.gridy = 0;
		gbc_jrbNoProxy.gridheight = 1;
		gbc_jrbNoProxy.anchor = GridBagConstraints.WEST;
		gbc_jrbNoProxy.insets = new Insets(5, 5, 0, 0);

		jrbManualProxyConfig = new JRadioButton(res.getString("DPreferences.jrbManualProxyConfig.text"));
		jrbManualProxyConfig.setToolTipText(res.getString("DPreferences.jrbManualProxyConfig.tooltip"));
		PlatformUtil.setMnemonic(jrbManualProxyConfig, res.getString("DPreferences.jrbManualProxyConfig.mnemonic")
				.charAt(0));

		jrbManualProxyConfig.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				updateProxyControls();
			}
		});

		GridBagConstraints gbc_jrbManualProxyConfig = new GridBagConstraints();
		gbc_jrbManualProxyConfig.gridx = 0;
		gbc_jrbManualProxyConfig.gridwidth = 4;
		gbc_jrbManualProxyConfig.gridy = 1;
		gbc_jrbManualProxyConfig.gridheight = 1;
		gbc_jrbManualProxyConfig.anchor = GridBagConstraints.WEST;
		gbc_jrbManualProxyConfig.insets = new Insets(5, 5, 0, 0);

		jlHttpHost = new JLabel(res.getString("DPreferences.jlHttpHost.text"));

		GridBagConstraints gbc_jlHttpHost = new GridBagConstraints();
		gbc_jlHttpHost.gridx = 0;
		gbc_jlHttpHost.gridwidth = 1;
		gbc_jlHttpHost.gridy = 3;
		gbc_jlHttpHost.gridheight = 1;
		gbc_jlHttpHost.anchor = GridBagConstraints.EAST;
		gbc_jlHttpHost.insets = new Insets(5, 30, 0, 0);

		jtfHttpHost = new JTextField(20);
		jtfHttpHost.setToolTipText(res.getString("DPreferences.jtfHttpHost.tooltip"));
		jtfHttpHost.setEnabled(false);

		GridBagConstraints gbc_jtfHttpHost = new GridBagConstraints();
		gbc_jtfHttpHost.gridx = 1;
		gbc_jtfHttpHost.gridwidth = 1;
		gbc_jtfHttpHost.gridy = 3;
		gbc_jtfHttpHost.gridheight = 1;
		gbc_jtfHttpHost.anchor = GridBagConstraints.WEST;
		gbc_jtfHttpHost.insets = new Insets(5, 5, 0, 0);

		jlHttpPort = new JLabel(res.getString("DPreferences.jlHttpPort.text"));

		GridBagConstraints gbc_jlHttpPort = new GridBagConstraints();
		gbc_jlHttpPort.gridx = 2;
		gbc_jlHttpPort.gridwidth = 1;
		gbc_jlHttpPort.gridy = 3;
		gbc_jlHttpPort.gridheight = 1;
		gbc_jlHttpPort.anchor = GridBagConstraints.WEST;
		gbc_jlHttpPort.insets = new Insets(5, 5, 0, 0);

		jtfHttpPort = new JTextField(4);
		jtfHttpPort.setToolTipText(res.getString("DPreferences.jtfHttpPort.tooltip"));
		jtfHttpPort.setEnabled(false);

		GridBagConstraints gbc_jtfHttpPort = new GridBagConstraints();
		gbc_jtfHttpPort.gridx = 3;
		gbc_jtfHttpPort.gridwidth = 1;
		gbc_jtfHttpPort.gridy = 3;
		gbc_jtfHttpPort.gridheight = 1;
		gbc_jtfHttpPort.anchor = GridBagConstraints.WEST;
		gbc_jtfHttpPort.insets = new Insets(5, 5, 0, 0);

		jlHttpsHost = new JLabel(res.getString("DPreferences.jlHttpsHost.text"));

		GridBagConstraints gbc_jlHttpsHost = new GridBagConstraints();
		gbc_jlHttpsHost.gridx = 0;
		gbc_jlHttpsHost.gridwidth = 1;
		gbc_jlHttpsHost.gridy = 4;
		gbc_jlHttpsHost.gridheight = 1;
		gbc_jlHttpsHost.anchor = GridBagConstraints.EAST;
		gbc_jlHttpsHost.insets = new Insets(5, 30, 0, 0);

		jtfHttpsHost = new JTextField(20);
		jtfHttpsHost.setToolTipText(res.getString("DPreferences.jtfHttpsHost.tooltip"));
		jtfHttpsHost.setEnabled(false);

		GridBagConstraints gbc_jtfHttpsHost = new GridBagConstraints();
		gbc_jtfHttpsHost.gridx = 1;
		gbc_jtfHttpsHost.gridwidth = 1;
		gbc_jtfHttpsHost.gridy = 4;
		gbc_jtfHttpsHost.gridheight = 1;
		gbc_jtfHttpsHost.anchor = GridBagConstraints.WEST;
		gbc_jtfHttpsHost.insets = new Insets(5, 5, 0, 0);

		jlHttpsPort = new JLabel(res.getString("DPreferences.jlHttpsPort.text"));

		GridBagConstraints gbc_jlHttpsPort = new GridBagConstraints();
		gbc_jlHttpsPort.gridx = 2;
		gbc_jlHttpsPort.gridwidth = 1;
		gbc_jlHttpsPort.gridy = 4;
		gbc_jlHttpsPort.gridheight = 1;
		gbc_jlHttpsPort.anchor = GridBagConstraints.WEST;
		gbc_jlHttpsPort.insets = new Insets(5, 5, 0, 0);

		jtfHttpsPort = new JTextField(4);
		jtfHttpsPort.setToolTipText(res.getString("DPreferences.jtfHttpsPort.tooltip"));
		jtfHttpsPort.setEnabled(false);

		GridBagConstraints gbc_jtfHttpsPort = new GridBagConstraints();
		gbc_jtfHttpsPort.gridx = 3;
		gbc_jtfHttpsPort.gridwidth = 1;
		gbc_jtfHttpsPort.gridy = 4;
		gbc_jtfHttpsPort.gridheight = 1;
		gbc_jtfHttpsPort.anchor = GridBagConstraints.WEST;
		gbc_jtfHttpsPort.insets = new Insets(5, 5, 0, 0);

		jlSocksHost = new JLabel(res.getString("DPreferences.jlSocksHost.text"));

		GridBagConstraints gbc_jlSocksHost = new GridBagConstraints();
		gbc_jlSocksHost.gridx = 0;
		gbc_jlSocksHost.gridwidth = 1;
		gbc_jlSocksHost.gridy = 5;
		gbc_jlSocksHost.gridheight = 1;
		gbc_jlSocksHost.anchor = GridBagConstraints.EAST;
		gbc_jlSocksHost.insets = new Insets(5, 30, 0, 0);

		jtfSocksHost = new JTextField(20);
		jtfSocksHost.setToolTipText(res.getString("DPreferences.jtfSocksHost.tooltip"));
		jtfSocksHost.setEnabled(false);

		GridBagConstraints gbc_jtfSocksHost = new GridBagConstraints();
		gbc_jtfSocksHost.gridx = 1;
		gbc_jtfSocksHost.gridwidth = 1;
		gbc_jtfSocksHost.gridy = 5;
		gbc_jtfSocksHost.gridheight = 1;
		gbc_jtfSocksHost.anchor = GridBagConstraints.WEST;
		gbc_jtfSocksHost.insets = new Insets(5, 5, 0, 0);

		jlSocksPort = new JLabel(res.getString("DPreferences.jlSocksPort.text"));

		GridBagConstraints gbc_jlSocksPort = new GridBagConstraints();
		gbc_jlSocksPort.gridx = 2;
		gbc_jlSocksPort.gridwidth = 1;
		gbc_jlSocksPort.gridy = 5;
		gbc_jlSocksPort.gridheight = 1;
		gbc_jlSocksPort.anchor = GridBagConstraints.WEST;
		gbc_jlSocksPort.insets = new Insets(5, 5, 0, 0);

		jtfSocksPort = new JTextField(4);
		jtfSocksPort.setToolTipText(res.getString("DPreferences.jtfSocksPort.tooltip"));
		jtfSocksPort.setEnabled(false);

		GridBagConstraints gbc_jtfSocksPort = new GridBagConstraints();
		gbc_jtfSocksPort.gridx = 3;
		gbc_jtfSocksPort.gridwidth = 1;
		gbc_jtfSocksPort.gridy = 5;
		gbc_jtfSocksPort.gridheight = 1;
		gbc_jtfSocksPort.anchor = GridBagConstraints.WEST;
		gbc_jtfSocksPort.insets = new Insets(5, 5, 0, 0);

		jrbAutomaticProxyConfig = new JRadioButton(res.getString("DPreferences.jrbAutomaticProxyConfig.text"));
		jrbAutomaticProxyConfig.setToolTipText(res.getString("DPreferences.jrbAutomaticProxyConfig.tooltip"));
		PlatformUtil.setMnemonic(jrbAutomaticProxyConfig, res
				.getString("DPreferences.jrbAutomaticProxyConfig.mnemonic").charAt(0));

		jrbAutomaticProxyConfig.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent evt) {
				updateProxyControls();
			}
		});

		GridBagConstraints gbc_jrbAutomaticProxyConfig = new GridBagConstraints();
		gbc_jrbAutomaticProxyConfig.gridx = 0;
		gbc_jrbAutomaticProxyConfig.gridwidth = 4;
		gbc_jrbAutomaticProxyConfig.gridy = 6;
		gbc_jrbAutomaticProxyConfig.gridheight = 1;
		gbc_jrbAutomaticProxyConfig.anchor = GridBagConstraints.WEST;
		gbc_jrbAutomaticProxyConfig.insets = new Insets(5, 5, 0, 0);

		jlPacUrl = new JLabel(res.getString("DPreferences.jlPacUrl.text"));

		GridBagConstraints gbc_jlPacUrl = new GridBagConstraints();
		gbc_jlPacUrl.gridx = 0;
		gbc_jlPacUrl.gridwidth = 1;
		gbc_jlPacUrl.gridy = 7;
		gbc_jlPacUrl.gridheight = 1;
		gbc_jlPacUrl.anchor = GridBagConstraints.EAST;
		gbc_jlPacUrl.insets = new Insets(5, 5, 0, 0);

		jtfPacUrl = new JTextField(30);
		jtfPacUrl.setToolTipText(res.getString("DPreferences.jtfPacUrl.tooltip"));
		jtfPacUrl.setEnabled(false);

		GridBagConstraints gbc_jtfPacUrl = new GridBagConstraints();
		gbc_jtfPacUrl.gridx = 1;
		gbc_jtfPacUrl.gridwidth = 3;
		gbc_jtfPacUrl.gridy = 7;
		gbc_jtfPacUrl.gridheight = 1;
		gbc_jtfPacUrl.anchor = GridBagConstraints.WEST;
		gbc_jtfPacUrl.insets = new Insets(5, 5, 0, 0);

		ButtonGroup bgProxies = new ButtonGroup();
		bgProxies.add(jrbNoProxy);
		bgProxies.add(jrbManualProxyConfig);
		bgProxies.add(jrbAutomaticProxyConfig);

		jpInternetProxy = new JPanel(new GridBagLayout());

		jpInternetProxy.add(jrbNoProxy, gbc_jrbNoProxy);
		jpInternetProxy.add(jrbManualProxyConfig, gbc_jrbManualProxyConfig);
		jpInternetProxy.add(jlHttpHost, gbc_jlHttpHost);
		jpInternetProxy.add(jtfHttpHost, gbc_jtfHttpHost);
		jpInternetProxy.add(jlHttpPort, gbc_jlHttpPort);
		jpInternetProxy.add(jtfHttpPort, gbc_jtfHttpPort);
		jpInternetProxy.add(jlHttpsHost, gbc_jlHttpsHost);
		jpInternetProxy.add(jtfHttpsHost, gbc_jtfHttpsHost);
		jpInternetProxy.add(jlHttpsPort, gbc_jlHttpsPort);
		jpInternetProxy.add(jtfHttpsPort, gbc_jtfHttpsPort);
		jpInternetProxy.add(jlSocksHost, gbc_jlSocksHost);
		jpInternetProxy.add(jtfSocksHost, gbc_jtfSocksHost);
		jpInternetProxy.add(jlSocksPort, gbc_jlSocksPort);
		jpInternetProxy.add(jtfSocksPort, gbc_jtfSocksPort);
		jpInternetProxy.add(jrbAutomaticProxyConfig, gbc_jrbAutomaticProxyConfig);
		jpInternetProxy.add(jlPacUrl, gbc_jlPacUrl);
		jpInternetProxy.add(jtfPacUrl, gbc_jtfPacUrl);

		jpInternetProxy.setBorder(new EmptyBorder(10, 10, 10, 10));

		ProxySelector proxySelector = ProxySelector.getDefault();

		if (proxySelector instanceof PacProxySelector) {
			jrbAutomaticProxyConfig.setSelected(true);

			PacProxySelector pacProxySelector = (PacProxySelector) proxySelector;

			jtfPacUrl.setText(pacProxySelector.getPacUrl());
		} else if (proxySelector instanceof ManualProxySelector) {
			jrbManualProxyConfig.setSelected(true);

			ManualProxySelector manualProxySelector = (ManualProxySelector) proxySelector;

			ProxyAddress httpProxy = manualProxySelector.getHttpProxyAddress();
			ProxyAddress httpsProxy = manualProxySelector.getHttpsProxyAddress();
			ProxyAddress socksProxy = manualProxySelector.getSocksProxyAddress();

			if (httpProxy != null) {
				jtfHttpHost.setText(httpProxy.getHost());
				jtfHttpHost.setCaretPosition(0);

				jtfHttpPort.setText("" + httpProxy.getPort());
				jtfHttpPort.setCaretPosition(0);
			}

			if (httpsProxy != null) {
				jtfHttpsHost.setText(httpsProxy.getHost());
				jtfHttpsHost.setCaretPosition(0);

				jtfHttpsPort.setText("" + httpsProxy.getPort());
				jtfHttpsPort.setCaretPosition(0);
			}

			if (socksProxy != null) {
				jtfSocksHost.setText(socksProxy.getHost());
				jtfSocksHost.setCaretPosition(0);

				jtfSocksPort.setText("" + socksProxy.getPort());
				jtfSocksPort.setCaretPosition(0);
			}
		} else {
			jrbNoProxy.setSelected(true);
		}
	}

	private void initDefaultNameTab() {
		
		jlCommonName = new JLabel(res.getString("DPreferences.jlCommonName.text"));
		jtfCommonName = new JTextField(25);
		jlOrganisationUnit = new JLabel(res.getString("DPreferences.jlOrganisationUnit.text"));
		jtfOrganisationUnit = new JTextField(25);
		jlOrganisationName = new JLabel(res.getString("DPreferences.jlOrganisationName.text"));
		jtfOrganisationName = new JTextField(25);
		jlLocalityName = new JLabel(res.getString("DPreferences.jlLocalityName.text"));
		jtfLocalityName = new JTextField(25);
		jlStateName = new JLabel(res.getString("DPreferences.jlStateName.text"));
		jtfStateName = new JTextField(25);
		jlCountryCode = new JLabel(res.getString("DPreferences.jlCountryCode.text"));
		jtfCountryCode = new JTextField(4);
		jlEmailAddress = new JLabel(res.getString("DPreferences.jlEmailAddress.text"));
		jtfEmailAddress = new JTextField(25);
	
		// layout
		jpDefaultName = new JPanel();
		jpDefaultName.setLayout(new MigLayout("insets dialog, fill", "[right][][]", "[]"));
		jpDefaultName.add(jlCommonName, "");
		jpDefaultName.add(jtfCommonName, "gap rel, wrap unrel");
		jpDefaultName.add(jlOrganisationUnit, "");
		jpDefaultName.add(jtfOrganisationUnit, "gap rel, wrap unrel");
		jpDefaultName.add(jlOrganisationName, "");
		jpDefaultName.add(jtfOrganisationName, "gap rel, wrap unrel");
		jpDefaultName.add(jlLocalityName, "");
		jpDefaultName.add(jtfLocalityName, "gap rel, wrap unrel");
		jpDefaultName.add(jlStateName, "");
		jpDefaultName.add(jtfStateName, "gap rel, wrap unrel");
		jpDefaultName.add(jlCountryCode, "");
		jpDefaultName.add(jtfCountryCode, "gap rel, wrap unrel");
		jpDefaultName.add(jlEmailAddress, "");
		jpDefaultName.add(jtfEmailAddress, "gap rel, wrap unrel");

		// populate fields with content from saved preferences
		if (defaultDN != null) {
			try {
				X500Name x500Name = new X500Name(defaultDN);
				populateRdnField(x500Name, jtfCommonName, KseX500NameStyle.CN);
				populateRdnField(x500Name, jtfOrganisationUnit, KseX500NameStyle.OU);
				populateRdnField(x500Name, jtfOrganisationName, KseX500NameStyle.O);
				populateRdnField(x500Name, jtfLocalityName, KseX500NameStyle.L);
				populateRdnField(x500Name, jtfStateName, KseX500NameStyle.ST);
				populateRdnField(x500Name, jtfCountryCode, KseX500NameStyle.C);
				populateRdnField(x500Name, jtfEmailAddress, KseX500NameStyle.E);
			} catch (Exception e) {
				// reset invalid DN by leaving fields empty
			}
		}
	}
	
	private void populateRdnField(X500Name distinguishedName, JTextField rdnField, ASN1ObjectIdentifier rdnOid) {
		rdnField.setText(X500NameUtils.getRdn(distinguishedName, rdnOid));
		rdnField.setCaretPosition(0);
	}
	
	private void updateProxyControls() {
		if (jrbManualProxyConfig.isSelected()) {
			jtfHttpHost.setEnabled(true);
			jtfHttpPort.setEnabled(true);
			jtfHttpsHost.setEnabled(true);
			jtfHttpsPort.setEnabled(true);
			jtfSocksHost.setEnabled(true);
			jtfSocksPort.setEnabled(true);

			jtfPacUrl.setEnabled(false);
		} else if (this.jrbAutomaticProxyConfig.isSelected()) {
			jtfHttpHost.setEnabled(false);
			jtfHttpPort.setEnabled(false);
			jtfHttpsHost.setEnabled(false);
			jtfHttpsPort.setEnabled(false);
			jtfSocksHost.setEnabled(false);
			jtfSocksPort.setEnabled(false);

			jtfPacUrl.setEnabled(true);
		} else {
			jtfHttpHost.setEnabled(false);
			jtfHttpPort.setEnabled(false);
			jtfHttpsHost.setEnabled(false);
			jtfHttpsPort.setEnabled(false);
			jtfSocksHost.setEnabled(false);
			jtfSocksPort.setEnabled(false);

			jtfPacUrl.setEnabled(false);
		}
	}

	private boolean storePreferences() {
		caCertificatesFile = new File(jtfCaCertificatesFile.getText());

		useCaCertificates = jcbUseCaCertificates.isSelected();

		if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
			useWinTrustRootCertificates = jcbUseWinTrustedRootCertificates.isSelected();
		}

		enableImportTrustedCertTrustCheck = jcbEnableImportTrustedCertTrustCheck.isSelected();
		enableImportCaReplyTrustCheck = jcbEnableImportCaReplyTrustCheck.isSelected();

		passwordQualityConfig.setEnabled(jcbEnablePasswordQuality.isSelected());
		passwordQualityConfig.setMinimumQuality(jsMinimumPasswordQuality.getValue());
		passwordQualityConfig.setEnforced(jcbEnforceMinimumPasswordQuality.isSelected());

		int selectedIndex = jcbLookFeel.getSelectedIndex();
		lookFeelInfo = lookFeelInfoList.get(selectedIndex);

		lookFeelDecorated = jcbLookFeelDecorated.isSelected();
		
		// These may fail:
		boolean returnValue = storeDefaultDN();
		returnValue &= storeProxyPreferences(); 
		
		return returnValue;
	}

	private boolean storeDefaultDN() {
		String commonName = StringUtils.trimAndConvertEmptyToNull(jtfCommonName.getText());
		String organisationUnit = StringUtils.trimAndConvertEmptyToNull(jtfOrganisationUnit.getText());
		String organisationName = StringUtils.trimAndConvertEmptyToNull(jtfOrganisationName.getText());
		String localityName = StringUtils.trimAndConvertEmptyToNull(jtfLocalityName.getText());
		String stateName = StringUtils.trimAndConvertEmptyToNull(jtfStateName.getText());
		String countryCode = StringUtils.trimAndConvertEmptyToNull(jtfCountryCode.getText());
		String emailAddress = StringUtils.trimAndConvertEmptyToNull(jtfEmailAddress.getText());

		defaultDN = X500NameUtils.buildX500Name(commonName, organisationUnit, organisationName,
				localityName, stateName, countryCode, emailAddress).toString();
		return true;
	}

	private boolean storeProxyPreferences() {
		// Store current proxy selector - compare with new one to see if default needs updated
		ProxySelector defaultProxySelector = ProxySelector.getDefault();

		if (jrbNoProxy.isSelected()) {
			NoProxySelector noProxySelector = new NoProxySelector();

			if (!noProxySelector.equals(defaultProxySelector)) {
				ProxySelector.setDefault(noProxySelector);
			}
		} else if (jrbManualProxyConfig.isSelected()) {
			String httpHost = jtfHttpHost.getText().trim();
			String httpPortStr = jtfHttpPort.getText().trim();
			String httpsHost = jtfHttpsHost.getText().trim();
			String httpsPortStr = jtfHttpsPort.getText().trim();
			String socksHost = jtfSocksHost.getText().trim();
			String socksPortStr = jtfSocksPort.getText().trim();

			ProxyAddress httpProxyAddress = null;
			ProxyAddress httpsProxyAddress = null;
			ProxyAddress socksProxyAddress = null;

			// Require at least one of the HTTP host or HTTPS host or SOCKS host
			// manual settings
			if ((httpHost.length() == 0) && (httpsHost.length() == 0) && (socksHost.length() == 0)) {
				jtpPreferences.setSelectedIndex(3);
				JOptionPane.showMessageDialog(this, res.getString("DPreferences.ManualConfigReq.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return false;
			} else {
				if (httpHost.length() > 0) {
					if (httpPortStr.length() == 0) {
						jtpPreferences.setSelectedIndex(3);
						JOptionPane.showMessageDialog(this, res.getString("DPreferences.PortReqHttp.message"),
								getTitle(), JOptionPane.WARNING_MESSAGE);
						return false;
					} else {
						try {
							int httpPort = Integer.parseInt(httpPortStr);

							if (httpPort < 1) {
								throw new NumberFormatException();
							}

							httpProxyAddress = new ProxyAddress(httpHost, httpPort);
						} catch (NumberFormatException ex) {
							jtpPreferences.setSelectedIndex(3);
							JOptionPane.showMessageDialog(this,
									res.getString("DPreferences.IntegerPortReqHttp.message"), getTitle(),
									JOptionPane.WARNING_MESSAGE);
							return false;
						}
					}
				}

				if (httpsHost.length() > 0) {
					if (httpsPortStr.length() == 0) {
						jtpPreferences.setSelectedIndex(3);
						JOptionPane.showMessageDialog(this, res.getString("DPreferences.PortReqHttps.message"),
								getTitle(), JOptionPane.WARNING_MESSAGE);
						return false;
					} else {
						try {
							int httpsPort = Integer.parseInt(httpsPortStr);

							if (httpsPort < 1) {
								throw new NumberFormatException();
							}

							httpsProxyAddress = new ProxyAddress(httpsHost, httpsPort);
						} catch (NumberFormatException ex) {
							jtpPreferences.setSelectedIndex(3);
							JOptionPane.showMessageDialog(this,
									res.getString("DPreferences.IntegerPortReqHttps.message"), getTitle(),
									JOptionPane.WARNING_MESSAGE);
							return false;
						}
					}
				}

				if (socksHost.length() > 0) {
					if (socksPortStr.length() == 0) {
						jtpPreferences.setSelectedIndex(3);
						JOptionPane.showMessageDialog(this, res.getString("DPreferences.PortReqSocks.message"),
								getTitle(), JOptionPane.WARNING_MESSAGE);
						return false;
					} else {
						try {
							int socksPort = Integer.parseInt(socksPortStr);

							if (socksPort < 1) {
								throw new NumberFormatException();
							}

							socksProxyAddress = new ProxyAddress(socksHost, socksPort);
						} catch (NumberFormatException ex) {
							jtpPreferences.setSelectedIndex(3);
							JOptionPane.showMessageDialog(this,
									res.getString("DPreferences.IntegerPortReqSocks.message"), getTitle(),
									JOptionPane.WARNING_MESSAGE);
							return false;
						}
					}
				}

				ManualProxySelector manualProxySelector = new ManualProxySelector(httpProxyAddress, httpsProxyAddress,
						null, socksProxyAddress);

				if (!manualProxySelector.equals(defaultProxySelector)) {
					ProxySelector.setDefault(manualProxySelector);
				}
			}
		} else if (jrbAutomaticProxyConfig.isSelected()) {
			String pacUrl = jtfPacUrl.getText().trim();

			if (pacUrl.length() == 0) {
				jtpPreferences.setSelectedIndex(3);
				JOptionPane.showMessageDialog(this, res.getString("DPreferences.PacUrlReq.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return false;
			}

			PacProxySelector pacProxySelector = new PacProxySelector(pacUrl);

			if (!pacProxySelector.equals(defaultProxySelector)) {
				ProxySelector.setDefault(pacProxySelector);
			}
		}

		return true;
	}

	/**
	 * Get whether or not the usage of CA Certificates has been chosen.
	 * 
	 * @return True if it has, false otherwise
	 */
	public boolean getUseCaCertificates() {
		return useCaCertificates;
	}

	/**
	 * Get the chosen CA Certificates KeyStore file.
	 * 
	 * @return The chosen CA Certificates KeyStore file
	 */
	public File getCaCertificatesFile() {
		return caCertificatesFile;
	}

	/**
	 * Get whether or not the usage of Windows Trusted Root Certificates has
	 * been chosen.
	 * 
	 * @return True if it has, false otherwise
	 */
	public boolean getUseWinTrustRootCertificates() {
		return useWinTrustRootCertificates;
	}

	/**
	 * Get whether or not trust checks are enabled when importing Trusted
	 * Certificates.
	 * 
	 * @return True if they are, false otherwise
	 */
	public boolean getEnableImportTrustedCertTrustCheck() {
		return enableImportTrustedCertTrustCheck;
	}

	/**
	 * Get whether or not trust checks are enabled when importing CA Replies.
	 * 
	 * @return True if they are, false otherwise
	 */
	public boolean getEnableImportCaReplyTrustCheck() {
		return enableImportCaReplyTrustCheck;
	}

	/**
	 * Get the chosen password quality confiruration settings.
	 * 
	 * @return Password quality configuration settings
	 */
	public PasswordQualityConfig getPasswordQualityConfig() {
		return passwordQualityConfig;
	}

	/**
	 * Get the chosen look & feel information.
	 * 
	 * @return The chosen look & feel information
	 */
	public UIManager.LookAndFeelInfo getLookFeelInfo() {
		return lookFeelInfo;
	}

	/**
	 * Get whether or not the look & feel should be used for window decoration.
	 * 
	 * @return True id it should, false otherwise.
	 */
	public boolean getLookFeelDecoration() {
		return lookFeelDecorated;
	}

	public String getDefaultDN() {
		return defaultDN;
	}

	/**
	 * Was the dialog cancelled (ie were no settings made).
	 * 
	 * @return True f it was cancelled
	 */
	public boolean wasCancelled() {
		return cancelled;
	}

	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();

		if ((caCertificatesFile.getParentFile() != null) && (caCertificatesFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(caCertificatesFile.getParentFile());
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DPreferences.ChooseCACertificatesKeyStore.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DPreferences.CaCertificatesKeyStoreFileChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfCaCertificatesFile.setText(chosenFile.toString());
			jtfCaCertificatesFile.setCaretPosition(0);
		}
	}

	private void okPressed() {
		if (storePreferences()) {
			closeDialog();
		}
	}

	private void cancelPressed() {
		cancelled = true;
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
