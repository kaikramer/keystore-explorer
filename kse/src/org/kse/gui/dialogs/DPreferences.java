/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
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
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.LookAndFeel;
import javax.swing.SpinnerNumberModel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.asn1.x500.X500Name;
import org.kse.ApplicationSettings;
import org.kse.crypto.SecurityProvider;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dnchooser.DistinguishedNameChooser;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.net.ManualProxySelector;
import org.kse.utilities.net.NoProxySelector;
import org.kse.utilities.net.PacProxySelector;
import org.kse.utilities.net.ProxyAddress;
import org.kse.utilities.net.SystemProxySelector;
import org.kse.utilities.os.OperatingSystem;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to allow the users to configure KeyStore Explorer's preferences.
 *
 */
public class DPreferences extends JEscDialog {
	private static final long serialVersionUID = 8804918466790662761L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JTabbedPane jtpPreferences;
	private JPanel jpAuthorityCertificates;
	private JLabel jlCaCertificatesFile;
	private JTextField jtfCaCertificatesFile;
	private JButton jbBrowseCaCertificatesFile;
	private JCheckBox jcbUseCaCertificates;
	private JCheckBox jcbUseWinTrustedRootCertificates;
	private JLabel jlTrustChecks;
	private JCheckBox jcbEnableImportTrustedCertTrustCheck;
	private JCheckBox jcbEnableImportCaReplyTrustCheck;
	private JLabel jlPasswordQuality;
	private JCheckBox jcbEnablePasswordQuality;
	private JCheckBox jcbEnforceMinimumPasswordQuality;
	private JLabel jlMinimumPasswordQuality;
	private JSlider jsMinimumPasswordQuality;
	private JPanel jpUI;
	private JLabel jlLookFeelNote;
	private JLabel jlLookFeel;
	private JComboBox<String> jcbLookFeel;
	private JLabel jlLanguage;
	private JComboBox<LanguageItem> jcbLanguage;
	private JCheckBox jcbLookFeelDecorated;
	private JPanel jpInternetProxy;
	private JRadioButton jrbNoProxy;
	private JRadioButton jrbSystemProxySettings;
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
	private JLabel jlAutoUpdateChecks;
	private JCheckBox jcbEnableAutoUpdateChecks;
	private JSpinner jspAutoUpdateCheckInterval;
	private JLabel jlAutoUpdateChecksDays;

	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private JPanel jpDefaultName;
	private DistinguishedNameChooser distinguishedNameChooser;
	private X500Name distinguishedName;
	private int expiryWarnDays;


	private boolean useCaCertificates;
	private File caCertificatesFile;
	private boolean useWinTrustRootCertificates;
	private boolean enableImportTrustedCertTrustCheck;
	private boolean enableImportCaReplyTrustCheck;
	private PasswordQualityConfig passwordQualityConfig;
	private ArrayList<UIManager.LookAndFeelInfo> lookFeelInfoList = new ArrayList<>();
	private UIManager.LookAndFeelInfo lookFeelInfo;
	private boolean lookFeelDecorated;
	private String language;
	private boolean autoUpdateChecksEnabled;
	private int autoUpdateChecksInterval;

	private String defaultDN;
	private boolean cancelled = false;

	private KeyStoreTableColumns kstColumns;

	private JPanel jpDisplayColumns;
	private JLabel jlDisplayColumns;
	private JCheckBox jcbEnableEntryName;
	private boolean bEnableEntryName;
	private JCheckBox jcbEnableAlgorithm;
	private boolean bEnableAlgorithm;
	private JCheckBox jcbEnableKeySize;
	private boolean bEnableKeySize;
	private JCheckBox jcbEnableCertificateExpiry;
	private boolean bEnableCertificateExpiry;
	private JCheckBox jcbEnableLastModified;
	private boolean bEnableLastModified;
	private JCheckBox jcbEnableCurve;
	private boolean bEnableCurve;
	private JCheckBox jcbEnableSKI;
	private boolean bEnableSKI;
	private JCheckBox jcbEnableAKI;
	private boolean bEnableAKI;
	private JCheckBox jcbEnableIssuerDN;
	private boolean bEnableIssuerDN;
	private JCheckBox jcbEnableIssuerCN;
	private boolean bEnableIssuerCN;
	private JCheckBox jcbEnableSubjectDN;
	private boolean bEnableSubjectDN;
	private JCheckBox jcbEnableSubjectCN;
	private boolean bEnableSubjectCN;
	private JCheckBox jcbEnableIssuerO;
	private boolean bEnableIssuerO;
	private JCheckBox jcbEnableSubjectO;
	private boolean bEnableSubjectO;
	private JLabel jlExpirationWarnDays;
	private JTextField jtfExpirationWarnDays;
	private boolean bColumnsChanged;

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
			String defaultDN, String language, boolean autoUpdateChecksEnabled, int autoUpdateChecksInterval,
			KeyStoreTableColumns kstColumns) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.useCaCertificates = useCaCertificates;
		this.caCertificatesFile = caCertificatesFile;
		this.useWinTrustRootCertificates = useWinTrustedRootCertificates;
		this.enableImportTrustedCertTrustCheck = enableImportTrustedCertTrustCheck;
		this.enableImportCaReplyTrustCheck = enableImportCaReplyTrustCheck;
		this.passwordQualityConfig = passwordQualityConfig;
		this.defaultDN = defaultDN;
		this.language = language;
		this.autoUpdateChecksEnabled = autoUpdateChecksEnabled;
		this.autoUpdateChecksInterval = autoUpdateChecksInterval;
		this.expiryWarnDays =  kstColumns.getExpiryWarnDays();
		this.kstColumns = kstColumns;
		initComponents();
	}

	private void initComponents() {
		initAuthorityCertificatesTab();
		initUserInterfaceTab();
		initInternetProxyTab();
		initDefaultNameTab();
		initDisplayColumnsTab();

		jtpPreferences = new JTabbedPane();
		jtpPreferences.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);

		jtpPreferences.addTab(res.getString("DPreferences.jpAuthorityCertificates.text"), new ImageIcon(getClass()
				.getResource("images/tab_authcerts.png")), jpAuthorityCertificates,
				res.getString("DPreferences.jpAuthorityCertificates.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpUI.text"),
				new ImageIcon(getClass().getResource("images/tab_lookfeel.png")), jpUI,
				res.getString("DPreferences.jpUI.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpInternetProxy.text"),
				new ImageIcon(getClass().getResource("images/tab_internetproxy.png")),
				jpInternetProxy, res.getString("DPreferences.jpInternetProxy.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpDefaultName.text"),
				new ImageIcon(getClass().getResource("images/tab_defaultname.png")),
				jpDefaultName, res.getString("DPreferences.jpDefaultName.tooltip"));

		jtpPreferences.addTab(res.getString("DPreferences.jpDisplayColumns.text"),
				new ImageIcon(getClass().getResource("images/tab_columns.png")),
				jpDisplayColumns, res.getString("DPreferences.jpDisplayColumns.tooltip"));


		jtpPreferences.setBorder(new EmptyBorder(5, 5, 5, 5));

		if (!OperatingSystem.isMacOs()) {
			jtpPreferences.setMnemonicAt(0, res.getString("DPreferences.jpAuthorityCertificates.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(1, res.getString("DPreferences.jpUI.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(2, res.getString("DPreferences.jpInternetProxy.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(3, res.getString("DPreferences.jpDefaultName.mnemonic").charAt(0));
			jtpPreferences.setMnemonicAt(4, res.getString("DPreferences.jpDisplayColumns.mnemonic").charAt(0));
		}

		jbOK = new JButton(res.getString("DPreferences.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
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
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jtpPreferences, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
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

		jlCaCertificatesFile = new JLabel(res.getString("DPreferences.jlCaCertificatesFile.text"));
		jtfCaCertificatesFile = new JTextField(caCertificatesFile.toString(), 25);
		jtfCaCertificatesFile.setToolTipText(res.getString("DPreferences.jtfCaCertificatesFile.tooltip"));
		jtfCaCertificatesFile.setCaretPosition(0);
		jtfCaCertificatesFile.setEditable(false);

		jbBrowseCaCertificatesFile = new JButton(res.getString("DPreferences.jbBrowseCaCertificatesFile.text"));
		PlatformUtil.setMnemonic(jbBrowseCaCertificatesFile,
				res.getString("DPreferences.jbBrowseCaCertificatesFile.mnemonic").charAt(0));
		jbBrowseCaCertificatesFile.setToolTipText(res.getString("DPreferences.jbBrowseCaCertificatesFile.tooltip"));

		jcbUseCaCertificates = new JCheckBox(res.getString("DPreferences.jcbUseCaCertificates.text"), useCaCertificates);
		jcbUseCaCertificates.setToolTipText(res.getString("DPreferences.jcbUseCaCertificates.tooltip"));
		PlatformUtil.setMnemonic(jcbUseCaCertificates, res.getString("DPreferences.jcbUseCaCertificates.mnemonic")
				.charAt(0));

		jcbUseWinTrustedRootCertificates = new JCheckBox(
				res.getString("DPreferences.jcbUseWinTrustRootCertificates.text"), useWinTrustRootCertificates);
		jcbUseWinTrustedRootCertificates.setToolTipText(res
				.getString("DPreferences.jcbUseWinTrustRootCertificates.tooltip"));
		PlatformUtil.setMnemonic(jcbUseWinTrustedRootCertificates,
				res.getString("DPreferences.jcbUseWinTrustRootCertificates.menmonic").charAt(0));


		jlTrustChecks = new JLabel(res.getString("DPreferences.jlTrustChecks.text"));

		jcbEnableImportTrustedCertTrustCheck = new JCheckBox(
				res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.text"),
				enableImportTrustedCertTrustCheck);
		jcbEnableImportTrustedCertTrustCheck.setToolTipText(res
				.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.tooltip"));
		jcbEnableImportTrustedCertTrustCheck.setMnemonic(res.getString(
				"DPreferences.jcbEnableImportTrustedCertTrustCheck.mnemonic").charAt(0));

		jcbEnableImportCaReplyTrustCheck = new JCheckBox(
				res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.text"), enableImportCaReplyTrustCheck);
		jcbEnableImportCaReplyTrustCheck.setToolTipText(res
				.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.tooltip"));
		jcbEnableImportCaReplyTrustCheck.setMnemonic(res.getString(
				"DPreferences.jcbEnableImportCaReplyTrustCheck.mnemonic").charAt(0));

		// layout
		jpAuthorityCertificates = new JPanel();
		jpAuthorityCertificates.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));
		jpAuthorityCertificates.add(jlCaCertificatesFile, "split");
		jpAuthorityCertificates.add(jtfCaCertificatesFile, "");
		jpAuthorityCertificates.add(jbBrowseCaCertificatesFile, "wrap rel");
		if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
			jpAuthorityCertificates.add(jcbUseCaCertificates, "wrap rel");
			jpAuthorityCertificates.add(jcbUseWinTrustedRootCertificates, "wrap para");
		} else {
			jpAuthorityCertificates.add(jcbUseCaCertificates, "wrap para");
		}
		jpAuthorityCertificates.add(jlTrustChecks, "wrap unrel");
		jpAuthorityCertificates.add(jcbEnableImportTrustedCertTrustCheck, "wrap rel");
		jpAuthorityCertificates.add(jcbEnableImportCaReplyTrustCheck, "wrap unrel");


		jbBrowseCaCertificatesFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DPreferences.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DPreferences.this);
				}
			}
		});
	}

	private void initUserInterfaceTab() {

		jlLookFeelNote = new JLabel(res.getString("DPreferences.jlLookFeelNote.text"));
		jlLookFeel = new JLabel(res.getString("DPreferences.jlLookFeel.text"));

		jcbLookFeel = new JComboBox<>();
		jcbLookFeel.setToolTipText(res.getString("DPreferences.jcbLookFeel.tooltip"));

		initLookAndFeelSelection();

		jcbLookFeelDecorated = new JCheckBox(res.getString("DPreferences.jcbLookFeelDecorated.text"),
				JFrame.isDefaultLookAndFeelDecorated());
		jcbLookFeelDecorated.setToolTipText(res.getString("DPreferences.jcbLookFeelDecorated.tooltip"));
		PlatformUtil.setMnemonic(jcbLookFeelDecorated, res.getString("DPreferences.jcbLookFeelDecorated.menmonic")
				.charAt(0));

		jlLanguage = new JLabel(res.getString("DPreferences.jlLanguage.text"));

		jcbLanguage = new JComboBox<>();
		jcbLanguage.setToolTipText(res.getString("DPreferences.jcbLanguage.tooltip"));
		initLanguageSelection();

		jlAutoUpdateChecks = new JLabel(res.getString("DPreferences.jlAutoUpdateChecks.text"));
		jcbEnableAutoUpdateChecks = new JCheckBox(res.getString("DPreferences.jcbEnableAutoUpdateChecks.text"));
		jcbEnableAutoUpdateChecks.setSelected(autoUpdateChecksEnabled);
		SpinnerNumberModel spinnerModel = new SpinnerNumberModel(autoUpdateChecksInterval, 1.0, 999.0, 1.0);
		jspAutoUpdateCheckInterval = new JSpinner(spinnerModel);
		jspAutoUpdateCheckInterval.setEnabled(autoUpdateChecksEnabled);
		jlAutoUpdateChecksDays = new JLabel(res.getString("DPreferences.jlAutoUpdateChecksDays.text"));

		jlPasswordQuality = new JLabel(res.getString("DPreferences.jpPasswordQuality.text"));

		jcbEnablePasswordQuality = new JCheckBox(res.getString("DPreferences.jcbEnablePasswordQuality.text"));
		jcbEnablePasswordQuality.setMnemonic(res.getString("DPreferences.jcbEnablePasswordQuality.mnemonic").charAt(0));
		jcbEnablePasswordQuality.setToolTipText(res.getString("DPreferences.jcbEnablePasswordQuality.tooltip"));

		jcbEnforceMinimumPasswordQuality = new JCheckBox(
				res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.text"));
		jcbEnforceMinimumPasswordQuality.setMnemonic(res.getString(
				"DPreferences.jcbEnforceMinimumPasswordQuality.mnemonic").charAt(0));
		jcbEnforceMinimumPasswordQuality.setToolTipText(res
				.getString("DPreferences.jcbEnforceMinimumPasswordQuality.tooltip"));

		jlMinimumPasswordQuality = new JLabel(res.getString("DPreferences.jlMinimumPasswordQuality.text"));

		jsMinimumPasswordQuality = new JSlider(0, 100);
		jsMinimumPasswordQuality.setPaintLabels(true);
		jsMinimumPasswordQuality.setMajorTickSpacing(25);
		jsMinimumPasswordQuality.setToolTipText(res.getString("DPreferences.jsMinimumPasswordQuality.tooltip"));

		boolean passwordQualityEnabled = passwordQualityConfig.getEnabled();
		boolean passwordQualityEnforced = passwordQualityConfig.getEnforced();
		int minimumPasswordQuality = passwordQualityConfig.getMinimumQuality();

		jcbEnablePasswordQuality.setSelected(passwordQualityEnabled);
		jcbEnforceMinimumPasswordQuality.setSelected(passwordQualityEnforced);
		jsMinimumPasswordQuality.setValue(minimumPasswordQuality);

		jcbEnforceMinimumPasswordQuality.setEnabled(passwordQualityEnabled);

		jlMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);
		jsMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);

		// layout
		jpUI = new JPanel();
		jpUI.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));
		jpUI.add(jlLookFeelNote, "split, span, wrap unrel");
		jpUI.add(jlLookFeel, "");
		jpUI.add(jcbLookFeel, "growx");
		jpUI.add(jcbLookFeelDecorated, "wrap");
		jpUI.add(jlLanguage, "");
		jpUI.add(jcbLanguage, "growx, wrap unrel");
		jpUI.add(jlAutoUpdateChecks, "spanx, split 4");
		jpUI.add(jcbEnableAutoUpdateChecks, "");
		jpUI.add(jspAutoUpdateCheckInterval, "");
		jpUI.add(jlAutoUpdateChecksDays, "wrap unrel");
		jpUI.add(jlPasswordQuality, "spanx, wrap");
		jpUI.add(jcbEnablePasswordQuality, "spanx, wrap");
		jpUI.add(jcbEnforceMinimumPasswordQuality, "spanx, gapx indent, wrap");
		jpUI.add(jlMinimumPasswordQuality, "gapx 4*indent, top, spanx, split 3");
		jpUI.add(jsMinimumPasswordQuality, "wrap");

		jcbEnableAutoUpdateChecks.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				jspAutoUpdateCheckInterval.setEnabled(jcbEnableAutoUpdateChecks.isSelected());
			}
		});

		jcbEnablePasswordQuality.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				jcbEnforceMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected());
				jlMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
				jsMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
			}
		});

		jcbEnforceMinimumPasswordQuality.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				jlMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
				jsMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected()
						&& jcbEnforceMinimumPasswordQuality.isSelected());
			}
		});
	}

	private void initLookAndFeelSelection() {
		// This may contain duplicates
		UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();
		LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();
		TreeSet<String> lookFeelClasses = new TreeSet<>();

		for (UIManager.LookAndFeelInfo lfi : lookFeelInfos) {
			// Avoid duplicates
			if (!lookFeelClasses.contains(lfi.getClassName())) {
				lookFeelClasses.add(lfi.getClassName());

				lookFeelInfoList.add(lfi);
				jcbLookFeel.addItem(lfi.getName());

				// Pre-select current look & feel - compare by class as the look
				// and feel name can differ from the look and feel info name
				if ((currentLookAndFeel != null)
						&& (currentLookAndFeel.getClass().getName().equals(lfi.getClassName()))) {
					this.lookFeelInfo = lfi;
					jcbLookFeel.setSelectedIndex(jcbLookFeel.getItemCount() - 1);
				}
			}
		}
	}

	private void initLanguageSelection() {
		LanguageItem[] languageItems = new LanguageItem[] {
				new LanguageItem("System", ApplicationSettings.SYSTEM_LANGUAGE),
				new LanguageItem("English", "en"),
				new LanguageItem("German", "de"),
				new LanguageItem("French", "fr") };

		for (LanguageItem languageItem : languageItems) {
			jcbLanguage.addItem(languageItem);
			if (languageItem.getIsoCode().equals(language)) {
				jcbLanguage.setSelectedItem(languageItem);
			}
		}
	}

	private void initInternetProxyTab() {
		jrbNoProxy = new JRadioButton(res.getString("DPreferences.jrbNoProxy.text"));
		jrbNoProxy.setToolTipText(res.getString("DPreferences.jrbNoProxy.tooltip"));
		PlatformUtil.setMnemonic(jrbNoProxy, res.getString("DPreferences.jrbNoProxy.mnemonic").charAt(0));

		jrbSystemProxySettings = new JRadioButton(res.getString("DPreferences.jrbSystemProxySettings.text"), true);
		jrbSystemProxySettings.setToolTipText(res.getString("DPreferences.jrbSystemProxySettings.tooltip"));
		PlatformUtil.setMnemonic(jrbSystemProxySettings, res.getString("DPreferences.jrbSystemProxySettings.mnemonic")
				.charAt(0));

		jrbManualProxyConfig = new JRadioButton(res.getString("DPreferences.jrbManualProxyConfig.text"));
		jrbManualProxyConfig.setToolTipText(res.getString("DPreferences.jrbManualProxyConfig.tooltip"));
		PlatformUtil.setMnemonic(jrbManualProxyConfig, res.getString("DPreferences.jrbManualProxyConfig.mnemonic")
				.charAt(0));

		jlHttpHost = new JLabel(res.getString("DPreferences.jlHttpHost.text"));

		jtfHttpHost = new JTextField(20);
		jtfHttpHost.setToolTipText(res.getString("DPreferences.jtfHttpHost.tooltip"));
		jtfHttpHost.setEnabled(false);

		jlHttpPort = new JLabel(res.getString("DPreferences.jlHttpPort.text"));

		jtfHttpPort = new JTextField(5);
		jtfHttpPort.setToolTipText(res.getString("DPreferences.jtfHttpPort.tooltip"));
		jtfHttpPort.setEnabled(false);

		jlHttpsHost = new JLabel(res.getString("DPreferences.jlHttpsHost.text"));

		jtfHttpsHost = new JTextField(20);
		jtfHttpsHost.setToolTipText(res.getString("DPreferences.jtfHttpsHost.tooltip"));
		jtfHttpsHost.setEnabled(false);

		jlHttpsPort = new JLabel(res.getString("DPreferences.jlHttpsPort.text"));

		jtfHttpsPort = new JTextField(5);
		jtfHttpsPort.setToolTipText(res.getString("DPreferences.jtfHttpsPort.tooltip"));
		jtfHttpsPort.setEnabled(false);

		jlSocksHost = new JLabel(res.getString("DPreferences.jlSocksHost.text"));

		jtfSocksHost = new JTextField(20);
		jtfSocksHost.setToolTipText(res.getString("DPreferences.jtfSocksHost.tooltip"));
		jtfSocksHost.setEnabled(false);

		jlSocksPort = new JLabel(res.getString("DPreferences.jlSocksPort.text"));

		jtfSocksPort = new JTextField(5);
		jtfSocksPort.setToolTipText(res.getString("DPreferences.jtfSocksPort.tooltip"));
		jtfSocksPort.setEnabled(false);

		jrbAutomaticProxyConfig = new JRadioButton(res.getString("DPreferences.jrbAutomaticProxyConfig.text"));
		jrbAutomaticProxyConfig.setToolTipText(res.getString("DPreferences.jrbAutomaticProxyConfig.tooltip"));
		PlatformUtil.setMnemonic(jrbAutomaticProxyConfig, res
				.getString("DPreferences.jrbAutomaticProxyConfig.mnemonic").charAt(0));

		jlPacUrl = new JLabel(res.getString("DPreferences.jlPacUrl.text"));

		jtfPacUrl = new JTextField(30);
		jtfPacUrl.setToolTipText(res.getString("DPreferences.jtfPacUrl.tooltip"));
		jtfPacUrl.setEnabled(false);

		ButtonGroup bgProxies = new ButtonGroup();
		bgProxies.add(jrbNoProxy);
		bgProxies.add(jrbSystemProxySettings);
		bgProxies.add(jrbManualProxyConfig);
		bgProxies.add(jrbAutomaticProxyConfig);

		// layout
		jpInternetProxy = new JPanel();
		jpInternetProxy.setLayout(new MigLayout("insets dialog", "20lp[][]", "20lp[][]"));
		jpInternetProxy.add(jrbNoProxy, "left, span, wrap");
		jpInternetProxy.add(jrbSystemProxySettings, "left, span, wrap");
		jpInternetProxy.add(jrbManualProxyConfig, "left, span, wrap");
		jpInternetProxy.add(jlHttpHost, "gap unrel, skip, right");
		jpInternetProxy.add(jtfHttpHost, "");
		jpInternetProxy.add(jlHttpPort, "gap unrel, right");
		jpInternetProxy.add(jtfHttpPort, "wrap");
		jpInternetProxy.add(jlHttpsHost, "gap unrel, skip, right");
		jpInternetProxy.add(jtfHttpsHost, "");
		jpInternetProxy.add(jlHttpsPort, "gap unrel, right");
		jpInternetProxy.add(jtfHttpsPort, "wrap");
		jpInternetProxy.add(jlSocksHost, "gap unrel, skip, right");
		jpInternetProxy.add(jtfSocksHost, "");
		jpInternetProxy.add(jlSocksPort, "gap unrel, right");
		jpInternetProxy.add(jtfSocksPort, "wrap");
		jpInternetProxy.add(jrbAutomaticProxyConfig, "left, span, wrap");
		jpInternetProxy.add(jlPacUrl, "gap unrel, skip, right");
		jpInternetProxy.add(jtfPacUrl, "span, wrap push");

		jrbAutomaticProxyConfig.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				updateProxyControls();
			}
		});

		jrbManualProxyConfig.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				updateProxyControls();
			}
		});

		ProxySelector proxySelector = ProxySelector.getDefault();

		if (proxySelector instanceof SystemProxySelector) {
			jrbSystemProxySettings.setSelected(true);
		} else if (proxySelector instanceof PacProxySelector) {
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

		distinguishedNameChooser = new DistinguishedNameChooser(distinguishedName, true, defaultDN);

		// layout
		jpDefaultName = new JPanel();
		jpDefaultName.setLayout(new MigLayout("insets dialog, fill", "[]", "[]"));
		jpDefaultName.add(distinguishedNameChooser, "left, spanx, wrap para");
	}

	private void initDisplayColumnsTab() {
		bColumnsChanged = false;
		jpDisplayColumns = new JPanel();
		jlDisplayColumns = new JLabel(res.getString("DPreferences.jlDisplayColumns.text"));

		bEnableEntryName = kstColumns.getEnableEntryName();
		jcbEnableEntryName = new JCheckBox(res.getString("DPreferences.jcbEnableEntryName.text"), bEnableEntryName);
		// fix for problem that without entry name a lot of things do not work
		jcbEnableEntryName.setSelected(true);
		jcbEnableEntryName.setEnabled(false);

		bEnableAlgorithm = kstColumns.getEnableAlgorithm();
		jcbEnableAlgorithm = new JCheckBox(res.getString("DPreferences.jcbEnableAlgorithm.text"), bEnableAlgorithm);

		bEnableKeySize = kstColumns.getEnableKeySize();
		jcbEnableKeySize = new JCheckBox(res.getString("DPreferences.jcbEnableKeySize.text"), bEnableKeySize);
		jcbEnableKeySize.setSelected(bEnableKeySize);

		bEnableCurve = kstColumns.getEnableCurve();
		jcbEnableCurve = new JCheckBox(res.getString("DPreferences.jcbEnableCurve.text"), bEnableCurve);
		jcbEnableCurve.setSelected(bEnableCurve);

		bEnableCertificateExpiry = kstColumns.getEnableCertificateExpiry();
		jcbEnableCertificateExpiry = new JCheckBox(res.getString("DPreferences.jcbEnableCertificateExpiry.text"),
				bEnableCertificateExpiry);
		jcbEnableCertificateExpiry.setSelected(bEnableCertificateExpiry);

		bEnableLastModified = kstColumns.getEnableLastModified();
		jcbEnableLastModified = new JCheckBox(res.getString("DPreferences.jcbEnableLastModified.text"),
				bEnableLastModified);
		jcbEnableLastModified.setSelected(bEnableLastModified);

		bEnableSKI = kstColumns.getEnableSKI();
		jcbEnableSKI = new JCheckBox(res.getString("DPreferences.jcbEnableSKI.text"), bEnableSKI);
		jcbEnableSKI.setSelected(bEnableSKI);

		bEnableAKI = kstColumns.getEnableAKI();
		jcbEnableAKI = new JCheckBox(res.getString("DPreferences.jcbEnableAKI.text"), bEnableAKI);
		jcbEnableAKI.setSelected(bEnableAKI);

		bEnableIssuerDN = kstColumns.getEnableIssuerDN();
		jcbEnableIssuerDN = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerDN.text"), bEnableIssuerDN);
		jcbEnableIssuerDN.setSelected(bEnableIssuerDN);

		bEnableSubjectDN = kstColumns.getEnableSubjectDN();
		jcbEnableSubjectDN = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectDN.text"), bEnableSubjectDN);
		jcbEnableSubjectDN.setSelected(bEnableSubjectDN);

		bEnableIssuerCN = kstColumns.getEnableIssuerCN();
		jcbEnableIssuerCN = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerCN.text"), bEnableIssuerCN);
		jcbEnableIssuerCN.setSelected(bEnableIssuerCN);

		bEnableSubjectCN = kstColumns.getEnableSubjectCN();
		jcbEnableSubjectCN = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectCN.text"), bEnableSubjectCN);
		jcbEnableSubjectCN.setSelected(bEnableSubjectCN);

		bEnableIssuerO = kstColumns.getEnableIssuerO();
		jcbEnableIssuerO = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerO.text"), bEnableIssuerO);
		jcbEnableIssuerO.setSelected(bEnableIssuerO);

		bEnableSubjectO = kstColumns.getEnableSubjectO();
		jcbEnableSubjectO = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectO.text"), bEnableSubjectO);
		jcbEnableSubjectO.setSelected(bEnableSubjectO);

		jlExpirationWarnDays = new JLabel(res.getString("DPreferences.jlExpiryWarning.text"));
		jtfExpirationWarnDays = new JTextField();
		jtfExpirationWarnDays.setColumns(3);
		jtfExpirationWarnDays.setText(Integer.toString(expiryWarnDays));

		jpDisplayColumns.setLayout(new MigLayout("insets dialog, fill", "[][]", ""));
		jpDisplayColumns.add(jlDisplayColumns, "left, wrap");
		jpDisplayColumns.add(jcbEnableEntryName, "left");
		jpDisplayColumns.add(jcbEnableAlgorithm, "left, wrap");
		jpDisplayColumns.add(jcbEnableKeySize, "left");
		jpDisplayColumns.add(jcbEnableCurve, "left, wrap");
		jpDisplayColumns.add(jcbEnableCertificateExpiry, "left");
		jpDisplayColumns.add(jcbEnableLastModified, "left, wrap");
		jpDisplayColumns.add(jcbEnableSKI, "left");
		jpDisplayColumns.add(jcbEnableAKI, "left, wrap");
		jpDisplayColumns.add(jcbEnableIssuerDN, "left");
		jpDisplayColumns.add(jcbEnableSubjectDN, "left, wrap");
		jpDisplayColumns.add(jcbEnableIssuerCN, "left");
		jpDisplayColumns.add(jcbEnableSubjectCN, "left, wrap");
		jpDisplayColumns.add(jcbEnableIssuerO, "left");
		jpDisplayColumns.add(jcbEnableSubjectO, "left, wrap");
		jpDisplayColumns.add(jlExpirationWarnDays, "left, spanx, split");
		jpDisplayColumns.add(jtfExpirationWarnDays, "wrap");
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
		storeColumns();
		language = ((LanguageItem) jcbLanguage.getSelectedItem()).getIsoCode();

		autoUpdateChecksEnabled = jcbEnableAutoUpdateChecks.isSelected();
		autoUpdateChecksInterval = ((Number) jspAutoUpdateCheckInterval.getValue()).intValue();

		// These may fail:
		boolean returnValue = storeDefaultDN();
		returnValue &= storeProxyPreferences();

		return returnValue;
	}

	private boolean storeDefaultDN() {
		X500Name dn = distinguishedNameChooser.getDNWithEmptyRdns();
		defaultDN = dn.toString();
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
		} else if (jrbSystemProxySettings.isSelected()) {
			SystemProxySelector systemProxySelector = new SystemProxySelector();

			if (!systemProxySelector.equals(defaultProxySelector)) {
				ProxySelector.setDefault(systemProxySelector);
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

			// Require at least one of the HTTP host or HTTPS host or SOCKS host manual settings
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

	/**
	 * Read the new language setting
	 * @return ISO code of selected language or system (for system default)
	 */
	public String getLanguage() {
		return language;
	}

	public boolean isAutoUpdateChecksEnabled() {
		return autoUpdateChecksEnabled;
	}

	public int getAutoUpdateChecksInterval() {
		return autoUpdateChecksInterval;
	}

	/**
	 * Read the new default DN (RDNs can be empty here)
	 * @return
	 */
	public String getDefaultDN() {
		return defaultDN;
	}

	public KeyStoreTableColumns getColumns() {
		return kstColumns;
	}

	public boolean columnsChanged() {
		return bColumnsChanged;
	}

	private void storeColumns() {
		int ist = kstColumns.getColumns();
		bEnableEntryName = jcbEnableEntryName.isSelected();
		bEnableAlgorithm = jcbEnableAlgorithm.isSelected();
		bEnableKeySize = jcbEnableKeySize.isSelected();
		bEnableCertificateExpiry = jcbEnableCertificateExpiry.isSelected();
		bEnableLastModified = jcbEnableLastModified.isSelected();
		bEnableCurve = jcbEnableCurve.isSelected();
		bEnableSKI = jcbEnableSKI.isSelected();
		bEnableAKI = jcbEnableAKI.isSelected();
		bEnableIssuerDN = jcbEnableIssuerDN.isSelected();
		bEnableSubjectDN = jcbEnableSubjectDN.isSelected();
		bEnableIssuerCN = jcbEnableIssuerCN.isSelected();
		bEnableSubjectCN = jcbEnableSubjectCN.isSelected();
		bEnableIssuerO = jcbEnableIssuerO.isSelected();
		bEnableSubjectO = jcbEnableSubjectO.isSelected();
		try {
			expiryWarnDays = Integer.parseInt(jtfExpirationWarnDays.getText());
		} catch (Exception e) {
			expiryWarnDays = 0;
		}
		kstColumns.setColumns(bEnableEntryName, bEnableAlgorithm, bEnableKeySize, bEnableCertificateExpiry,
				bEnableLastModified, bEnableSKI, bEnableAKI, bEnableIssuerDN, bEnableSubjectDN, bEnableIssuerCN,
				bEnableSubjectCN, bEnableIssuerO, bEnableSubjectO, bEnableCurve, expiryWarnDays);
		bColumnsChanged = (kstColumns.getColumns() != ist);
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
		chooser.setApproveButtonText(res.getString("DPreferences.CaCertificatesKeyStoreFileChooser.button"));

		int rtnValue = chooser.showOpenDialog(this);
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
		bColumnsChanged = false;
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private static class LanguageItem {
		private String displayName;
		private String isoCode;
		public LanguageItem(String displayName, String isoCode) {
			super();
			this.displayName = displayName;
			this.isoCode = isoCode;
		}
		public String getIsoCode() {
			return isoCode;
		}
		@Override
		public String toString() {
			return displayName;
		}
	}

	public static void main(String[] args) throws Exception {
		DPreferences dialog = new DPreferences(new javax.swing.JFrame(), true, new File(""), true, true, true,
				new PasswordQualityConfig(true, true, 100), "", "en", true, 14, new KeyStoreTableColumns());
		DialogViewer.run(dialog);
	}
}
