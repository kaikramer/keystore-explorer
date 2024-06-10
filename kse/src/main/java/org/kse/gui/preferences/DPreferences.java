/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.gui.preferences;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Security;
import java.util.ArrayList;
import java.util.ResourceBundle;
import java.util.TreeSet;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
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
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.LookAndFeel;
import javax.swing.SpinnerNumberModel;
import javax.swing.ToolTipManager;
import javax.swing.UIManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeSelectionModel;

import org.kse.crypto.SecurityProvider;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dnchooser.DistinguishedNameChooser;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.gui.preferences.data.AutoUpdateCheckSettings;
import org.kse.gui.preferences.data.CaCertsSettings;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.preferences.data.LanguageItem;
import org.kse.gui.preferences.data.Pkcs12EncryptionSetting;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.net.IpAddress;
import org.kse.utilities.net.ManualProxySelector;
import org.kse.utilities.net.NoProxySelector;
import org.kse.utilities.net.PacProxySelector;
import org.kse.utilities.net.ProxyAddress;
import org.kse.utilities.net.SystemProxySelector;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to allow the users to configure KeyStore Explorer's preferences.
 */
public class DPreferences extends JEscDialog {

    private static final long serialVersionUID = -3625128197124011083L;
    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

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
    private JLabel jlFileChooser;
    private JCheckBox jcbShowHiddenFiles;
    private JCheckBox jcbShowNativeFileChooser;
    private JCheckBox jcbLookFeelDecorated;
    private JLabel jlPkcs12Encryption;
    private JComboBox<Pkcs12EncryptionSetting> jcbPkcs12Encryption;
    private JLabel jlSnRandomBytes;
    private JSpinner jspSnRandomBytes;
    private JLabel jlSnRandomBytesPostfix;
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

    private DistinguishedNameChooser distinguishedNameChooser;

    private JPanel jpDisplayColumns;
    private JCheckBox jcbEnableEntryName;
    private JCheckBox jcbEnableAlgorithm;
    private JCheckBox jcbEnableKeySize;
    private JCheckBox jcbEnableCertificateValidityStart;
    private JCheckBox jcbEnableCertificateExpiry;
    private JCheckBox jcbEnableLastModified;
    private JCheckBox jcbEnableCurve;
    private JCheckBox jcbEnableSKI;
    private JCheckBox jcbEnableAKI;
    private JCheckBox jcbEnableIssuerDN;
    private JCheckBox jcbEnableIssuerCN;
    private JCheckBox jcbEnableSubjectDN;
    private JCheckBox jcbEnableSubjectCN;
    private JCheckBox jcbEnableIssuerO;
    private JCheckBox jcbEnableSubjectO;
    private JCheckBox jcbEnableSerialNumberHex;
    private JCheckBox jcbEnableSerialNumberDec;
    private JLabel jlExpirationWarnDays;
    private JSpinner jspExpirationWarnDays;
    private boolean bColumnsChanged;
    private JSplitPane jsPane;
    private JScrollPane rightScPane;
    private JScrollPane leftScPane;
    private JPanel rightJPanel;
    private MenuTreeNode[] menus;
    private DefaultMutableTreeNode rootNode;
    private JTree jtree;

    private boolean cancelled = false;

    private final ArrayList<UIManager.LookAndFeelInfo> lookFeelInfoList = new ArrayList<>();

    private final KsePreferences preferences;

    /**
     * Creates a new DPreference dialog.
     *
     * @param parent      The parent frame
     * @param preferences Current state of preferences, probably as loaded from config file
     */
    public DPreferences(JFrame parent, KsePreferences preferences) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        setResizable(true);
        Dimension d = new Dimension(900, 500);
        setMinimumSize(d);
        this.preferences = preferences;
        initComponents();
    }

    /**
     * Create preference menu components for navigation and cardlayout
     */
    public void initComponents() {
        getContentPane().setLayout(new BorderLayout(0, 0));
        jsPane = new JSplitPane();
        jsPane.setDividerSize(20);
        jsPane.setOneTouchExpandable(true);
        jsPane.setResizeWeight(0.2);
        getContentPane().add(jsPane);

        rootNode = new DefaultMutableTreeNode("Root", true);

        // set the properties for leaf nodes.
        menus = new MenuTreeNode[] {
                new MenuTreeNode("DPreferences.jpAuthorityCertificates.text", "images/tab_authcerts.png",
                        "DPreferences.jpAuthorityCertificates.tooltip", "jpCard1"),
                new MenuTreeNode("DPreferences.jpUI.text", "images/tab_lookfeel.png", "DPreferences.jpUI.tooltip",
                        "jpCard2"),
                new MenuTreeNode("DPreferences.jpInternetProxy.text", "images/tab_internetproxy.png",
                        "DPreferences.jpInternetProxy.tooltip", "jpCard3"),
                new MenuTreeNode("DPreferences.jpDefaultName.text", "images/tab_defaultname.png",
                        "DPreferences.jpDefaultName.tooltip", "jpCard4"),
                new MenuTreeNode("DPreferences.jpDisplayColumns.text", "images/tab_columns.png",
                        "DPreferences.jpDisplayColumns.tooltip", "jpCard5") };

        for (MenuTreeNode menu : menus) {
            DefaultMutableTreeNode node = new DefaultMutableTreeNode(menu);
            rootNode.add(node);
        }

        jtree = new JTree(rootNode);
        jtree.setRootVisible(false);
        jtree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        jtree.setCellRenderer(new SettingsTreeCellRenderer());
        jtree.setEditable(false);
        jtree.setSelectionRow(0);

        jtree.getSelectionModel().addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) jtree.getLastSelectedPathComponent();
            Object nodeInfo = selectedNode.getUserObject();
            MenuTreeNode mtn = null;
            String screen = "";
            if (selectedNode.isLeaf()) {
                mtn = (MenuTreeNode) nodeInfo;
            }
            for (MenuTreeNode menu : menus) {
                if (mtn.getName().equals(menu.getName())) {
                    screen = menu.getCard();
                }
            }
            changeScreen(screen);
        });

        // Enable tool tips.
        ToolTipManager.sharedInstance().registerComponent(jtree);

        // set left split pane for navigation menu
        leftScPane = new JScrollPane(jtree);
        jsPane.setLeftComponent(leftScPane);

        // set right split pane for card layout
        rightJPanel = new JPanel();
        rightJPanel.setLayout(new CardLayout(0, 0));
        rightScPane = new JScrollPane(rightJPanel);
        jsPane.setRightComponent(rightScPane);

        jbOK = new JButton(res.getString("DPreferences.jbOK.text"));
        jbCancel = new JButton(res.getString("DPreferences.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        // set dialog pane buttons
        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        jbOK.addActionListener(e -> {
            try {
                CursorUtil.setCursorBusy(DPreferences.this);
                okPressed();
            } finally {
                CursorUtil.setCursorFree(DPreferences.this);
            }
        });

        jbCancel.addActionListener(e -> cancelPressed());

        // action listner for window
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed(); // No save of settings
            }
        });

        // initialize each card layout
        initAuthorityCertificatesCard();
        initUserInterfaceCard();
        initInternetProxyCard();
        initDefaultNameCard();
        initDisplayColumnsCard();

        setTitle(res.getString("DPreferences.Title"));
        getRootPane().setDefaultButton(jbOK);
        pack();
    }

    /**
     * Set the preference screen from the selected navigation menu item
     *
     * @param screen
     */
    private void changeScreen(String screen) {
        ((CardLayout) rightJPanel.getLayout()).show(rightJPanel, screen);
    }

    private void initAuthorityCertificatesCard() {
        CaCertsSettings caCertsSettings = preferences.getCaCertsSettings();

        jlCaCertificatesFile = new JLabel(res.getString("DPreferences.jlCaCertificatesFile.text"));
        jtfCaCertificatesFile = new JTextField(caCertsSettings.getCaCertificatesFile(), 25);
        jtfCaCertificatesFile.setToolTipText(res.getString("DPreferences.jtfCaCertificatesFile.tooltip"));
        jtfCaCertificatesFile.setCaretPosition(0);
        jtfCaCertificatesFile.setEditable(false);

        jbBrowseCaCertificatesFile = new JButton(res.getString("DPreferences.jbBrowseCaCertificatesFile.text"));
        PlatformUtil.setMnemonic(jbBrowseCaCertificatesFile,
                res.getString("DPreferences.jbBrowseCaCertificatesFile.mnemonic").charAt(0));
        jbBrowseCaCertificatesFile.setToolTipText(res.getString("DPreferences.jbBrowseCaCertificatesFile.tooltip"));

        jcbUseCaCertificates = new JCheckBox(res.getString("DPreferences.jcbUseCaCertificates.text"),
                                             caCertsSettings.isUseCaCertificates());
        jcbUseCaCertificates.setToolTipText(res.getString("DPreferences.jcbUseCaCertificates.tooltip"));
        PlatformUtil.setMnemonic(jcbUseCaCertificates,
                res.getString("DPreferences.jcbUseCaCertificates.mnemonic").charAt(0));

        jcbUseWinTrustedRootCertificates =
                new JCheckBox(res.getString("DPreferences.jcbUseWinTrustRootCertificates.text"),
                              caCertsSettings.isUseWindowsTrustedRootCertificates());
        jcbUseWinTrustedRootCertificates
                .setToolTipText(res.getString("DPreferences.jcbUseWinTrustRootCertificates.tooltip"));
        PlatformUtil.setMnemonic(jcbUseWinTrustedRootCertificates,
                res.getString("DPreferences.jcbUseWinTrustRootCertificates.menmonic").charAt(0));

        jlTrustChecks = new JLabel(res.getString("DPreferences.jlTrustChecks.text"));

        jcbEnableImportTrustedCertTrustCheck = new JCheckBox(
                res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.text"),
                caCertsSettings.isImportTrustedCertTrustCheckEnabled());
        jcbEnableImportTrustedCertTrustCheck
                .setToolTipText(res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.tooltip"));
        jcbEnableImportTrustedCertTrustCheck
                .setMnemonic(res.getString("DPreferences.jcbEnableImportTrustedCertTrustCheck.mnemonic").charAt(0));

        jcbEnableImportCaReplyTrustCheck =
                new JCheckBox(res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.text"),
                              caCertsSettings.isImportCaReplyTrustCheckEnabled());
        jcbEnableImportCaReplyTrustCheck
                .setToolTipText(res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.tooltip"));
        jcbEnableImportCaReplyTrustCheck
                .setMnemonic(res.getString("DPreferences.jcbEnableImportCaReplyTrustCheck.mnemonic").charAt(0));

        // layout
        jpAuthorityCertificates = new JPanel();
        rightJPanel.add(jpAuthorityCertificates, "jpCard1");
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

        jbBrowseCaCertificatesFile.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DPreferences.this);
                browsePressed();
            } finally {
                CursorUtil.setCursorFree(DPreferences.this);
            }
        });

    }

    private void initUserInterfaceCard() {
        jlLookFeelNote = new JLabel(res.getString("DPreferences.jlLookFeelNote.text"));
        jlLookFeel = new JLabel(res.getString("DPreferences.jlLookFeel.text"));

        jcbLookFeel = new JComboBox<>();
        jcbLookFeel.setToolTipText(res.getString("DPreferences.jcbLookFeel.tooltip"));

        initLookAndFeelSelection();

        jcbLookFeelDecorated = new JCheckBox(res.getString("DPreferences.jcbLookFeelDecorated.text"),
                JFrame.isDefaultLookAndFeelDecorated());
        jcbLookFeelDecorated.setToolTipText(res.getString("DPreferences.jcbLookFeelDecorated.tooltip"));
        PlatformUtil.setMnemonic(jcbLookFeelDecorated,
                res.getString("DPreferences.jcbLookFeelDecorated.menmonic").charAt(0));

        jlLanguage = new JLabel(res.getString("DPreferences.jlLanguage.text"));

        jcbLanguage = new JComboBox<>();
        jcbLanguage.setToolTipText(res.getString("DPreferences.jcbLanguage.tooltip"));
        initLanguageSelection();

        jlAutoUpdateChecks = new JLabel(res.getString("DPreferences.jlAutoUpdateChecks.text"));
        jcbEnableAutoUpdateChecks = new JCheckBox(res.getString("DPreferences.jcbEnableAutoUpdateChecks.text"));
        AutoUpdateCheckSettings autoUpdateCheckSettings = preferences.getAutoUpdateCheckSettings();
        jcbEnableAutoUpdateChecks.setSelected(autoUpdateCheckSettings.isEnabled());
        var spinnerModel = new SpinnerNumberModel(autoUpdateCheckSettings.getCheckInterval(), 1.0, 999.0, 1.0);
        jspAutoUpdateCheckInterval = new JSpinner(spinnerModel);
        jspAutoUpdateCheckInterval.setEnabled(autoUpdateCheckSettings.isEnabled());
        jlAutoUpdateChecksDays = new JLabel(res.getString("DPreferences.jlAutoUpdateChecksDays.text"));

        jlPasswordQuality = new JLabel(res.getString("DPreferences.jpPasswordQuality.text"));

        jcbEnablePasswordQuality = new JCheckBox(res.getString("DPreferences.jcbEnablePasswordQuality.text"));
        jcbEnablePasswordQuality.setMnemonic(res.getString("DPreferences.jcbEnablePasswordQuality.mnemonic").charAt(0));
        jcbEnablePasswordQuality.setToolTipText(res.getString("DPreferences.jcbEnablePasswordQuality.tooltip"));

        jcbEnforceMinimumPasswordQuality = new JCheckBox(
                res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.text"));
        jcbEnforceMinimumPasswordQuality
                .setMnemonic(res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.mnemonic").charAt(0));
        jcbEnforceMinimumPasswordQuality
                .setToolTipText(res.getString("DPreferences.jcbEnforceMinimumPasswordQuality.tooltip"));

        jlMinimumPasswordQuality = new JLabel(res.getString("DPreferences.jlMinimumPasswordQuality.text"));

        jsMinimumPasswordQuality = new JSlider(0, 100);
        jsMinimumPasswordQuality.setPaintLabels(true);
        jsMinimumPasswordQuality.setMajorTickSpacing(25);
        jsMinimumPasswordQuality.setToolTipText(res.getString("DPreferences.jsMinimumPasswordQuality.tooltip"));

        boolean passwordQualityEnabled = preferences.getPasswordQualityConfig().getEnabled();
        boolean passwordQualityEnforced = preferences.getPasswordQualityConfig().getEnforced();
        int minimumPasswordQuality = preferences.getPasswordQualityConfig().getMinimumQuality();

        jcbEnablePasswordQuality.setSelected(passwordQualityEnabled);
        jcbEnforceMinimumPasswordQuality.setSelected(passwordQualityEnforced);
        jsMinimumPasswordQuality.setValue(minimumPasswordQuality);

        jcbEnforceMinimumPasswordQuality.setEnabled(passwordQualityEnabled);

        jlMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);
        jsMinimumPasswordQuality.setEnabled(passwordQualityEnabled && passwordQualityEnforced);

        jlFileChooser = new JLabel(res.getString("DPreferences.jlFileChooser.text"));

        jcbShowHiddenFiles = new JCheckBox(res.getString("DPreferences.jcbShowHiddenFiles.text"));
        jcbShowHiddenFiles.setSelected(preferences.isShowHiddenFilesEnabled());

        jcbShowNativeFileChooser = new JCheckBox(res.getString("DPreferences.jcbShowNativeFileChooser.text"));
        jcbShowNativeFileChooser.setSelected(preferences.isNativeFileChooserEnabled());

        jlPkcs12Encryption  = new JLabel(res.getString("DPreferences.jlPkcs12Encryption.text"));
        Pkcs12EncryptionSetting.setResourceBundle(res);
        jcbPkcs12Encryption = new JComboBox<>(Pkcs12EncryptionSetting.values());
        jcbPkcs12Encryption.setSelectedItem(preferences.getPkcs12EncryptionSetting());
        jcbPkcs12Encryption.setToolTipText(res.getString("DPreferences.jcbPkcs12Encryption.tooltip"));

        jlSnRandomBytes = new JLabel(res.getString("DPreferences.jlSnRandomBytes.text"));
        var snSpinnerModel = new SpinnerNumberModel(preferences.getSerialNumberLengthInBytes(), 8.0, 20.0, 1.0);
        jspSnRandomBytes = new JSpinner(snSpinnerModel);
        JSpinner.DefaultEditor editor = ( JSpinner.DefaultEditor ) jspSnRandomBytes.getEditor();
        editor.getTextField().setEnabled(true);
        editor.getTextField().setEditable(false);
        jspSnRandomBytes.setToolTipText(res.getString("DPreferences.jlSnRandomBytes.tooltip"));
        jlSnRandomBytesPostfix = new JLabel(res.getString("DPreferences.jlSnRandomBytesPostfix.text"));

        // layout
        jpUI = new JPanel();
        rightJPanel.add(jpUI, "jpCard2");
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
        jpUI.add(jlFileChooser, "wrap");
        jpUI.add(jcbShowHiddenFiles, "spanx, gapx indent, wrap rel");
        jpUI.add(jcbShowNativeFileChooser, "spanx, gapx indent, wrap unrel");
        jpUI.add(jlPkcs12Encryption, "");
        jpUI.add(jcbPkcs12Encryption, "spanx, wrap unrel");
        jpUI.add(jlSnRandomBytes, "");
        jpUI.add(jspSnRandomBytes, "split 2");
        jpUI.add(jlSnRandomBytesPostfix, "");

        jcbEnableAutoUpdateChecks
                .addItemListener(evt -> jspAutoUpdateCheckInterval.setEnabled(jcbEnableAutoUpdateChecks.isSelected()));

        jcbEnablePasswordQuality.addItemListener(evt -> {
            jcbEnforceMinimumPasswordQuality.setEnabled(jcbEnablePasswordQuality.isSelected());
            jlMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
            jsMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
        });

        jcbEnforceMinimumPasswordQuality.addItemListener(evt -> {
            jlMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
            jsMinimumPasswordQuality
                    .setEnabled(jcbEnablePasswordQuality.isSelected() && jcbEnforceMinimumPasswordQuality.isSelected());
        });
    }

    private void initInternetProxyCard() {
        jrbNoProxy = new JRadioButton(res.getString("DPreferences.jrbNoProxy.text"));
        jrbNoProxy.setToolTipText(res.getString("DPreferences.jrbNoProxy.tooltip"));
        PlatformUtil.setMnemonic(jrbNoProxy, res.getString("DPreferences.jrbNoProxy.mnemonic").charAt(0));

        jrbSystemProxySettings = new JRadioButton(res.getString("DPreferences.jrbSystemProxySettings.text"), true);
        jrbSystemProxySettings.setToolTipText(res.getString("DPreferences.jrbSystemProxySettings.tooltip"));
        PlatformUtil.setMnemonic(jrbSystemProxySettings,
                res.getString("DPreferences.jrbSystemProxySettings.mnemonic").charAt(0));

        jrbManualProxyConfig = new JRadioButton(res.getString("DPreferences.jrbManualProxyConfig.text"));
        jrbManualProxyConfig.setToolTipText(res.getString("DPreferences.jrbManualProxyConfig.tooltip"));
        PlatformUtil.setMnemonic(jrbManualProxyConfig,
                res.getString("DPreferences.jrbManualProxyConfig.mnemonic").charAt(0));

        jlHttpHost = new JLabel(res.getString("DPreferences.jlHttpHost.text"));

        jtfHttpHost = new JTextField(20);
        jtfHttpHost.setToolTipText(res.getString("DPreferences.jtfHttpHost.tooltip"));
        jtfHttpHost.setEnabled(false);
        jtfHttpHost.setText(preferences.getProxySettings().getHttpHost());
        jtfHttpHost.setCaretPosition(0);

        jlHttpPort = new JLabel(res.getString("DPreferences.jlHttpPort.text"));

        jtfHttpPort = new JTextField(5);
        jtfHttpPort.setToolTipText(res.getString("DPreferences.jtfHttpPort.tooltip"));
        jtfHttpPort.setEnabled(false);
        jtfHttpPort.setText("" + preferences.getProxySettings().getHttpPort());
        jtfHttpPort.setCaretPosition(0);

        jlHttpsHost = new JLabel(res.getString("DPreferences.jlHttpsHost.text"));

        jtfHttpsHost = new JTextField(20);
        jtfHttpsHost.setToolTipText(res.getString("DPreferences.jtfHttpsHost.tooltip"));
        jtfHttpsHost.setEnabled(false);
        jtfHttpsHost.setText(preferences.getProxySettings().getHttpsHost());
        jtfHttpsHost.setCaretPosition(0);

        jlHttpsPort = new JLabel(res.getString("DPreferences.jlHttpsPort.text"));

        jtfHttpsPort = new JTextField(5);
        jtfHttpsPort.setToolTipText(res.getString("DPreferences.jtfHttpsPort.tooltip"));
        jtfHttpsPort.setEnabled(false);
        jtfHttpsPort.setText("" + preferences.getProxySettings().getHttpsPort());
        jtfHttpsPort.setCaretPosition(0);

        jlSocksHost = new JLabel(res.getString("DPreferences.jlSocksHost.text"));

        jtfSocksHost = new JTextField(20);
        jtfSocksHost.setToolTipText(res.getString("DPreferences.jtfSocksHost.tooltip"));
        jtfSocksHost.setEnabled(false);
        jtfSocksHost.setText(preferences.getProxySettings().getSocksHost());
        jtfSocksHost.setCaretPosition(0);

        jlSocksPort = new JLabel(res.getString("DPreferences.jlSocksPort.text"));

        jtfSocksPort = new JTextField(5);
        jtfSocksPort.setToolTipText(res.getString("DPreferences.jtfSocksPort.tooltip"));
        jtfSocksPort.setEnabled(false);
        jtfSocksPort.setText("" + preferences.getProxySettings().getSocksPort());
        jtfSocksPort.setCaretPosition(0);

        jrbAutomaticProxyConfig = new JRadioButton(res.getString("DPreferences.jrbAutomaticProxyConfig.text"));
        jrbAutomaticProxyConfig.setToolTipText(res.getString("DPreferences.jrbAutomaticProxyConfig.tooltip"));
        PlatformUtil.setMnemonic(jrbAutomaticProxyConfig,
                res.getString("DPreferences.jrbAutomaticProxyConfig.mnemonic").charAt(0));

        jlPacUrl = new JLabel(res.getString("DPreferences.jlPacUrl.text"));

        jtfPacUrl = new JTextField(30);
        jtfPacUrl.setToolTipText(res.getString("DPreferences.jtfPacUrl.tooltip"));
        jtfPacUrl.setEnabled(false);
        jtfPacUrl.setText(preferences.getProxySettings().getPacUrl());

        ButtonGroup bgProxies = new ButtonGroup();
        bgProxies.add(jrbNoProxy);
        bgProxies.add(jrbSystemProxySettings);
        bgProxies.add(jrbManualProxyConfig);
        bgProxies.add(jrbAutomaticProxyConfig);

        // layout
        jpInternetProxy = new JPanel();
        rightJPanel.add(jpInternetProxy, "jpCard3");
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

        jrbAutomaticProxyConfig.addItemListener(evt -> updateProxyControls());

        jrbManualProxyConfig.addItemListener(evt -> updateProxyControls());

        ProxySelector proxySelector = ProxySelector.getDefault();
        if (proxySelector instanceof SystemProxySelector) {
            jrbSystemProxySettings.setSelected(true);
        } else if (proxySelector instanceof PacProxySelector) {
            jrbAutomaticProxyConfig.setSelected(true);
        } else if (proxySelector instanceof ManualProxySelector) {
            jrbManualProxyConfig.setSelected(true);
        } else {
            jrbNoProxy.setSelected(true);
        }
    }

    private void initDefaultNameCard() {
        distinguishedNameChooser = new DistinguishedNameChooser(null, true, preferences.getDefaultSubjectDN());

        // layout
        rightJPanel.add(distinguishedNameChooser, "jpCard4");
    }

    private void initDisplayColumnsCard() {
        bColumnsChanged = false;
        KeyStoreTableColumns kstColumns = preferences.getKeyStoreTableColumns();

        boolean bEnableEntryName = kstColumns.getEnableEntryName();
        jcbEnableEntryName = new JCheckBox(res.getString("DPreferences.jcbEnableEntryName.text"), bEnableEntryName);
        // fix for problem that without entry name a lot of things do not work
        jcbEnableEntryName.setSelected(true);
        jcbEnableEntryName.setEnabled(false);

        boolean bEnableAlgorithm = kstColumns.getEnableAlgorithm();
        jcbEnableAlgorithm = new JCheckBox(res.getString("DPreferences.jcbEnableAlgorithm.text"), bEnableAlgorithm);

        boolean bEnableKeySize = kstColumns.getEnableKeySize();
        jcbEnableKeySize = new JCheckBox(res.getString("DPreferences.jcbEnableKeySize.text"), bEnableKeySize);
        jcbEnableKeySize.setSelected(bEnableKeySize);

        boolean bEnableCurve = kstColumns.getEnableCurve();
        jcbEnableCurve = new JCheckBox(res.getString("DPreferences.jcbEnableCurve.text"), bEnableCurve);
        jcbEnableCurve.setSelected(bEnableCurve);

        boolean bEnableCertificateValidityStart = kstColumns.getEnableCertificateValidityStart();
        jcbEnableCertificateValidityStart = new JCheckBox(res.getString(
                "DPreferences.jcbEnableCertificateValidityStart.text"), bEnableCertificateValidityStart);
        jcbEnableCertificateValidityStart.setSelected(bEnableCertificateValidityStart);

        boolean bEnableCertificateExpiry = kstColumns.getEnableCertificateExpiry();
        jcbEnableCertificateExpiry = new JCheckBox(res.getString("DPreferences.jcbEnableCertificateExpiry.text"),
                bEnableCertificateExpiry);
        jcbEnableCertificateExpiry.setSelected(bEnableCertificateExpiry);

        boolean bEnableLastModified = kstColumns.getEnableLastModified();
        jcbEnableLastModified = new JCheckBox(res.getString("DPreferences.jcbEnableLastModified.text"),
                bEnableLastModified);
        jcbEnableLastModified.setSelected(bEnableLastModified);

        boolean bEnableSKI = kstColumns.getEnableSKI();
        jcbEnableSKI = new JCheckBox(res.getString("DPreferences.jcbEnableSKI.text"), bEnableSKI);
        jcbEnableSKI.setSelected(bEnableSKI);

        boolean bEnableAKI = kstColumns.getEnableAKI();
        jcbEnableAKI = new JCheckBox(res.getString("DPreferences.jcbEnableAKI.text"), bEnableAKI);
        jcbEnableAKI.setSelected(bEnableAKI);

        boolean bEnableIssuerDN = kstColumns.getEnableIssuerDN();
        jcbEnableIssuerDN = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerDN.text"), bEnableIssuerDN);
        jcbEnableIssuerDN.setSelected(bEnableIssuerDN);

        boolean bEnableSubjectDN = kstColumns.getEnableSubjectDN();
        jcbEnableSubjectDN = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectDN.text"), bEnableSubjectDN);
        jcbEnableSubjectDN.setSelected(bEnableSubjectDN);

        boolean bEnableIssuerCN = kstColumns.getEnableIssuerCN();
        jcbEnableIssuerCN = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerCN.text"), bEnableIssuerCN);
        jcbEnableIssuerCN.setSelected(bEnableIssuerCN);

        boolean bEnableSubjectCN = kstColumns.getEnableSubjectCN();
        jcbEnableSubjectCN = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectCN.text"), bEnableSubjectCN);
        jcbEnableSubjectCN.setSelected(bEnableSubjectCN);

        boolean bEnableIssuerO = kstColumns.getEnableIssuerO();
        jcbEnableIssuerO = new JCheckBox(res.getString("DPreferences.jcbEnableIssuerO.text"), bEnableIssuerO);
        jcbEnableIssuerO.setSelected(bEnableIssuerO);

        boolean bEnableSubjectO = kstColumns.getEnableSubjectO();
        jcbEnableSubjectO = new JCheckBox(res.getString("DPreferences.jcbEnableSubjectO.text"), bEnableSubjectO);
        jcbEnableSubjectO.setSelected(bEnableSubjectO);

        boolean bEnableSerialNumberHex = kstColumns.getEnableSerialNumberHex();
        jcbEnableSerialNumberHex = new JCheckBox(res.getString("DPreferences.jcbEnableSerialNumberHex.text"),
                bEnableSerialNumberHex);
        jcbEnableSerialNumberHex.setSelected(bEnableSerialNumberHex);

        boolean bEnableSerialNumberDec = kstColumns.getEnableSerialNumberDec();
        jcbEnableSerialNumberDec = new JCheckBox(res.getString("DPreferences.jcbEnableSerialNumberDec.text"),
                bEnableSerialNumberDec);
        jcbEnableSerialNumberDec.setSelected(bEnableSerialNumberDec);

        jlExpirationWarnDays = new JLabel(res.getString("DPreferences.jlExpiryWarning.text"));
        var spinnerNumberModel = new SpinnerNumberModel(preferences.getExpiryWarnDays(), 0, 90, 1);
        jspExpirationWarnDays = new JSpinner(spinnerNumberModel);
        JSpinner.DefaultEditor editor = ( JSpinner.DefaultEditor ) jspExpirationWarnDays.getEditor();
        editor.getTextField().setEnabled(true);
        editor.getTextField().setEditable(false);

        // layout
        jpDisplayColumns = new JPanel();
        rightJPanel.add(jpDisplayColumns, "jpCard5");
        jpDisplayColumns.setLayout(new MigLayout("insets dialog", "20lp[]20lp[]", "20lp[]rel[]"));
        jpDisplayColumns.add(jcbEnableEntryName, "left");
        jpDisplayColumns.add(jcbEnableAlgorithm, "left, wrap");
        jpDisplayColumns.add(jcbEnableKeySize, "left");
        jpDisplayColumns.add(jcbEnableCurve, "left, wrap");
        jpDisplayColumns.add(jcbEnableCertificateValidityStart, "left");
        jpDisplayColumns.add(jcbEnableCertificateExpiry, "left, wrap");
        jpDisplayColumns.add(jcbEnableLastModified, "left");
        jpDisplayColumns.add(jcbEnableSKI, "left, wrap");
        jpDisplayColumns.add(jcbEnableAKI, "left");
        jpDisplayColumns.add(jcbEnableIssuerDN, "left, wrap");
        jpDisplayColumns.add(jcbEnableSubjectDN, "left");
        jpDisplayColumns.add(jcbEnableIssuerCN, "left, wrap");
        jpDisplayColumns.add(jcbEnableSubjectCN, "left");
        jpDisplayColumns.add(jcbEnableIssuerO, "left, wrap");
        jpDisplayColumns.add(jcbEnableSubjectO, "left");
        jpDisplayColumns.add(jcbEnableSerialNumberHex, "left, wrap");
        jpDisplayColumns.add(jcbEnableSerialNumberDec, "left, wrap para");
        jpDisplayColumns.add(jlExpirationWarnDays, "left, spanx, split");
        jpDisplayColumns.add(jspExpirationWarnDays, "wrap");
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
                    jcbLookFeel.setSelectedIndex(jcbLookFeel.getItemCount() - 1);
                }
            }
        }
    }

    private void updateProxyControls() {
        jtfHttpHost.setEnabled(jrbManualProxyConfig.isSelected());
        jtfHttpPort.setEnabled(jrbManualProxyConfig.isSelected());
        jtfHttpsHost.setEnabled(jrbManualProxyConfig.isSelected());
        jtfHttpsPort.setEnabled(jrbManualProxyConfig.isSelected());
        jtfSocksHost.setEnabled(jrbManualProxyConfig.isSelected());
        jtfSocksPort.setEnabled(jrbManualProxyConfig.isSelected());
        jtfPacUrl.setEnabled(jrbAutomaticProxyConfig.isSelected());
    }

    private boolean storeProxyPreferences() {
        // Store current proxy selector - compare with new one to see if default needs updated
        ProxySelector defaultProxySelector = ProxySelector.getDefault();

        // set no proxy
        if (jrbNoProxy.isSelected()) {
            NoProxySelector noProxySelector = new NoProxySelector();
            if (!noProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(noProxySelector);
            }
        }

        // set system proxy
        if (jrbSystemProxySettings.isSelected()) {
            SystemProxySelector systemProxySelector = new SystemProxySelector();
            if (!systemProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(systemProxySelector);
            }
        }

        // set manual proxy
        if (jrbManualProxyConfig.isSelected()) {
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
            if ((httpHost.isEmpty()) && (httpsHost.isEmpty()) && (socksHost.isEmpty())) {
                JOptionPane.showMessageDialog(this, res.getString("DPreferences.ManualConfigReq.message"), getTitle(),
                        JOptionPane.WARNING_MESSAGE);
                return false;
            }

            // check http
            if (!httpHost.isEmpty()) {
                if (!IpAddress.isValidPort(httpPortStr) || httpPortStr.isEmpty()) {
                    JOptionPane.showMessageDialog(this, res.getString("DPreferences.PortReqHttp.message"), getTitle(),
                            JOptionPane.WARNING_MESSAGE);
                    return false;
                }
                int httpPort = Integer.parseInt(httpPortStr);
                httpProxyAddress = new ProxyAddress(httpHost, httpPort);
            }

            // check https
            if (!httpsHost.isEmpty()) {
                if (!IpAddress.isValidPort(httpsPortStr) || httpsPortStr.isEmpty()) {
                    JOptionPane.showMessageDialog(this, res.getString("DPreferences.PortReqHttps.message"), getTitle(),
                            JOptionPane.WARNING_MESSAGE);
                    return false;
                }
                int httpsPort = Integer.parseInt(httpsPortStr);
                httpsProxyAddress = new ProxyAddress(httpsHost, httpsPort);
            }

            // check socks
            if (!socksHost.isEmpty()) {
                if (!IpAddress.isValidPort(socksPortStr) || socksPortStr.isEmpty()) {
                    JOptionPane.showMessageDialog(this, res.getString("DPreferences.PortReqSocks.message"), getTitle(),
                            JOptionPane.WARNING_MESSAGE);
                    return false;
                }
                int socksPort = Integer.parseInt(socksPortStr);
                socksProxyAddress = new ProxyAddress(socksHost, socksPort);
            }
            ManualProxySelector manualProxySelector = new ManualProxySelector(httpProxyAddress, httpsProxyAddress, null,
                    socksProxyAddress);
            if (!manualProxySelector.equals(defaultProxySelector)) {
                ProxySelector.setDefault(manualProxySelector);
            }
        }

        // check automatic proxy
        if (jrbAutomaticProxyConfig.isSelected()) {
            String pacUrl = jtfPacUrl.getText().trim();
            if (pacUrl.isEmpty()) {
                JOptionPane.showMessageDialog(this, res.getString("DPreferences.PacUrlReq.message"), getTitle(),
                        JOptionPane.WARNING_MESSAGE);
                return false;
            }
            PacProxySelector pacProxySelector = null;
            try {
                pacProxySelector = new PacProxySelector(new URI(pacUrl));
            } catch (URISyntaxException e) {
                JOptionPane.showMessageDialog(this, res.getString("DPreferences.PacUrlReq.message"), getTitle(),
                        JOptionPane.WARNING_MESSAGE);
                return false;
            }
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
        return jcbUseCaCertificates.isSelected();
    }

    /**
     * Get the chosen CA Certificates KeyStore file.
     *
     * @return The chosen CA Certificates KeyStore file
     */
    public File getCaCertificatesFile() {
        return new File(jtfCaCertificatesFile.getText());
    }

    /**
     * Get whether or not the usage of Windows Trusted Root Certificates has been
     * chosen.
     *
     * @return True if it has, false otherwise
     */
    public boolean getUseWinTrustRootCertificates() {
        if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
            return jcbUseWinTrustedRootCertificates.isSelected();
        }
        return false;
    }

    /**
     * Get whether or not trust checks are enabled when importing Trusted
     * Certificates.
     *
     * @return True if they are, false otherwise
     */
    public boolean getEnableImportTrustedCertTrustCheck() {
        return jcbEnableImportTrustedCertTrustCheck.isSelected();
    }

    /**
     * Get whether or not trust checks are enabled when importing CA Replies.
     *
     * @return True if they are, false otherwise
     */
    public boolean getEnableImportCaReplyTrustCheck() {
        return jcbEnableImportCaReplyTrustCheck.isSelected();
    }

    /**
     * Get the chosen password quality confiruration settings.
     *
     * @return Password quality configuration settings
     */
    public PasswordQualityConfig getPasswordQualityConfig() {
        return new PasswordQualityConfig(jcbEnablePasswordQuality.isSelected(),
                                         jcbEnforceMinimumPasswordQuality.isSelected(),
                                         jsMinimumPasswordQuality.getValue());
    }

    /**
     * Get the chosen look & feel information.
     *
     * @return The chosen look & feel information
     */
    public UIManager.LookAndFeelInfo getLookFeelInfo() {
        int selectedIndex = jcbLookFeel.getSelectedIndex();
        return lookFeelInfoList.get(selectedIndex);
    }

    /**
     * Get whether or not the look & feel should be used for window decoration.
     *
     * @return True id it should, false otherwise.
     */
    public boolean getLookFeelDecoration() {
        return jcbLookFeelDecorated.isSelected();
    }

    /**
     * Read the new language setting
     *
     * @return ISO code of selected language or system (for system default)
     */
    public String getLanguage() {
        return ((LanguageItem) jcbLanguage.getSelectedItem()).getIsoCode();
    }

    /**
     * Read status of show hidden files
     *
     * @return True if show hidden files is enabled
     */
    public boolean isShowHiddenFilesEnabled() {
        return jcbShowHiddenFiles.isSelected();
    }

    /**
     * Get value of "show native file chooser" option
     *
     * @return True if show native file chooser is enabled
     */
    public boolean isNativeFileChooserEnabled() {
        return jcbShowNativeFileChooser.isSelected();
    }

    /**
     * Read enable status of check auto update
     *
     * @return True if auto update is enabled
     */
    public boolean isAutoUpdateChecksEnabled() {
        return jcbEnableAutoUpdateChecks.isSelected();
    }

    /**
     * Read interval of check auto update
     *
     * @return Auto update interval check
     */
    public int getAutoUpdateChecksInterval() {
        return ((Number) jspAutoUpdateCheckInterval.getValue()).intValue();
    }

    /**
     * Read the new default DN (RDNs can be empty here)
     *
     * @return Default DN
     */
    public String getDefaultDN() {
        return distinguishedNameChooser.getDNWithEmptyRdns().toString();
    }

    /**
     * Get columns list for main table
     *
     * @return Columns config
     */
    public KeyStoreTableColumns getColumns() {
        var newKstColumns = new KeyStoreTableColumns();
        newKstColumns.setEnableEntryName(jcbEnableEntryName.isSelected());
        newKstColumns.setEnableAlgorithm(jcbEnableAlgorithm.isSelected());
        newKstColumns.setEnableKeySize(jcbEnableKeySize.isSelected());
        newKstColumns.setEnableCertificateValidityStart(jcbEnableCertificateValidityStart.isSelected());
        newKstColumns.setEnableCertificateExpiry(jcbEnableCertificateExpiry.isSelected());
        newKstColumns.setEnableLastModified(jcbEnableLastModified.isSelected());
        newKstColumns.setEnableCurve(jcbEnableCurve.isSelected());
        newKstColumns.setEnableSKI(jcbEnableSKI.isSelected());
        newKstColumns.setEnableAKI(jcbEnableAKI.isSelected());
        newKstColumns.setEnableIssuerDN(jcbEnableIssuerDN.isSelected());
        newKstColumns.setEnableSubjectDN(jcbEnableSubjectDN.isSelected());
        newKstColumns.setEnableIssuerCN(jcbEnableIssuerCN.isSelected());
        newKstColumns.setEnableSubjectCN(jcbEnableSubjectCN.isSelected());
        newKstColumns.setEnableIssuerO(jcbEnableIssuerO.isSelected());
        newKstColumns.setEnableSubjectO(jcbEnableSubjectO.isSelected());
        newKstColumns.setEnableSerialNumberHex(jcbEnableSerialNumberHex.isSelected());
        newKstColumns.setEnableSerialNumberDec(jcbEnableSerialNumberDec.isSelected());
        return newKstColumns;
    }

    /**
     * Get number of days before certificate expiration warnings in the main table are shown in advance
     * @return Expiry warn
     */
    public int getExpiryWarnDays() {
        return ((Number) jspExpirationWarnDays.getValue()).intValue();
    }

    /**
     * Get PKCS12 encryption settings
     * @return P12 encryption settings
     */
    public Pkcs12EncryptionSetting getPkcs12EncryptionSetting() {
        return (Pkcs12EncryptionSetting) jcbPkcs12Encryption.getSelectedItem();
    }

    /**
     * Returns length of serial number random bytes
     *
     * @return serial number random bytes
     */
    public int getSerialNumberLengthInBytes() {
        return ((Number) jspSnRandomBytes.getValue()).intValue();
    }

    /**
     * Check if columns have changed
     *
     * @return True if changed
     */
    public boolean columnsChanged() {
        return !preferences.getKeyStoreTableColumns().equals(getColumns());
    }

    /**
     * Was the dialog cancelled (ie were no settings made).
     *
     * @return True if it was cancelled
     */
    public boolean wasCancelled() {
        return cancelled;
    }

    private void browsePressed() {
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
        File caCertsFile = new File(preferences.getCaCertsSettings().getCaCertificatesFile());

        if ((caCertsFile.getParentFile() != null) && (caCertsFile.getParentFile().exists())) {
            chooser.setCurrentDirectory(caCertsFile.getParentFile());
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

    /**
     * Validate store preferences Call close dialog method
     */
    private void okPressed() {
        if (storeProxyPreferences()) {
            closeDialog();
        }
    }

    /**
     * Call the close dialog method
     */
    private void cancelPressed() {
        cancelled = true;
        bColumnsChanged = false;
        closeDialog();
    }

    /**
     * Close dialog method dispose of window
     */
    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    private void initLanguageSelection() {
        LanguageItem[] languageItems = new LanguageItem[] {
                new LanguageItem("System", LanguageItem.SYSTEM_LANGUAGE),
                new LanguageItem("English", "en"),
                new LanguageItem("German", "de"),
                new LanguageItem("French", "fr"),
                new LanguageItem("Russian", "ru"),
        };

        for (LanguageItem languageItem : languageItems) {
            jcbLanguage.addItem(languageItem);
            if (languageItem.getIsoCode().equals(preferences.getLanguage())) {
                jcbLanguage.setSelectedItem(languageItem);
            }
        }
    }

    /**
     * Quick UI testing
     */
    public static void main(String[] args) throws Exception {
        DPreferences dialog = new DPreferences(new JFrame(), new KsePreferences());
        DialogViewer.run(dialog);
    }
}