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

import static javax.swing.SwingUtilities.invokeLater;
import static org.kse.gui.SwingUtil.fixScrolling;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.security.Security;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.ToolTipManager;
import javax.swing.UIManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeSelectionModel;

import org.kse.crypto.SecurityProvider;
import org.kse.gui.CursorUtil;
import org.kse.gui.KeyStoreTableColumns;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;
import org.kse.gui.password.PasswordQualityConfig;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.preferences.data.PasswordGeneratorSettings;
import org.kse.gui.preferences.data.Pkcs12EncryptionSetting;
import org.kse.utilities.DialogViewer;

/**
 * Dialog to allow the users to configure KeyStore Explorer's preferences.
 */
public class DPreferences extends JEscDialog {

    private static final long serialVersionUID = -3625128197124011083L;
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/preferences/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";
    static final String CARD_1 = "jpCard1";
    static final String CARD_2 = "jpCard2";
    static final String CARD_3 = "jpCard3";
    static final String CARD_4 = "jpCard4";
    static final String CARD_5 = "jpCard5";
    static final String CARD_6 = "jpCard6";

    private JPanel jpRight;
    JScrollPane jspRightPanel;
    private MenuTreeNode[] menuTreeNodes;
    private JTree jtMenuLeft;

    private boolean cancelled = false;

    private final KsePreferences preferences;
    private PanelAuthorityCertificates panelAuthorityCertificates;
    private PanelUserInterface panelUserInterface;
    private PanelProxy panelProxy;
    private PanelDefaultName panelDefaultName;
    private PanelDisplayColumns panelDisplayColumns;
    private PanelPasswords panelPasswords;

    /**
     * Creates a new DPreference dialog.
     *
     * @param parent      The parent frame
     * @param preferences Current state of preferences, probably as loaded from config file
     */
    public DPreferences(JFrame parent, KsePreferences preferences) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        setResizable(true);
        setPreferredSize(new Dimension(900, 600));
        this.preferences = preferences;
        initComponents();
    }

    /**
     * Create preference menu components for navigation and cardlayout
     */
    public void initComponents() {
        getContentPane().setLayout(new BorderLayout(0, 0));
        JSplitPane jsPane = new JSplitPane();
        jsPane.setDividerSize(20);
        jsPane.setOneTouchExpandable(true);
        jsPane.setResizeWeight(0.2);
        getContentPane().add(jsPane);

        DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("Root", true);

        // set the properties for leaf nodes.
        menuTreeNodes = new MenuTreeNode[] {
                new MenuTreeNode("DPreferences.jpAuthorityCertificates.text", "images/tab_authcerts.png",
                                 "DPreferences.jpAuthorityCertificates.tooltip", CARD_1),
                new MenuTreeNode("DPreferences.jpUI.text", "images/tab_lookfeel.png", "DPreferences.jpUI.tooltip",
                                 CARD_2),
                new MenuTreeNode("DPreferences.jpInternetProxy.text", "images/tab_internetproxy.png",
                                 "DPreferences.jpInternetProxy.tooltip", CARD_3),
                new MenuTreeNode("DPreferences.jpDefaultName.text", "images/tab_defaultname.png",
                                 "DPreferences.jpDefaultName.tooltip", CARD_4),
                new MenuTreeNode("DPreferences.jpDisplayColumns.text", "images/tab_columns.png",
                                 "DPreferences.jpDisplayColumns.tooltip", CARD_5),
                new MenuTreeNode("DPreferences.jpPasswords.text", "images/tab_password.png",
                                 "DPreferences.jpPasswords.tooltip", CARD_6) };

        for (MenuTreeNode menu : menuTreeNodes) {
            DefaultMutableTreeNode node = new DefaultMutableTreeNode(menu);
            rootNode.add(node);
        }

        jtMenuLeft = new JTree(rootNode);
        jtMenuLeft.setRootVisible(false);
        jtMenuLeft.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        jtMenuLeft.setCellRenderer(new SettingsTreeCellRenderer());
        jtMenuLeft.setEditable(false);
        jtMenuLeft.setSelectionRow(0);

        jtMenuLeft.getSelectionModel().addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) jtMenuLeft.getLastSelectedPathComponent();
            Object nodeInfo = selectedNode.getUserObject();
            MenuTreeNode mtn = null;
            String screen = "";
            if (selectedNode.isLeaf()) {
                mtn = (MenuTreeNode) nodeInfo;
            }
            for (MenuTreeNode menu : menuTreeNodes) {
                if (mtn != null && mtn.getName().equals(menu.getName())) {
                    screen = menu.getCard();
                }
            }
            changeScreen(screen);
        });

        // Enable tool tips.
        ToolTipManager.sharedInstance().registerComponent(jtMenuLeft);

        // set left split pane for navigation menu
        JScrollPane leftScPane = new JScrollPane(jtMenuLeft);
        jsPane.setLeftComponent(leftScPane);

        // set right split pane for card layout
        jpRight = new JPanel();
        jpRight.setLayout(new CardLayout(0, 0));
        jspRightPanel = new JScrollPane(jpRight);
        fixScrolling(jspRightPanel);
        jsPane.setRightComponent(jspRightPanel);

        JButton jbOK = new JButton(res.getString("DPreferences.jbOK.text"));
        JButton jbCancel = new JButton(res.getString("DPreferences.jbCancel.text"));
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
        JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        jbOK.addActionListener(e -> {
            try {
                CursorUtil.setCursorBusy(this);
                okPressed();
            } finally {
                CursorUtil.setCursorFree(this);
            }
        });

        jbCancel.addActionListener(e -> cancelPressed());

        // action listener for window
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed(); // No save of settings
            }
        });

        // initialize each card layout
        panelAuthorityCertificates = new PanelAuthorityCertificates(this, preferences);
        panelUserInterface = new PanelUserInterface(this, preferences);
        panelProxy = new PanelProxy(this, preferences);
        panelDefaultName = new PanelDefaultName(this, preferences);
        panelDisplayColumns = new PanelDisplayColumns(this, preferences);
        panelPasswords = new PanelPasswords(this, preferences);

        // add cards to the right panel
        jpRight.add(panelAuthorityCertificates.initAuthorityCertificatesCard(), CARD_1);
        jpRight.add(panelUserInterface.initUserInterfaceCard(), CARD_2);
        jpRight.add(panelProxy.initInternetProxyCard(), CARD_3);
        jpRight.add(panelDefaultName.initDefaultNameCard(), CARD_4);
        jpRight.add(panelDisplayColumns.initDisplayColumnsCard(), CARD_5);
        jpRight.add(panelPasswords.initPasswordsCard(), CARD_6);

        setTitle(res.getString("DPreferences.Title"));
        getRootPane().setDefaultButton(jbOK);
        pack();
    }

    private void changeScreen(String screen) {
        ((CardLayout) jpRight.getLayout()).show(jpRight, screen);
        invokeLater(() -> jspRightPanel.getVerticalScrollBar().setValue(0));
    }

    /**
     * Get whether the usage of CA Certificates has been chosen.
     *
     * @return True if it has, false otherwise
     */
    public boolean getUseCaCertificates() {
        return panelAuthorityCertificates.getJcbUseCaCertificates().isSelected();
    }

    /**
     * Get the chosen CA Certificates KeyStore file.
     *
     * @return The chosen CA Certificates KeyStore file
     */
    public File getCaCertificatesFile() {
        return new File(panelAuthorityCertificates.getJtfCaCertificatesFile().getText());
    }

    /**
     * Get whether the usage of Windows Trusted Root Certificates has been
     * chosen.
     *
     * @return True if it has, false otherwise
     */
    public boolean getUseWinTrustRootCertificates() {
        if (Security.getProvider(SecurityProvider.MS_CAPI.jce()) != null) {
            return panelAuthorityCertificates.getJcbUseWinTrustedRootCertificates().isSelected();
        }
        return false;
    }

    /**
     * Get whether trust checks are enabled when importing Trusted
     * Certificates.
     *
     * @return True if they are, false otherwise
     */
    public boolean getEnableImportTrustedCertTrustCheck() {
        return panelAuthorityCertificates.getJcbEnableImportTrustedCertTrustCheck().isSelected();
    }

    /**
     * Get whether trust checks are enabled when importing CA Replies.
     *
     * @return True if they are, false otherwise
     */
    public boolean getEnableImportCaReplyTrustCheck() {
        return panelAuthorityCertificates.getJcbEnableImportCaReplyTrustCheck().isSelected();
    }

    /**
     * Get the chosen password quality configuration settings.
     *
     * @return Password quality configuration settings
     */
    public PasswordQualityConfig getPasswordQualityConfig() {
        return new PasswordQualityConfig(panelUserInterface.getJcbEnablePasswordQuality().isSelected(),
                                         panelUserInterface.getJcbEnforceMinimumPasswordQuality().isSelected(),
                                         panelUserInterface.getJsMinimumPasswordQuality().getValue());
    }

    /**
     * Get password generator settings.
     *
     * @return Password generator settings
     */
    public PasswordGeneratorSettings getPasswordGeneratorSettings() {
        PasswordGeneratorSettings pwdGeneratorSettings = new PasswordGeneratorSettings();
        pwdGeneratorSettings.setEnabled(panelPasswords.getJcbPasswordGeneratorEnabled().isSelected());
        pwdGeneratorSettings.setLength(((Number) panelPasswords.getJsPasswordLength().getValue()).intValue());
        pwdGeneratorSettings.setIncludeLowerCaseLetters(panelPasswords.getJcbIncludeLowerCaseLetters().isSelected());
        pwdGeneratorSettings.setIncludeUpperCaseLetters(panelPasswords.getJcbIncludeUpperCaseLetters().isSelected());
        pwdGeneratorSettings.setIncludeDigits(panelPasswords.getJcbIncludeDigits().isSelected());
        pwdGeneratorSettings.setIncludeSpecialCharacters(panelPasswords.getJcbIncludeSpecialCharacters().isSelected());
        return pwdGeneratorSettings;
    }

    /**
     * Get the chosen look & feel information.
     *
     * @return The chosen look & feel information
     */
    public UIManager.LookAndFeelInfo getLookFeelInfo() {
        return panelUserInterface.getLookFeelInfo();
    }

    /**
     * Get whether the look & feel should be used for window decoration.
     *
     * @return True id it should, false otherwise.
     */
    public boolean getLookFeelDecoration() {
        return panelUserInterface.getJcbLookFeelDecorated().isSelected();
    }

    /**
     * Read the new language setting
     *
     * @return ISO code of selected language or system (for system default)
     */
    public String getLanguage() {
        return panelUserInterface.getLanguage();
    }

    /**
     * Read status of show hidden files
     *
     * @return True if show hidden files is enabled
     */
    public boolean isShowHiddenFilesEnabled() {
        return panelUserInterface.getJcbShowHiddenFiles().isSelected();
    }

    /**
     * Get value of "show native file chooser" option
     *
     * @return True if show native file chooser is enabled
     */
    public boolean isNativeFileChooserEnabled() {
        return panelUserInterface.getJcbShowNativeFileChooser().isSelected();
    }

    /**
     * Read enable status of check auto update
     *
     * @return True if auto update is enabled
     */
    public boolean isAutoUpdateChecksEnabled() {
        return panelUserInterface.getJcbEnableAutoUpdateChecks().isSelected();
    }

    /**
     * Read interval of check auto update
     *
     * @return Auto update interval check
     */
    public int getAutoUpdateChecksInterval() {
        return ((Number) panelUserInterface.getJspAutoUpdateCheckInterval().getValue()).intValue();
    }

    /**
     * Read the new default DN (RDNs can be empty here)
     *
     * @return Default DN
     */
    public String getDefaultDN() {
        return panelDefaultName.getDistinguishedNameChooser().getDNWithEmptyRdns().toString();
    }

    /**
     * Get columns list for main table
     *
     * @return Columns config
     */
    public KeyStoreTableColumns getColumns() {
        var newKstColumns = new KeyStoreTableColumns();
        newKstColumns.setEnableEntryName(panelDisplayColumns.getJcbEnableEntryName().isSelected());
        newKstColumns.setEnableAlgorithm(panelDisplayColumns.getJcbEnableAlgorithm().isSelected());
        newKstColumns.setEnableKeySize(panelDisplayColumns.getJcbEnableKeySize().isSelected());
        newKstColumns.setEnableCertificateValidityStart(panelDisplayColumns.getJcbEnableCertificateValidityStart().isSelected());
        newKstColumns.setEnableCertificateExpiry(panelDisplayColumns.getJcbEnableCertificateExpiry().isSelected());
        newKstColumns.setEnableLastModified(panelDisplayColumns.getJcbEnableLastModified().isSelected());
        newKstColumns.setEnableCurve(panelDisplayColumns.getJcbEnableCurve().isSelected());
        newKstColumns.setEnableSKI(panelDisplayColumns.getJcbEnableSKI().isSelected());
        newKstColumns.setEnableAKI(panelDisplayColumns.getJcbEnableAKI().isSelected());
        newKstColumns.setEnableIssuerDN(panelDisplayColumns.getJcbEnableIssuerDN().isSelected());
        newKstColumns.setEnableSubjectDN(panelDisplayColumns.getJcbEnableSubjectDN().isSelected());
        newKstColumns.setEnableIssuerCN(panelDisplayColumns.getJcbEnableIssuerCN().isSelected());
        newKstColumns.setEnableSubjectCN(panelDisplayColumns.getJcbEnableSubjectCN().isSelected());
        newKstColumns.setEnableIssuerO(panelDisplayColumns.getJcbEnableIssuerO().isSelected());
        newKstColumns.setEnableSubjectO(panelDisplayColumns.getJcbEnableSubjectO().isSelected());
        newKstColumns.setEnableSerialNumberHex(panelDisplayColumns.getJcbEnableSerialNumberHex().isSelected());
        newKstColumns.setEnableSerialNumberDec(panelDisplayColumns.getJcbEnableSerialNumberDec().isSelected());
        return newKstColumns;
    }

    /**
     * Get number of days before certificate expiration warnings in the main table are shown in advance
     * @return Expiry warn
     */
    public int getExpiryWarnDays() {
        return ((Number) panelDisplayColumns.getJspExpirationWarnDays().getValue()).intValue();
    }

    /**
     * Get PKCS12 encryption settings
     * @return P12 encryption settings
     */
    public Pkcs12EncryptionSetting getPkcs12EncryptionSetting() {
        return (Pkcs12EncryptionSetting) panelUserInterface.getJcbPkcs12Encryption().getSelectedItem();
    }

    /**
     * Returns length of serial number random bytes
     *
     * @return serial number random bytes
     */
    public int getSerialNumberLengthInBytes() {
        return ((Number) panelUserInterface.getJspSnRandomBytes().getValue()).intValue();
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

    /**
     * Validate store preferences Call close dialog method
     */
    private void okPressed() {
        if (panelProxy.storeProxyPreferences()) {
            closeDialog();
        }
    }

    /**
     * Call the close dialog method
     */
    private void cancelPressed() {
        cancelled = true;
        closeDialog();
    }

    /**
     * Close dialog method dispose of window
     */
    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    /**
     * Quick UI testing
     */
    public static void main(String[] args) throws Exception {
        DPreferences dialog = new DPreferences(new JFrame(), new KsePreferences());
        DialogViewer.run(dialog);
    }
}