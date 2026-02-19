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
package org.kse.gui;

import static org.kse.crypto.keystore.KeyStoreType.BCFKS;
import static org.kse.crypto.keystore.KeyStoreType.BKS;
import static org.kse.crypto.keystore.KeyStoreType.JCEKS;
import static org.kse.crypto.keystore.KeyStoreType.JKS;
import static org.kse.crypto.keystore.KeyStoreType.PEM;
import static org.kse.crypto.keystore.KeyStoreType.PKCS12;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DragSource;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import javax.swing.plaf.TabbedPaneUI;
import javax.swing.table.TableRowSorter;

import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.publickey.OpenSslPubUtil;
import org.kse.gui.actions.AboutAction;
import org.kse.gui.actions.AppendToCertificateChainAction;
import org.kse.gui.actions.ChangeTypeAction;
import org.kse.gui.actions.CheckUpdateAction;
import org.kse.gui.actions.CloseAction;
import org.kse.gui.actions.CloseAllAction;
import org.kse.gui.actions.CloseOthersAction;
import org.kse.gui.actions.CompareCertificateAction;
import org.kse.gui.actions.CopyAction;
import org.kse.gui.actions.CopyKeyPairAction;
import org.kse.gui.actions.CopyTrustedCertificateAction;
import org.kse.gui.actions.CutAction;
import org.kse.gui.actions.CutKeyPairAction;
import org.kse.gui.actions.CutTrustedCertificateAction;
import org.kse.gui.actions.DeleteKeyAction;
import org.kse.gui.actions.DeleteKeyPairAction;
import org.kse.gui.actions.DeleteMultipleEntriesAction;
import org.kse.gui.actions.DeleteTrustedCertificateAction;
import org.kse.gui.actions.DetectFileTypeAction;
import org.kse.gui.actions.ExamineClipboardAction;
import org.kse.gui.actions.ExamineFileAction;
import org.kse.gui.actions.ExamineSslAction;
import org.kse.gui.actions.ExitAction;
import org.kse.gui.actions.ExportCsvAction;
import org.kse.gui.actions.ExportKeyPairAction;
import org.kse.gui.actions.ExportKeyPairCertificateChainAction;
import org.kse.gui.actions.ExportKeyPairPrivateKeyAction;
import org.kse.gui.actions.ExportKeyPairPublicKeyAction;
import org.kse.gui.actions.ExportSelectedCertificatesAction;
import org.kse.gui.actions.ExportTrustedCertificateAction;
import org.kse.gui.actions.ExportTrustedCertificatePublicKeyAction;
import org.kse.gui.actions.FindAction;
import org.kse.gui.actions.GenerateCsrAction;
import org.kse.gui.actions.GenerateDHParametersAction;
import org.kse.gui.actions.GenerateKeyPairAction;
import org.kse.gui.actions.GenerateSecretKeyAction;
import org.kse.gui.actions.HelpAction;
import org.kse.gui.actions.ImportCaReplyFromClipboardAction;
import org.kse.gui.actions.ImportCaReplyFromFileAction;
import org.kse.gui.actions.ImportKeyPairAction;
import org.kse.gui.actions.ImportTrustedCertificateAction;
import org.kse.gui.actions.JarsAction;
import org.kse.gui.actions.KeyDetailsAction;
import org.kse.gui.actions.KeyPairCertificateChainDetailsAction;
import org.kse.gui.actions.KeyPairPrivateKeyDetailsAction;
import org.kse.gui.actions.KeyPairPublicKeyDetailsAction;
import org.kse.gui.actions.NewAction;
import org.kse.gui.actions.OpenAction;
import org.kse.gui.actions.OpenAppleKeychainAction;
import org.kse.gui.actions.OpenCaCertificatesAction;
import org.kse.gui.actions.OpenDefaultAction;
import org.kse.gui.actions.OpenPkcs11Action;
import org.kse.gui.actions.OpenWindowsMyAction;
import org.kse.gui.actions.OpenWindowsRootAction;
import org.kse.gui.actions.PasteAction;
import org.kse.gui.actions.PreferencesAction;
import org.kse.gui.actions.PropertiesAction;
import org.kse.gui.actions.RedoAction;
import org.kse.gui.actions.RemoveFromCertificateChainAction;
import org.kse.gui.actions.RenameKeyAction;
import org.kse.gui.actions.RenameKeyPairAction;
import org.kse.gui.actions.RenameTrustedCertificateAction;
import org.kse.gui.actions.SaveAction;
import org.kse.gui.actions.SaveAllAction;
import org.kse.gui.actions.SaveAsAction;
import org.kse.gui.actions.SecurityProvidersAction;
import org.kse.gui.actions.SelectedCertificatesChainDetailsAction;
import org.kse.gui.actions.SetKeyPairPasswordAction;
import org.kse.gui.actions.SetKeyPasswordAction;
import org.kse.gui.actions.SetPasswordAction;
import org.kse.gui.actions.ShowHideStatusBarAction;
import org.kse.gui.actions.ShowHideToolBarAction;
import org.kse.gui.actions.SignCrlAction;
import org.kse.gui.actions.SignCsrAction;
import org.kse.gui.actions.SignFileAction;
import org.kse.gui.actions.SignJarAction;
import org.kse.gui.actions.SignJwtAction;
import org.kse.gui.actions.SignMidletAction;
import org.kse.gui.actions.SignNewKeyPairAction;
import org.kse.gui.actions.StorePassphraseAction;
import org.kse.gui.actions.SystemInformationAction;
import org.kse.gui.actions.TabStyleScrollAction;
import org.kse.gui.actions.TabStyleWrapAction;
import org.kse.gui.actions.TipOfTheDayAction;
import org.kse.gui.actions.TrustedCertificateDetailsAction;
import org.kse.gui.actions.TrustedCertificatePublicKeyDetailsAction;
import org.kse.gui.actions.UndoAction;
import org.kse.gui.actions.UnlockKeyAction;
import org.kse.gui.actions.UnlockKeyPairAction;
import org.kse.gui.actions.VerifyCertificateAction;
import org.kse.gui.actions.VerifyJarAction;
import org.kse.gui.actions.VerifySignatureAction;
import org.kse.gui.actions.WebsiteAction;
import org.kse.gui.dnd.DragEntry;
import org.kse.gui.dnd.DragKeyPairEntry;
import org.kse.gui.dnd.DragTrustedCertificateEntry;
import org.kse.gui.dnd.KeyStoreEntryDragGestureListener;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.preferences.PreferencesManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.gui.quickstart.JQuickStartPane;
import org.kse.gui.statusbar.StatusBar;
import org.kse.gui.statusbar.StatusBarChangeHandler;
import org.kse.gui.table.TableUtil;
import org.kse.gui.table.ToolTipTable;
import org.kse.utilities.buffer.Buffer;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.os.OperatingSystem;

/**
 * KeyStore Explorer application frame. Wraps an actual JFrame.
 */
public final class KseFrame implements StatusBar {

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

    static final String KSE_UPDATE_CHECK_DISABLED = "kse.update.disabled";

    // Default KeyStores tabbed pane width - dictates width of this frame
    public static final int DEFAULT_WIDTH = 700;

    // Default KeyStores tabbed pane - dictates height of this frame
    public static final int DEFAULT_HEIGHT = 450;

    private final ArrayList<KeyStoreHistory> histories = new ArrayList<>();
    private final ArrayList<JTable> keyStoreTables = new ArrayList<>();
    private final JFrame frame = new JFrame();
    private final KsePreferences preferences = PreferencesManager.getPreferences();
    private KeyStoreTableColumns keyStoreTableColumns = PreferencesManager.getPreferences().getKeyStoreTableColumns();

    //
    // Menu bar controls
    //

    private JMenu jmFile;
    private JMenuItem jmiNew;
    private JMenuItem jmiOpen;
    private JMenu jmOpenSpecial;
    private JMenuItem jmiOpenDefaultKeyStore;
    private JMenuItem jmiOpenCaCertificatesKeyStore;
    private JMenuItem jmiOpenPkcs11KeyStore;
    private JMenuItem jmiAppleKeychainKeyStore;
    private JMenuItem jmiOpenWindowsMyKeyStore;
    private JMenuItem jmiOpenWindowsRootKeyStore;
    private JMenuItem jmiClose;
    private JMenuItem jmiCloseAll;
    private JMenuItem jmiSave;
    private JMenuItem jmiSaveAs;
    private JMenuItem jmiSaveAll;
    private JMenuRecentFiles jmrfRecentFiles;
    private JMenuItem jmiExit;

    private JMenu jmEdit;
    private JMenuItem jmiUndo;
    private JMenuItem jmiRedo;
    private JMenuItem jmiCut;
    private JMenuItem jmiCopy;
    private JMenuItem jmiPaste;
    private JMenuItem jmiFind;
    private JMenuItem jmiCompare;

    private JMenu jmView;
    private JCheckBoxMenuItem jcbmiShowHideToolBar;
    private JCheckBoxMenuItem jcbmiShowHideStatusBar;
    private JMenu jmTabStyle;
    private JRadioButtonMenuItem jrbmiTabStyleWrap;
    private JRadioButtonMenuItem jrbmiTabStyleScroll;

    private JMenu jmTools;
    private JMenuItem jmiGenerateDHParameters;
    private JMenuItem jmiGenerateKeyPair;
    private JMenuItem jmiGenerateSecretKey;
    private JMenuItem jmiImportTrustedCertificate;
    private JMenuItem jmiImportKeyPair;
    private JMenuItem jmiStorePassphrase;
    private JMenuItem jmiVerifySignature;
    private JMenuItem jmiVerifyJar;
    private JMenu jmChangeType;
    private JRadioButtonMenuItem jrbmiChangeTypeJks;
    private JRadioButtonMenuItem jrbmiChangeTypeJceks;
    private JRadioButtonMenuItem jrbmiChangeTypePkcs12;
    private JRadioButtonMenuItem jrbmiChangeTypePem;
    private JRadioButtonMenuItem jrbmiChangeTypeBks;
    private JRadioButtonMenuItem jrbmiChangeTypeBcfks;
    private JRadioButtonMenuItem jrbmiChangeTypeUber;
    private JMenuItem jmiSetPassword;
    private JMenuItem jmiProperties;
    private JMenuItem jmiExportCsv;
    private JMenuItem jmiPreferences;

    private JMenu jmExamine;
    private JMenuItem jmiExamineFile;
    private JMenuItem jmiExamineClipboard;
    private JMenuItem jmiExamineSsl;
    private JMenuItem jmiDetectFileType;

    private JMenu jmHelp;
    private JMenuItem jmiHelp;
    private JMenuItem jmiTipOfTheDay;
    private JMenu jmOnlineResources;
    private JMenuItem jmiWebsite;
    private JMenuItem jmiSourceforge;
    private JMenuItem jmiSfBugs;
    private JMenuItem jmiCheckUpdate;
    private JMenuItem jmiSecurityProviders;
    private JMenuItem jmiSystemInformation;
    private JMenuItem jmiJars;
    private JMenuItem jmiAbout;

    //
    // Tool Bar controls
    //

    private JToolBar jtbToolBar;
    private JButton jbNew;
    private JButton jbOpen;
    private JButton jbSave;
    private JButton jbUndo;
    private JButton jbRedo;
    private JButton jbCut;
    private JButton jbCopy;
    private JButton jbPaste;
    private JButton jbGenerateKeyPair;
    private JButton jbGenerateSecretKey;
    private JButton jbImportTrustedCertificate;
    private JButton jbImportKeyPair;
    private JButton jbVerifySignature;
    private JButton jbVerifyJar;
    private JButton jbSetPassword;
    private JButton jbProperties;
    private JButton jbExportCsv;
    private JButton jbExamineFile;
    private JButton jbExamineClipboard;
    private JButton jbExamineSsl;
    private JButton jbHelp;

    //
    // Pop-up menu controls
    //

    private JPopupMenu jpmKeyStoreTab;
    private JMenuItem jmiKeyStoreTabSave;
    private JMenuItem jmiKeyStoreTabSaveAll;
    private JMenuItem jmiKeyStoreTabPaste;
    private JMenuItem jmiKeyStoreTabClose;
    private JMenuItem jmiKeyStoreTabCloseOthers;
    private JMenuItem jmiKeyStoreTabCloseAll;
    private JMenuItem jmiKeyStoreTabProperties;
    private JMenuItem jmiKeyStoreTabExportCsv;

    private JPopupMenu jpmKeyStore;
    private JMenuItem jmiKeyStoreGenerateKeyPair;
    private JMenuItem jmiKeyStoreGenerateSecretKey;
    private JMenuItem jmiKeyStoreImportTrustedCertificate;
    private JMenuItem jmiKeyStoreImportKeyPair;
    private JMenuItem jmiKeyStoreStorePassphrase;
    private JMenu jmKeyStoreChangeType;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypeJks;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypeJceks;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypePkcs12;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypePem;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypeBks;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypeBcfks;
    private JRadioButtonMenuItem jrbmiKeyStoreChangeTypeUber;
    private JMenuItem jmiKeyStoreSetPassword;
    private JMenuItem jmiKeyStoreProperties;
    private JMenuItem jmiKeyStoreExportCsv;

    private JPopupMenu jpmKeyPair;
    private JMenu jmKeyPairDetails;
    private JMenuItem jmiKeyPairCertificateChainDetails;
    private JMenuItem jmiKeyPairPrivateKeyDetails;
    private JMenuItem jmiKeyPairPublicKeyDetails;
    private JMenuItem jmiKeyPairCut;
    private JMenuItem jmiKeyPairCopy;
    private JMenu jmKeyPairExport;
    private JMenuItem jmiKeyPairExport;
    private JMenuItem jmiKeyPairExportCertificateChain;
    private JMenuItem jmiKeyPairExportPrivateKey;
    private JMenuItem jmiKeyPairExportPublicKey;
    private JMenuItem jmiKeyPairGenerateCsr;
    private JMenuItem jmiKeyPairVerifyCertificate;
    private JMenu jmKeyPairImportCaReply;
    private JMenuItem jmiKeyPairImportCaReplyFile;
    private JMenuItem jmiKeyPairImportCaReplyClipboard;
    private JMenu jmKeyPairEditCertChain;
    private JMenuItem jmiKeyPairEditCertChainAppendCert;
    private JMenuItem jmiKeyPairEditCertChainRemoveCert;
    private JMenu jmKeyPairSign;
    private JMenuItem jmiKeyPairSignCsr;
    private JMenuItem jmiKeyPairSignJar;
    private JMenuItem jmiKeyPairSignMidlet;
    private JMenuItem jmiKeyPairSignCrl;
    private JMenuItem jmiKeyPairSignJwt;
    private JMenuItem jmiKeyPairSignNewKeyPair;
    private JMenuItem jmiKeyPairSignFile;
    private JMenuItem jmiKeyPairUnlock;
    private JMenuItem jmiKeyPairSetPassword;
    private JMenuItem jmiKeyPairDelete;
    private JMenuItem jmiKeyPairRename;

    private JPopupMenu jpmTrustedCertificate;
    private JMenu jmTrustedCertificateDetails;
    private JMenuItem jmiTrustedCertificateDetails;
    private JMenuItem jmiTrustedCertificatePublicKeyDetails;
    private JMenuItem jmiTrustedCertificateCut;
    private JMenuItem jmiTrustedCertificateCopy;
    private JMenu jmTrustedCertificateExport;
    private JMenuItem jmiTrustedCertificateExport;
    private JMenuItem jmiTrustedCertificateExportPublicKey;
    private JMenuItem jmiTrustedCertificateVerifyCertificate;
    private JMenuItem jmiTrustedCertificateDelete;
    private JMenuItem jmiTrustedCertificateRename;

    private JPopupMenu jpmKey;
    private JMenuItem jmiKeyDetails;
    private JMenuItem jmiKeyCut;
    private JMenuItem jmiKeyCopy;
    private JMenuItem jmiKeyUnlock;
    private JMenuItem jmiKeySetPassword;
    private JMenuItem jmiKeyDelete;
    private JMenuItem jmiKeyRename;


    private JPopupMenu jpmMultiEntrySel;
    private JMenuItem jmiMultiEntryDetails;
    private JMenuItem jmiMultiEntrySelCut;
    private JMenuItem jmiMultEntrySelCopy;
    private JMenuItem jmiMultiEntrySelDelete;
    private JMenuItem jmiMultiEntryCompare;
    private JMenuItem jmiMultiEntryExport;
    private JMenuItem jmiMultiEntryUnlock;

    //
    // Table header popup menu controls
    //

    private JPopupMenu jpmTableHeader;
    private JCheckBoxMenuItem jcbmiHeaderAlgorithm;
    private JCheckBoxMenuItem jcbmiHeaderKeySize;
    private JCheckBoxMenuItem jcbmiHeaderCurve;
    private JCheckBoxMenuItem jcbmiHeaderCertificateValidityStart;
    private JCheckBoxMenuItem jcbmiHeaderCertificateExpiry;
    private JCheckBoxMenuItem jcbmiHeaderLastModified;
    private JCheckBoxMenuItem jcbmiHeaderAKI;
    private JCheckBoxMenuItem jcbmiHeaderSKI;
    private JCheckBoxMenuItem jcbmiHeaderIssuerDN;
    private JCheckBoxMenuItem jcbmiHeaderSubjectDN;
    private JCheckBoxMenuItem jcbmiHeaderIssuerCN;
    private JCheckBoxMenuItem jcbmiHeaderSubjectCN;
    private JCheckBoxMenuItem jcbmiHeaderIssuerO;
    private JCheckBoxMenuItem jcbmiHeaderSubjectO;
    private JCheckBoxMenuItem jcbmiHeaderSerialNumberHex;
    private JCheckBoxMenuItem jcbmiHeaderSerialNumberDec;
    private JCheckBoxMenuItem jcbmiHeaderFingerprint;

    //
    // Main display controls
    //

    private JKeyStoreTabbedPane jkstpKeyStores;
    private JQuickStartPane jQuickStart;

    //
    // Status bar controls
    //

    private JLabel jlStatusBar;

    //
    // Actions - these are shared between menus and toolbar
    //

    private final NewAction newAction = new NewAction(this);
    private final OpenAction openAction = new OpenAction(this);
    private final OpenDefaultAction openDefaultKeyStoreAction = new OpenDefaultAction(this);
    private final OpenCaCertificatesAction openCaCertificatesKeyStoreAction = new OpenCaCertificatesAction(this);
    private final OpenPkcs11Action openPkcs11KeyStoreAction = new OpenPkcs11Action(this);
    private final OpenAppleKeychainAction openAppleKeychainAction = new OpenAppleKeychainAction(this);
    private final OpenWindowsMyAction openWindowsMyAction = new OpenWindowsMyAction(this);
    private final OpenWindowsRootAction openWindowsRootAction = new OpenWindowsRootAction(this);
    private final SaveAction saveAction = new SaveAction(this);
    private final SaveAsAction saveAsAction = new SaveAsAction(this);
    private final SaveAllAction saveAllAction = new SaveAllAction(this);
    private final CloseAction closeAction = new CloseAction(this);
    private final CloseOthersAction closeOthersAction = new CloseOthersAction(this);
    private final CloseAllAction closeAllAction = new CloseAllAction(this);
    private final ExitAction exitAction = new ExitAction(this);
    private final UndoAction undoAction = new UndoAction(this);
    private final RedoAction redoAction = new RedoAction(this);
    private final CutAction cutAction = new CutAction(this);
    private final CopyAction copyAction = new CopyAction(this);
    private final PasteAction pasteAction = new PasteAction(this);
    private final FindAction findAction = new FindAction(this);
    private final CompareCertificateAction compareCertificateAction = new CompareCertificateAction(this);
    private final ShowHideToolBarAction showHideToolBarAction = new ShowHideToolBarAction(this);
    private final ShowHideStatusBarAction showHideStatusBarAction = new ShowHideStatusBarAction(this);
    private final TabStyleWrapAction tabStyleWrapAction = new TabStyleWrapAction(this);
    private final TabStyleScrollAction tabStyleScrollAction = new TabStyleScrollAction(this);
    private final GenerateDHParametersAction generateDHParametersAction = new GenerateDHParametersAction(this);
    private final GenerateKeyPairAction generateKeyPairAction = new GenerateKeyPairAction(this);
    private final GenerateSecretKeyAction generateSecretKeyAction = new GenerateSecretKeyAction(this);
    private final ImportTrustedCertificateAction importTrustedCertificateAction = new ImportTrustedCertificateAction(
            this);
    private final ImportKeyPairAction importKeyPairAction = new ImportKeyPairAction(this);
    private final StorePassphraseAction storePassphraseAction = new StorePassphraseAction(this);
    private final SetPasswordAction setPasswordAction = new SetPasswordAction(this);
    private final ChangeTypeAction changeTypeJksAction = new ChangeTypeAction(this, KeyStoreType.JKS);
    private final ChangeTypeAction changeTypeJceksAction = new ChangeTypeAction(this, KeyStoreType.JCEKS);
    private final ChangeTypeAction changeTypePkcs12Action = new ChangeTypeAction(this, KeyStoreType.PKCS12);
    private final ChangeTypeAction changeTypePemAction = new ChangeTypeAction(this, KeyStoreType.PEM);
    private final ChangeTypeAction changeTypeBksAction = new ChangeTypeAction(this, KeyStoreType.BKS);
    private final ChangeTypeAction changeTypeBcfksAction = new ChangeTypeAction(this, KeyStoreType.BCFKS);
    private final ChangeTypeAction changeTypeUberAction = new ChangeTypeAction(this, KeyStoreType.UBER);
    private final PropertiesAction propertiesAction = new PropertiesAction(this);
    private final ExportCsvAction exportCsvAction = new ExportCsvAction(this);
    private final PreferencesAction preferencesAction = new PreferencesAction(this);
    private final ExamineFileAction examineFileAction = new ExamineFileAction(this);
    private final ExamineClipboardAction examineClipboardAction = new ExamineClipboardAction(this);
    private final ExamineSslAction examineSslAction = new ExamineSslAction(this);
    private final DetectFileTypeAction detectFileTypeAction = new DetectFileTypeAction(this);
    private final HelpAction helpAction = new HelpAction(this);
    private final TipOfTheDayAction tipOfTheDayAction = new TipOfTheDayAction(this);
    private final WebsiteAction websiteAction = new WebsiteAction(this, WebsiteAction.Target.MAIN);
    private final WebsiteAction gitHubProjectSiteAction = new WebsiteAction(this, WebsiteAction.Target.GITHUB);
    private final WebsiteAction gitHubIssueTrackerAction = new WebsiteAction(this, WebsiteAction.Target.ISSUE_TRACKER);
    private final CheckUpdateAction checkUpdateAction = new CheckUpdateAction(this);
    private final SecurityProvidersAction securityProvidersAction = new SecurityProvidersAction(this);
    private final SystemInformationAction systemInformationAction = new SystemInformationAction(this);
    private final JarsAction jarsAction = new JarsAction(this);
    private final AboutAction aboutAction = new AboutAction(this);
    private final KeyPairCertificateChainDetailsAction keyPairCertificateChainDetailsAction =
            new KeyPairCertificateChainDetailsAction(
            this);
    private final KeyPairPrivateKeyDetailsAction keyPairPrivateKeyDetailsAction = new KeyPairPrivateKeyDetailsAction(
            this);
    private final KeyPairPublicKeyDetailsAction keyPairPublicKeyDetailsAction = new KeyPairPublicKeyDetailsAction(this);
    private final CutKeyPairAction cutKeyPairAction = new CutKeyPairAction(this);
    private final CopyKeyPairAction copyKeyPairAction = new CopyKeyPairAction(this);
    private final ExportKeyPairAction exportKeyPairAction = new ExportKeyPairAction(this);
    private final ExportKeyPairCertificateChainAction exportKeyPairCertificateChainAction =
     new ExportKeyPairCertificateChainAction(
            this);
    private final ExportKeyPairPrivateKeyAction exportKeyPairPrivateKeyAction = new ExportKeyPairPrivateKeyAction(this);
    private final ExportKeyPairPublicKeyAction exportKeyPairPublicKeyAction = new ExportKeyPairPublicKeyAction(this);
    private final GenerateCsrAction generateCsrAction = new GenerateCsrAction(this);
    private final VerifyCertificateAction verifyCertificateAction = new VerifyCertificateAction(this);
    private final VerifySignatureAction verifySignatureAction = new VerifySignatureAction(this);
    private final VerifyJarAction verifyJarAction = new VerifyJarAction(this);
    private final ImportCaReplyFromFileAction importCaReplyFromFileAction = new ImportCaReplyFromFileAction(this);
    private final ImportCaReplyFromClipboardAction importCaReplyFromClipboardAction =
            new ImportCaReplyFromClipboardAction(
            this);
    private final AppendToCertificateChainAction appendToCertificateChainAction = new AppendToCertificateChainAction(
            this);
    private final RemoveFromCertificateChainAction removeFromCertificateChainAction =
     new RemoveFromCertificateChainAction(
            this);
    private final SignCsrAction signCsrAction = new SignCsrAction(this);
    private final SignJarAction signJarAction = new SignJarAction(this);
    private final SignMidletAction signMidletAction = new SignMidletAction(this);
    private final SignCrlAction signCrlAction = new SignCrlAction(this);
    private final SignJwtAction signJwtAction = new SignJwtAction(this);
    private final SignFileAction signFileAction = new SignFileAction(this);
    private final SignNewKeyPairAction signNewKeyPairAction = new SignNewKeyPairAction(this);
    private final UnlockKeyPairAction unlockKeyPairAction = new UnlockKeyPairAction(this);
    private final SetKeyPairPasswordAction setKeyPairPasswordAction = new SetKeyPairPasswordAction(this);
    private final DeleteKeyPairAction deleteKeyPairAction = new DeleteKeyPairAction(this);
    private final RenameKeyPairAction renameKeyPairAction = new RenameKeyPairAction(this);

    private final DeleteMultipleEntriesAction deleteMultipleEntriesAction = new DeleteMultipleEntriesAction(this);

    private final TrustedCertificateDetailsAction trustedCertificateDetailsAction = new TrustedCertificateDetailsAction(
            this);
    private final TrustedCertificatePublicKeyDetailsAction trustedCertificatePublicKeyDetailsAction =
     new TrustedCertificatePublicKeyDetailsAction(
            this);
    private final CutTrustedCertificateAction cutTrustedCertificateAction = new CutTrustedCertificateAction(this);
    private final CopyTrustedCertificateAction copyTrustedCertificateAction = new CopyTrustedCertificateAction(this);
    private final ExportTrustedCertificateAction exportTrustedCertificateAction = new ExportTrustedCertificateAction(
            this);
    private final ExportTrustedCertificatePublicKeyAction exportTrustedCertificatePublicKeyAction =
     new ExportTrustedCertificatePublicKeyAction(
            this);
    private final DeleteTrustedCertificateAction deleteTrustedCertificateAction = new DeleteTrustedCertificateAction(
            this);
    private final RenameTrustedCertificateAction renameTrustedCertificateAction = new RenameTrustedCertificateAction(
            this);
    private final KeyDetailsAction keyDetailsAction = new KeyDetailsAction(this);
    private final UnlockKeyAction unlockKeyAction = new UnlockKeyAction(this);
    private final SetKeyPasswordAction setKeyPasswordAction = new SetKeyPasswordAction(this);
    private final DeleteKeyAction deleteKeyAction = new DeleteKeyAction(this);
    private final RenameKeyAction renameKeyAction = new RenameKeyAction(this);
    private final ExportSelectedCertificatesAction exportSelectedCertificatesAction = new ExportSelectedCertificatesAction(this);
    private final SelectedCertificatesChainDetailsAction selectedCertificatesChainDetailsAction = new SelectedCertificatesChainDetailsAction(this);

    //
    // Action map keys - map input to action
    //

    private static final String CUT_KEY = "CUT_KEY";
    private static final String COPY_KEY = "COPY_KEY";
    private static final String PASTE_KEY = "PASTE_KEY";
    private static final String CONTEXT_MENU_KEY = "CONTEXT_MENU_KEY";
    private static final String ENTER_KEY = "ENTER_KEY";

    public KseFrame() {
        initComponents();
    }

    /**
     * Get underlying JFrame.
     *
     * @return Underlying frame
     */
    public JFrame getUnderlyingFrame() {
        return frame;
    }

    /**
     * Get application settings.
     *
     * @return Application settings
     */
    public KsePreferences getPreferences() {
        return preferences;
    }

    void display() {
        frame.setVisible(true);

        if (preferences.isShowTipsOnStartUp()) {
            tipOfTheDayAction.showTipOfTheDay();
        }
    }

    private void initComponents() {
        initStatusBar();
        initMenu();
        initToolBar();
        initMainPane();
        initKeyStoreTabPopupMenu();
        initKeyStorePopupMenu();
        initKeyStoreEntryPopupMenus();
        initTableHeaderPopupMenu();

        // Handle application close
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                exitAction.exitApplication();
            }
        });
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

        updateApplicationTitle();
        frame.pack();

        initApplicationPosition();
        initApplicationIcons();

        updateControls(false);
    }

    private void initApplicationPosition() {
        Rectangle sizeAndPosition = preferences.getMainWindowSizeAndPosition();

        int xPos = sizeAndPosition.x;
        int yPos = sizeAndPosition.y;

        if (xPos <= 0 || yPos <= 0) {
            frame.setLocationRelativeTo(null);
        } else {
            frame.setLocation(new Point(xPos, yPos));
        }

        if (!SwingUtilities.isRectangleContainingRectangle(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()),
                                                           frame.getBounds())) {
            jQuickStart.setPreferredSize(new Dimension(DEFAULT_WIDTH, DEFAULT_HEIGHT));
            frame.setLocationRelativeTo(null);
        }
    }

    private void initApplicationIcons() {
        // Adds many different sizes to give each OS flexibility in choosing a suitable icon for display
        ArrayList<Image> icons = new ArrayList<>();
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-16x16.png")));
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-24x24.png")));
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-32x32.png")));
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-48x48.png")));
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-128x128.png")));
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-256x256.png")));
        icons.add(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/kse-512x512.png")));

        frame.setIconImages(icons);
    }

    private void initMenu() {
        JMenuBar jmbMenuBar = new JMenuBar();

        jmFile = new JMenu(res.getString("KseFrame.jmFile.text"));
        PlatformUtil.setMnemonic(jmFile, res.getString("KseFrame.jmFile.mnemonic").charAt(0));

        jmiNew = new JMenuItem(newAction);
        PlatformUtil.setMnemonic(jmiNew, res.getString("KseFrame.jmiNew.mnemonic").charAt(0));
        jmiNew.setToolTipText(null);
        new StatusBarChangeHandler(jmiNew, (String) newAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiNew);

        jmiOpen = new JMenuItem(openAction);
        PlatformUtil.setMnemonic(jmiOpen, res.getString("KseFrame.jmiOpen.mnemonic").charAt(0));
        jmiOpen.setToolTipText(null);
        new StatusBarChangeHandler(jmiOpen, (String) openAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiOpen);

        jmOpenSpecial = new JMenu(res.getString("KseFrame.jmOpenSpecial.text"));
        jmOpenSpecial.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/openspecial.png"))));
        PlatformUtil.setMnemonic(jmOpenSpecial, res.getString("KseFrame.jmOpenSpecial.mnemonic").charAt(0));
        jmFile.add(jmOpenSpecial);

        jmiOpenDefaultKeyStore = new JMenuItem(openDefaultKeyStoreAction);
        PlatformUtil.setMnemonic(jmiOpenDefaultKeyStore,
                                 res.getString("KseFrame.jmiOpenDefaultKeyStore.mnemonic").charAt(0));
        jmiOpenDefaultKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiOpenDefaultKeyStore,
                                   (String) openDefaultKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this);
        jmOpenSpecial.add(jmiOpenDefaultKeyStore);

        jmiOpenCaCertificatesKeyStore = new JMenuItem(openCaCertificatesKeyStoreAction);
        PlatformUtil.setMnemonic(jmiOpenCaCertificatesKeyStore,
                                 res.getString("KseFrame.jmiOpenCaCertificatesKeyStore.mnemonic").charAt(0));
        jmiOpenCaCertificatesKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiOpenCaCertificatesKeyStore,
                                   (String) openCaCertificatesKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this);
        jmOpenSpecial.add(jmiOpenCaCertificatesKeyStore);

        jmiOpenPkcs11KeyStore = new JMenuItem(openPkcs11KeyStoreAction);
        PlatformUtil.setMnemonic(jmiOpenPkcs11KeyStore,
                                 res.getString("KseFrame.jmiOpenPkcs11KeyStore.mnemonic").charAt(0));
        jmiOpenPkcs11KeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiOpenPkcs11KeyStore,
                                   (String) openPkcs11KeyStoreAction.getValue(Action.LONG_DESCRIPTION), this);
        jmOpenSpecial.add(jmiOpenPkcs11KeyStore);

        jmiOpenWindowsMyKeyStore = new JMenuItem(openWindowsMyAction);
        PlatformUtil.setMnemonic(jmiOpenWindowsMyKeyStore,
                                 res.getString("KseFrame.jmiOpenWindowsMyKeyStore.mnemonic").charAt(0));
        jmiOpenWindowsMyKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiOpenWindowsMyKeyStore, (String) openWindowsMyAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiOpenWindowsRootKeyStore = new JMenuItem(openWindowsRootAction);
        PlatformUtil.setMnemonic(jmiOpenWindowsRootKeyStore,
                                 res.getString("KseFrame.jmiOpenWindowsRootKeyStore.mnemonic").charAt(0));
        jmiOpenWindowsRootKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiOpenWindowsRootKeyStore, (String) openWindowsRootAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        // show menu item for MSCAPI Windows-MY and Windows-ROOT only on Windows
        if (OperatingSystem.isWindows()) {
            jmOpenSpecial.add(jmiOpenWindowsMyKeyStore);
            jmOpenSpecial.add(jmiOpenWindowsRootKeyStore);
        }

        jmiAppleKeychainKeyStore = new JMenuItem(openAppleKeychainAction);
        PlatformUtil.setMnemonic(jmiAppleKeychainKeyStore,
                res.getString("KseFrame.jmiOpenAppleKeychainKeystore.mnemonic").charAt(0));
        jmiAppleKeychainKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiAppleKeychainKeyStore, (String) openAppleKeychainAction.getValue(Action.LONG_DESCRIPTION),
                this);
        // show menu item for Apple Keychain only on macOS
        if (OperatingSystem.isMacOs()) {
            jmOpenSpecial.add(jmiAppleKeychainKeyStore);
        }

        jmFile.addSeparator();

        jmiClose = new JMenuItem(closeAction);
        PlatformUtil.setMnemonic(jmiClose, res.getString("KseFrame.jmiClose.mnemonic").charAt(0));
        jmiClose.setToolTipText(null);
        new StatusBarChangeHandler(jmiClose, (String) closeAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiClose);

        jmiCloseAll = new JMenuItem(closeAllAction);
        PlatformUtil.setMnemonic(jmiCloseAll, res.getString("KseFrame.jmiCloseAll.mnemonic").charAt(0));
        jmiCloseAll.setToolTipText(null);
        new StatusBarChangeHandler(jmiCloseAll, (String) closeAllAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiCloseAll);

        jmFile.addSeparator();

        jmiSave = new JMenuItem(saveAction);
        PlatformUtil.setMnemonic(jmiSave, res.getString("KseFrame.jmiSave.mnemonic").charAt(0));
        jmiSave.setToolTipText(null);
        new StatusBarChangeHandler(jmiSave, (String) saveAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiSave);

        jmiSaveAs = new JMenuItem(saveAsAction);
        PlatformUtil.setMnemonic(jmiSaveAs, res.getString("KseFrame.jmiSaveAs.mnemonic").charAt(0));
        jmiSaveAs.setDisplayedMnemonicIndex(5);
        jmiSaveAs.setToolTipText(null);
        new StatusBarChangeHandler(jmiSaveAs, (String) saveAsAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiSaveAs);

        jmiSaveAll = new JMenuItem(saveAllAction);
        PlatformUtil.setMnemonic(jmiSaveAll, res.getString("KseFrame.jmiSaveAll.mnemonic").charAt(0));
        jmiSaveAll.setToolTipText(null);
        new StatusBarChangeHandler(jmiSaveAll, (String) saveAllAction.getValue(Action.LONG_DESCRIPTION), this);
        jmFile.add(jmiSaveAll);

        jmFile.addSeparator();

        jmrfRecentFiles = new JMenuRecentFiles(res.getString("KseFrame.jmrfRecentFiles.text"));
        jmrfRecentFiles.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/recentfiles.png"))));
        PlatformUtil.setMnemonic(jmrfRecentFiles, res.getString("KseFrame.jmrfRecentFiles.mnemonic").charAt(0));
        jmFile.add(jmrfRecentFiles);

        List<String> recentFiles = preferences.getRecentFiles();

        for (int i = recentFiles.size() - 1; i >= 0; i--) {
            jmrfRecentFiles.add(createRecentFileMenuItem(jmrfRecentFiles, new File(recentFiles.get(i))));
        }

        if (!OperatingSystem.isMacOs()) {
            jmFile.addSeparator();

            jmiExit = new JMenuItem(exitAction);
            PlatformUtil.setMnemonic(jmiExit, res.getString("KseFrame.jmiExit.mnemonic").charAt(0));
            jmiExit.setToolTipText(null);
            new StatusBarChangeHandler(jmiExit, (String) exitAction.getValue(Action.LONG_DESCRIPTION), this);
            jmFile.add(jmiExit);
        }

        jmEdit = new JMenu(res.getString("KseFrame.jmEdit.text"));
        PlatformUtil.setMnemonic(jmEdit, res.getString("KseFrame.jmEdit.mnemonic").charAt(0));

        jmiUndo = new JMenuItem(undoAction);
        PlatformUtil.setMnemonic(jmiUndo, res.getString("KseFrame.jmiUndo.mnemonic").charAt(0));
        jmiUndo.setToolTipText(null);
        new StatusBarChangeHandler(jmiUndo, (String) undoAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiUndo);

        jmiRedo = new JMenuItem(redoAction);
        PlatformUtil.setMnemonic(jmiRedo, res.getString("KseFrame.jmiRedo.mnemonic").charAt(0));
        jmiRedo.setToolTipText(null);
        new StatusBarChangeHandler(jmiRedo, (String) redoAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiRedo);

        jmEdit.addSeparator();

        jmiCut = new JMenuItem(cutAction);
        PlatformUtil.setMnemonic(jmiCut, res.getString("KseFrame.jmiCut.mnemonic").charAt(0));
        jmiCut.setToolTipText(null);
        new StatusBarChangeHandler(jmiCut, (String) cutAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiCut);

        jmiCopy = new JMenuItem(copyAction);
        PlatformUtil.setMnemonic(jmiCopy, res.getString("KseFrame.jmiCopy.mnemonic").charAt(0));
        jmiCopy.setToolTipText(null);
        new StatusBarChangeHandler(jmiCopy, (String) copyAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiCopy);

        jmiPaste = new JMenuItem(pasteAction);
        PlatformUtil.setMnemonic(jmiPaste, res.getString("KseFrame.jmiPaste.mnemonic").charAt(0));
        jmiPaste.setToolTipText(null);
        new StatusBarChangeHandler(jmiPaste, (String) pasteAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiPaste);

        jmEdit.addSeparator();

        jmiCompare = new JMenuItem(compareCertificateAction);
        PlatformUtil.setMnemonic(jmiCompare, res.getString("KseFrame.jmiCompareCertificates.mnemonic").charAt(0));
        jmiCompare.setToolTipText(null);
        new StatusBarChangeHandler(jmiCompare, (String) compareCertificateAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiCompare);

        jmiFind = new JMenuItem(findAction);
        PlatformUtil.setMnemonic(jmiFind, res.getString("KseFrame.jmiFind.mnemonic").charAt(0));
        jmiFind.setToolTipText(null);
        new StatusBarChangeHandler(jmiFind, (String) findAction.getValue(Action.LONG_DESCRIPTION), this);
        jmEdit.add(jmiFind);

        jmView = new JMenu(res.getString("KseFrame.jmView.text"));
        PlatformUtil.setMnemonic(jmView, res.getString("KseFrame.jmView.mnemonic").charAt(0));

        boolean showToolBar = preferences.isShowToolBar();

        jcbmiShowHideToolBar = new JCheckBoxMenuItem(showHideToolBarAction);
        jcbmiShowHideToolBar.setState(showToolBar);
        PlatformUtil.setMnemonic(jcbmiShowHideToolBar,
                                 res.getString("KseFrame.jcbmiShowHideToolBar.mnemonic").charAt(0));
        jcbmiShowHideToolBar.setToolTipText(null);
        new StatusBarChangeHandler(jcbmiShowHideToolBar,
                                   (String) showHideToolBarAction.getValue(Action.LONG_DESCRIPTION), this);
        jmView.add(jcbmiShowHideToolBar);

        jcbmiShowHideStatusBar = new JCheckBoxMenuItem(showHideStatusBarAction);
        jcbmiShowHideStatusBar.setState(preferences.isShowStatusBar());
        PlatformUtil.setMnemonic(jcbmiShowHideStatusBar,
                                 res.getString("KseFrame.jcbmiShowHideStatusBar.mnemonic").charAt(0));
        jcbmiShowHideStatusBar.setToolTipText(null);
        new StatusBarChangeHandler(jcbmiShowHideStatusBar,
                                   (String) showHideStatusBarAction.getValue(Action.LONG_DESCRIPTION), this);
        jmView.add(jcbmiShowHideStatusBar);

        jmView.addSeparator();

        jmTabStyle = new JMenu(res.getString("KseFrame.jmTabStyle.text"));
        jmTabStyle.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/tabstyle.png"))));
        PlatformUtil.setMnemonic(jmTabStyle, res.getString("KseFrame.jmTabStyle.mnemonic").charAt(0));
        jmView.add(jmTabStyle);

        jrbmiTabStyleWrap = new JRadioButtonMenuItem(tabStyleWrapAction);
        PlatformUtil.setMnemonic(jrbmiTabStyleWrap, res.getString("KseFrame.jrbmiTabStyleWrap.mnemonic").charAt(0));
        jrbmiTabStyleWrap.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiTabStyleWrap, (String) tabStyleWrapAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmTabStyle.add(jrbmiTabStyleWrap);

        jrbmiTabStyleScroll = new JRadioButtonMenuItem(tabStyleScrollAction);
        PlatformUtil.setMnemonic(jrbmiTabStyleScroll, res.getString("KseFrame.jrbmiTabStyleScroll.mnemonic").charAt(0));
        jrbmiTabStyleScroll.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiTabStyleScroll, (String) tabStyleScrollAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmTabStyle.add(jrbmiTabStyleScroll);

        ButtonGroup bgTabStyles = new ButtonGroup();
        bgTabStyles.add(jrbmiTabStyleWrap);
        bgTabStyles.add(jrbmiTabStyleScroll);

        int tabLayout = preferences.getTabLayout();

        if (tabLayout == JTabbedPane.WRAP_TAB_LAYOUT) {
            jrbmiTabStyleWrap.setSelected(true);
        } else {
            jrbmiTabStyleScroll.setSelected(true);
        }

        jmTools = new JMenu(res.getString("KseFrame.jmTools.text"));
        PlatformUtil.setMnemonic(jmTools, res.getString("KseFrame.jmTools.mnemonic").charAt(0));

        jmiGenerateKeyPair = new JMenuItem(generateKeyPairAction);
        PlatformUtil.setMnemonic(jmiGenerateKeyPair, res.getString("KseFrame.jmiGenerateKeyPair.mnemonic").charAt(0));
        jmiGenerateKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiGenerateKeyPair, (String) generateKeyPairAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmTools.add(jmiGenerateKeyPair);

        jmiGenerateSecretKey = new JMenuItem(generateSecretKeyAction);
        PlatformUtil.setMnemonic(jmiGenerateSecretKey,
                                 res.getString("KseFrame.jmiGenerateSecretKey.mnemonic").charAt(0));
        jmiGenerateSecretKey.setToolTipText(null);
        new StatusBarChangeHandler(jmiGenerateSecretKey,
                                   (String) generateSecretKeyAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiGenerateSecretKey);

        jmiGenerateDHParameters = new JMenuItem(generateDHParametersAction);
        PlatformUtil.setMnemonic(jmiGenerateDHParameters,
                                 res.getString("KseFrame.jmiGenerateDHParameters.mnemonic").charAt(0));
        jmiGenerateDHParameters.setToolTipText(null);
        new StatusBarChangeHandler(jmiGenerateDHParameters,
                                   (String) generateDHParametersAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiGenerateDHParameters);

        jmiImportTrustedCertificate = new JMenuItem(importTrustedCertificateAction);
        PlatformUtil.setMnemonic(jmiImportTrustedCertificate,
                                 res.getString("KseFrame.jmiImportTrustedCertificate.mnemonic").charAt(0));
        jmiImportTrustedCertificate.setToolTipText(null);
        new StatusBarChangeHandler(jmiImportTrustedCertificate,
                                   (String) importTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiImportTrustedCertificate);

        jmiImportKeyPair = new JMenuItem(importKeyPairAction);
        PlatformUtil.setMnemonic(jmiImportKeyPair, res.getString("KseFrame.jmiImportKeyPair.mnemonic").charAt(0));
        jmiImportKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiImportKeyPair, (String) importKeyPairAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmTools.add(jmiImportKeyPair);

        jmiStorePassphrase = new JMenuItem(storePassphraseAction);
        PlatformUtil.setMnemonic(jmiStorePassphrase,
                                 res.getString("KseFrame.jmiStorePassphrase.mnemonic").charAt(0));
        jmiStorePassphrase.setToolTipText(null);
        new StatusBarChangeHandler(jmiStorePassphrase,
                                   (String) storePassphraseAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiStorePassphrase);

        jmTools.addSeparator();

        jmiVerifySignature = new JMenuItem(verifySignatureAction);
        PlatformUtil.setMnemonic(jmiVerifySignature, res.getString("KseFrame.jmiVerifySignature.mnemonic").charAt(0));
        jmiVerifySignature.setToolTipText(null);
        new StatusBarChangeHandler(jmiVerifySignature, (String) verifySignatureAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmTools.add(jmiVerifySignature);

        jmiVerifyJar = new JMenuItem(verifyJarAction);
        PlatformUtil.setMnemonic(jmiVerifyJar, res.getString("KseFrame.jmiVerifyJar.mnemonic").charAt(0));
        jmiVerifyJar.setToolTipText(null);
        new StatusBarChangeHandler(jmiVerifyJar, (String) verifyJarAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiVerifyJar);

        jmTools.addSeparator();

        jmiSetPassword = new JMenuItem(setPasswordAction);
        PlatformUtil.setMnemonic(jmiSetPassword, res.getString("KseFrame.jmiSetPassword.mnemonic").charAt(0));
        jmiSetPassword.setToolTipText(null);
        new StatusBarChangeHandler(jmiSetPassword, (String) setPasswordAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiSetPassword);

        jmChangeType = new JMenu(res.getString("KseFrame.jmChangeType.text"));
        jmChangeType.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/keystoretype.png"))));
        PlatformUtil.setMnemonic(jmChangeType, res.getString("KseFrame.jmChangeType.mnemonic").charAt(0));
        jmChangeType.setEnabled(false);
        jmTools.add(jmChangeType);

        jrbmiChangeTypePkcs12 = new JRadioButtonMenuItem(changeTypePkcs12Action);
        PlatformUtil.setMnemonic(jrbmiChangeTypePkcs12,
                                 res.getString("KseFrame.jrbmiChangeTypePkcs12.mnemonic").charAt(0));
        jrbmiChangeTypePkcs12.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypePkcs12,
                                   (String) changeTypePkcs12Action.getValue(Action.LONG_DESCRIPTION), this);
        jmChangeType.add(jrbmiChangeTypePkcs12);

        jrbmiChangeTypeJceks = new JRadioButtonMenuItem(changeTypeJceksAction);
        PlatformUtil.setMnemonic(jrbmiChangeTypeJceks,
                                 res.getString("KseFrame.jrbmiChangeTypeJceks.mnemonic").charAt(0));
        jrbmiChangeTypeJceks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypeJceks,
                                   (String) changeTypeJceksAction.getValue(Action.LONG_DESCRIPTION), this);
        jmChangeType.add(jrbmiChangeTypeJceks);

        jrbmiChangeTypeJks = new JRadioButtonMenuItem(changeTypeJksAction);
        PlatformUtil.setMnemonic(jrbmiChangeTypeJks, res.getString("KseFrame.jrbmiChangeTypeJks.mnemonic").charAt(0));
        jrbmiChangeTypeJks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypeJks, (String) changeTypeJksAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmChangeType.add(jrbmiChangeTypeJks);

        jrbmiChangeTypeBks = new JRadioButtonMenuItem(changeTypeBksAction);
        PlatformUtil.setMnemonic(jrbmiChangeTypeBks, res.getString("KseFrame.jrbmiChangeTypeBks.mnemonic").charAt(0));
        jrbmiChangeTypeBks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypeBks, (String) changeTypeBksAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmChangeType.add(jrbmiChangeTypeBks);

        jrbmiChangeTypeUber = new JRadioButtonMenuItem(changeTypeUberAction);
        PlatformUtil.setMnemonic(jrbmiChangeTypeUber, res.getString("KseFrame.jrbmiChangeTypeUber.mnemonic").charAt(0));
        jrbmiChangeTypeUber.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypeUber, (String) changeTypeUberAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmChangeType.add(jrbmiChangeTypeUber);

        jrbmiChangeTypeBcfks = new JRadioButtonMenuItem(changeTypeBcfksAction);
        PlatformUtil.setMnemonic(jrbmiChangeTypeBcfks,
                                 res.getString("KseFrame.jrbmiChangeTypeBcfks.mnemonic").charAt(0));
        jrbmiChangeTypeBcfks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypeBcfks,
                                   (String) changeTypeBcfksAction.getValue(Action.LONG_DESCRIPTION), this);
        jmChangeType.add(jrbmiChangeTypeBcfks);

        jrbmiChangeTypePem = new JRadioButtonMenuItem(changeTypePemAction);
        PlatformUtil.setMnemonic(jrbmiChangeTypePem,
                res.getString("KseFrame.jrbmiChangeTypePem.mnemonic").charAt(0));
        jrbmiChangeTypePem.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiChangeTypePem,
                (String) changeTypePemAction.getValue(Action.LONG_DESCRIPTION), this);
        jmChangeType.add(jrbmiChangeTypePem);

        ButtonGroup changeTypeGroup = new ButtonGroup();
        changeTypeGroup.add(jrbmiChangeTypePkcs12);
        changeTypeGroup.add(jrbmiChangeTypeJceks);
        changeTypeGroup.add(jrbmiChangeTypeJks);
        changeTypeGroup.add(jrbmiChangeTypeBks);
        changeTypeGroup.add(jrbmiChangeTypeUber);
        changeTypeGroup.add(jrbmiChangeTypeBcfks);
        changeTypeGroup.add(jrbmiChangeTypePem);

        jmiProperties = new JMenuItem(propertiesAction);
        PlatformUtil.setMnemonic(jmiProperties, res.getString("KseFrame.jmiProperties.mnemonic").charAt(0));
        jmiProperties.setToolTipText(null);
        new StatusBarChangeHandler(jmiProperties, (String) propertiesAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiProperties);

        jmiExportCsv = new JMenuItem(exportCsvAction);
        PlatformUtil.setMnemonic(jmiExportCsv, res.getString("KseFrame.jmiExportCsv.mnemonic").charAt(0));
        jmiExportCsv.setToolTipText(null);
        new StatusBarChangeHandler(jmiExportCsv, (String) exportCsvAction.getValue(Action.LONG_DESCRIPTION), this);
        jmTools.add(jmiExportCsv);

        if (!OperatingSystem.isMacOs()) {
            jmTools.addSeparator();

            jmiPreferences = new JMenuItem(preferencesAction);
            PlatformUtil.setMnemonic(jmiPreferences, res.getString("KseFrame.jmiPreferences.mnemonic").charAt(0));
            jmiPreferences.setToolTipText(null);
            new StatusBarChangeHandler(jmiPreferences, (String) preferencesAction.getValue(Action.LONG_DESCRIPTION),
                                       this);
            jmTools.add(jmiPreferences);
        }

        jmExamine = new JMenu(res.getString("KseFrame.jmExamine.text"));
        PlatformUtil.setMnemonic(jmExamine, res.getString("KseFrame.jmExamine.mnemonic").charAt(0));

        jmiExamineFile = new JMenuItem(examineFileAction);
        PlatformUtil.setMnemonic(jmiExamineFile, res.getString("KseFrame.jmiExamineFile.mnemonic").charAt(0));
        jmiExamineFile.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineFile, (String) examineFileAction.getValue(Action.LONG_DESCRIPTION), this);
        jmExamine.add(jmiExamineFile);

        jmiExamineClipboard = new JMenuItem(examineClipboardAction);
        PlatformUtil.setMnemonic(jmiExamineClipboard, res.getString("KseFrame.jmiExamineClipboard.mnemonic").charAt(0));
        jmiExamineClipboard.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineClipboard,
                                   (String) examineClipboardAction.getValue(Action.LONG_DESCRIPTION), this);
        jmExamine.add(jmiExamineClipboard);

        jmiExamineSsl = new JMenuItem(examineSslAction);
        PlatformUtil.setMnemonic(jmiExamineSsl, res.getString("KseFrame.jmiExamineSsl.mnemonic").charAt(0));
        jmiExamineSsl.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineSsl, (String) examineSslAction.getValue(Action.LONG_DESCRIPTION), this);
        jmExamine.add(jmiExamineSsl);

        jmExamine.addSeparator();

        jmiDetectFileType = new JMenuItem(detectFileTypeAction);
        PlatformUtil.setMnemonic(jmiDetectFileType, res.getString("KseFrame.jmiDetectFileType.mnemonic").charAt(0));
        jmiDetectFileType.setToolTipText(null);
        new StatusBarChangeHandler(jmiDetectFileType, (String) detectFileTypeAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmExamine.add(jmiDetectFileType);

        jmHelp = new JMenu(res.getString("KseFrame.jmHelp.text"));
        PlatformUtil.setMnemonic(jmHelp, res.getString("KseFrame.jmHelp.mnemonic").charAt(0));

        jmiHelp = new JMenuItem(helpAction);
        PlatformUtil.setMnemonic(jmiHelp, res.getString("KseFrame.jmiHelp.mnemonic").charAt(0));
        jmiHelp.setToolTipText(null);
        new StatusBarChangeHandler(jmiHelp, (String) helpAction.getValue(Action.LONG_DESCRIPTION), this);
        jmHelp.add(jmiHelp);

        jmiTipOfTheDay = new JMenuItem(tipOfTheDayAction);
        PlatformUtil.setMnemonic(jmiTipOfTheDay, res.getString("KseFrame.jmiTipOfTheDay.mnemonic").charAt(0));
        jmiTipOfTheDay.setToolTipText(null);
        new StatusBarChangeHandler(jmiTipOfTheDay, (String) tipOfTheDayAction.getValue(Action.LONG_DESCRIPTION), this);
        jmHelp.add(jmiTipOfTheDay);

        jmHelp.addSeparator();

        jmOnlineResources = new JMenu(res.getString("KseFrame.jmOnlineResources.text"));
        jmOnlineResources.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/online.png"))));
        PlatformUtil.setMnemonic(jmOnlineResources, res.getString("KseFrame.jmOnlineResources.mnemonic").charAt(0));
        jmHelp.add(jmOnlineResources);

        jmiWebsite = new JMenuItem(websiteAction);
        PlatformUtil.setMnemonic(jmiWebsite, res.getString("KseFrame.jmiWebsite.mnemonic").charAt(0));
        jmiWebsite.setToolTipText(null);
        new StatusBarChangeHandler(jmiWebsite, (String) websiteAction.getValue(Action.LONG_DESCRIPTION), this);
        jmOnlineResources.add(jmiWebsite);

        jmiSourceforge = new JMenuItem(gitHubProjectSiteAction);
        PlatformUtil.setMnemonic(jmiSourceforge, res.getString("KseFrame.jmiSourceforge.mnemonic").charAt(0));
        jmiSourceforge.setToolTipText(null);
        new StatusBarChangeHandler(jmiSourceforge, (String) gitHubProjectSiteAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmOnlineResources.add(jmiSourceforge);

        jmiSfBugs = new JMenuItem(gitHubIssueTrackerAction);
        PlatformUtil.setMnemonic(jmiSfBugs, res.getString("KseFrame.jmiSfBugs.mnemonic").charAt(0));
        jmiSfBugs.setToolTipText(null);
        new StatusBarChangeHandler(jmiSfBugs, (String) gitHubIssueTrackerAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jmOnlineResources.add(jmiSfBugs);

        jmiCheckUpdate = new JMenuItem(checkUpdateAction);
        PlatformUtil.setMnemonic(jmiCheckUpdate, res.getString("KseFrame.jmiCheckUpdate.mnemonic").charAt(0));
        jmiCheckUpdate.setToolTipText(null);
        new StatusBarChangeHandler(jmiCheckUpdate, (String) checkUpdateAction.getValue(Action.LONG_DESCRIPTION), this);
        // no update checks if KSE was packaged as rpm
        if (!Boolean.getBoolean(KSE_UPDATE_CHECK_DISABLED)) {
            jmOnlineResources.add(jmiCheckUpdate);
        }

        jmiSecurityProviders = new JMenuItem(securityProvidersAction);
        PlatformUtil.setMnemonic(jmiSecurityProviders,
                                 res.getString("KseFrame.jmiSecurityProviders.mnemonic").charAt(0));
        jmiSecurityProviders.setToolTipText(null);
        new StatusBarChangeHandler(jmiSecurityProviders,
                                   (String) securityProvidersAction.getValue(Action.LONG_DESCRIPTION), this);
        jmHelp.add(jmiSecurityProviders);

        jmiJars = new JMenuItem(jarsAction);
        PlatformUtil.setMnemonic(jmiJars, res.getString("KseFrame.jmiJars.mnemonic").charAt(0));
        jmiJars.setToolTipText(null);
        new StatusBarChangeHandler(jmiJars, (String) jarsAction.getValue(Action.LONG_DESCRIPTION), this);
        jmHelp.add(jmiJars);

        jmiSystemInformation = new JMenuItem(systemInformationAction);
        PlatformUtil.setMnemonic(jmiSystemInformation,
                                 res.getString("KseFrame.jmiSystemInformation.mnemonic").charAt(0));
        jmiSystemInformation.setToolTipText(null);
        new StatusBarChangeHandler(jmiSystemInformation,
                                   (String) systemInformationAction.getValue(Action.LONG_DESCRIPTION), this);
        jmHelp.add(jmiSystemInformation);

        if (!OperatingSystem.isMacOs()) {
            jmHelp.addSeparator();

            jmiAbout = new JMenuItem(aboutAction);
            PlatformUtil.setMnemonic(jmiAbout, res.getString("KseFrame.jmiAbout.mnemonic").charAt(0));
            jmiAbout.setToolTipText(null);
            new StatusBarChangeHandler(jmiAbout, (String) aboutAction.getValue(Action.LONG_DESCRIPTION), this);
            jmHelp.add(jmiAbout);
        }

        jmbMenuBar.add(jmFile);
        jmbMenuBar.add(jmEdit);
        jmbMenuBar.add(jmView);
        jmbMenuBar.add(jmTools);
        jmbMenuBar.add(jmExamine);
        jmbMenuBar.add(jmHelp);

        frame.setJMenuBar(jmbMenuBar);
    }

    private JMenuItemRecentFile createRecentFileMenuItem(JMenuRecentFiles jmRecentFiles, File recentFile) {
        JMenuItemRecentFile jmirfNew = new JMenuItemRecentFile(jmRecentFiles, recentFile);
        jmirfNew.addActionListener(new RecentKeyStoreFileActionListener(recentFile, this));

        new StatusBarChangeHandler(jmirfNew,
                                   MessageFormat.format(res.getString("KseFrame.recentfile.statusbar"), recentFile),
                                   this);
        return jmirfNew;
    }

    private void initToolBar() {
        jbNew = new JButton();
        jbNew.setAction(newAction);
        jbNew.setText(null);
        PlatformUtil.setMnemonic(jbNew, 0);
        jbNew.setFocusable(false);
        jbNew.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) newAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbOpen = new JButton();
        jbOpen.setAction(openAction);
        jbOpen.setText(null);
        PlatformUtil.setMnemonic(jbOpen, 0);
        jbOpen.setFocusable(false);
        jbOpen.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) openAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbSave = new JButton();
        jbSave.setAction(saveAction);
        jbSave.setText(null);
        PlatformUtil.setMnemonic(jbSave, 0);
        jbSave.setFocusable(false);
        jbSave.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) saveAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbUndo = new JButton();
        jbUndo.setAction(undoAction);
        jbUndo.setText(null);
        PlatformUtil.setMnemonic(jbUndo, 0);
        jbUndo.setHideActionText(true); // Ensure text is not displayed when
        // changed dynamically
        // later on action
        jbUndo.setFocusable(false);
        jbUndo.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) undoAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbRedo = new JButton();
        jbRedo.setAction(redoAction);
        jbRedo.setText(null);
        PlatformUtil.setMnemonic(jbRedo, 0);
        jbRedo.setHideActionText(true); // Ensure text is not displayed when
        // changed dynamically
        // later on action
        jbRedo.setFocusable(false);
        jbRedo.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) redoAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbCut = new JButton();
        jbCut.setAction(cutAction);
        jbCut.setText(null);
        PlatformUtil.setMnemonic(jbCut, 0);
        jbCut.setFocusable(false);
        jbCut.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) cutAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbCopy = new JButton();
        jbCopy.setAction(copyAction);
        jbCopy.setText(null);
        PlatformUtil.setMnemonic(jbCopy, 0);
        jbCopy.setFocusable(false);
        jbCopy.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) copyAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbPaste = new JButton();
        jbPaste.setAction(pasteAction);
        jbPaste.setText(null);
        PlatformUtil.setMnemonic(jbPaste, 0);
        jbPaste.setFocusable(false);
        jbPaste.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) pasteAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbGenerateKeyPair = new JButton();
        jbGenerateKeyPair.setAction(generateKeyPairAction);
        jbGenerateKeyPair.setText(null);
        PlatformUtil.setMnemonic(jbGenerateKeyPair, 0);
        jbGenerateKeyPair.setFocusable(false);
        jbGenerateKeyPair.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) generateKeyPairAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbGenerateSecretKey = new JButton();
        jbGenerateSecretKey.setAction(generateSecretKeyAction);
        jbGenerateSecretKey.setText(null);
        PlatformUtil.setMnemonic(jbGenerateSecretKey, 0);
        jbGenerateSecretKey.setFocusable(false);
        jbGenerateSecretKey.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) generateSecretKeyAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbImportTrustedCertificate = new JButton();
        jbImportTrustedCertificate.setAction(importTrustedCertificateAction);
        jbImportTrustedCertificate.setText(null);
        PlatformUtil.setMnemonic(jbImportTrustedCertificate, 0);
        jbImportTrustedCertificate.setFocusable(false);
        jbImportTrustedCertificate.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) importTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbImportKeyPair = new JButton();
        jbImportKeyPair.setAction(importKeyPairAction);
        jbImportKeyPair.setText(null);
        PlatformUtil.setMnemonic(jbImportKeyPair, 0);
        jbImportKeyPair.setFocusable(false);
        jbImportKeyPair.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) importKeyPairAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbVerifySignature = new JButton();
        jbVerifySignature.setAction(verifySignatureAction);
        jbVerifySignature.setText(null);
        PlatformUtil.setMnemonic(jbVerifySignature, 0);
        jbVerifySignature.setFocusable(false);
        jbVerifySignature.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) verifySignatureAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbVerifyJar = new JButton();
        jbVerifyJar.setAction(verifyJarAction);
        jbVerifyJar.setText(null);
        PlatformUtil.setMnemonic(jbVerifyJar, 0);
        jbVerifyJar.setFocusable(false);
        jbVerifyJar.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) verifyJarAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbSetPassword = new JButton();
        jbSetPassword.setAction(setPasswordAction);
        jbSetPassword.setText(null);
        PlatformUtil.setMnemonic(jbSetPassword, 0);
        jbSetPassword.setFocusable(false);
        jbSetPassword.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) setPasswordAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbProperties = new JButton();
        jbProperties.setAction(propertiesAction);
        jbProperties.setText(null);
        PlatformUtil.setMnemonic(jbProperties, 0);
        jbProperties.setFocusable(false);
        jbProperties.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) propertiesAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbExportCsv = new JButton();
        jbExportCsv.setAction(exportCsvAction);
        jbExportCsv.setText(null);
        PlatformUtil.setMnemonic(jbExportCsv, 0);
        jbExportCsv.setFocusable(false);
        jbExportCsv.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) exportCsvAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbExamineFile = new JButton();
        jbExamineFile.setAction(examineFileAction);
        jbExamineFile.setText(null);
        PlatformUtil.setMnemonic(jbExamineFile, 0);
        jbExamineFile.setFocusable(false);
        jbExamineFile.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) examineFileAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbExamineClipboard = new JButton();
        jbExamineClipboard.setAction(examineClipboardAction);
        jbExamineClipboard.setText(null);
        PlatformUtil.setMnemonic(jbExamineClipboard, 0);
        jbExamineClipboard.setFocusable(false);
        jbExamineClipboard.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) examineClipboardAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbExamineSsl = new JButton();
        jbExamineSsl.setAction(examineSslAction);
        jbExamineSsl.setText(null);
        PlatformUtil.setMnemonic(jbExamineSsl, 0);
        jbExamineSsl.setFocusable(false);
        jbExamineSsl.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) examineSslAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jbHelp = new JButton();
        jbHelp.setAction(helpAction);
        jbHelp.setText(null);
        PlatformUtil.setMnemonic(jbHelp, 0);
        jbHelp.setFocusable(false);
        jbHelp.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                setStatusBarText((String) helpAction.getValue(Action.LONG_DESCRIPTION));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                setDefaultStatusBarText();
            }
        });

        jtbToolBar = new JToolBar();

        // If using Windows need a bottom line on the toolbar to seperate it
        // from the main view
        if (LnfUtil.usingWindowsLnf()) {
            jtbToolBar.setBorder(new MatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));
        }

        jtbToolBar.setFloatable(false);
        jtbToolBar.setRollover(true);
        jtbToolBar.setName(KSE.getApplicationName());

        jtbToolBar.add(jbNew);
        jtbToolBar.add(jbOpen);
        jtbToolBar.add(jbSave);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbUndo);
        jtbToolBar.add(jbRedo);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbCut);
        jtbToolBar.add(jbCopy);
        jtbToolBar.add(jbPaste);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbGenerateKeyPair);
        jtbToolBar.add(jbGenerateSecretKey);
        jtbToolBar.add(jbImportTrustedCertificate);
        jtbToolBar.add(jbImportKeyPair);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbVerifySignature);
        jtbToolBar.add(jbVerifyJar);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbSetPassword);
        jtbToolBar.add(jbProperties);
        jtbToolBar.add(jbExportCsv);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbExamineFile);
        jtbToolBar.add(jbExamineClipboard);
        jtbToolBar.add(jbExamineSsl);

        jtbToolBar.addSeparator();

        jtbToolBar.add(jbHelp);

        if (preferences.isShowToolBar()) {
            frame.getContentPane().add(jtbToolBar, BorderLayout.NORTH);
        }
    }

    private void initMainPane() {

        // Displays Quick Start pane initially and KeyStore tabbed pane when at
        // least one KeyStore is open

        jQuickStart = new JQuickStartPane(this);

        jkstpKeyStores = new JKeyStoreTabbedPane(this);

        int tabLayout = preferences.getTabLayout();
        jkstpKeyStores.setTabLayoutPolicy(tabLayout);

        jkstpKeyStores.setBorder(new EmptyBorder(3, 3, 3, 3));

        jkstpKeyStores.addChangeListener(evt -> {
            // Update controls as selected KeyStore is changed
            updateControls(false);
        });

        jkstpKeyStores.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_F10, InputEvent.SHIFT_DOWN_MASK, true), CONTEXT_MENU_KEY);
        jkstpKeyStores.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_CONTEXT_MENU, 0, true), CONTEXT_MENU_KEY);
        jkstpKeyStores.getActionMap().put(CONTEXT_MENU_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent e) {
                maybeShowKeyStoreTabPopup();
            }
        });

        jkstpKeyStores.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent evt) {
                maybeShowKeyStoreTabPopup(evt);
            }

            @Override
            public void mouseReleased(MouseEvent evt) {
                maybeShowKeyStoreTabPopup(evt);
            }

            @Override
            public void mouseClicked(MouseEvent evt) {
                // Close tab if it is middle-clicked
                if (evt.getButton() == MouseEvent.BUTTON2) {
                    closeAction.closeActiveKeyStore();
                }
            }
        });

        Rectangle sizeAndPosition = preferences.getMainWindowSizeAndPosition();
        int width = sizeAndPosition.width;
        int height = sizeAndPosition.height;

        if (width <= 0 || height <= 0) {
            jQuickStart.setPreferredSize(new Dimension(DEFAULT_WIDTH, DEFAULT_HEIGHT));
        } else {
            jQuickStart.setPreferredSize(new Dimension(width, height));
        }

        frame.getContentPane().add(jQuickStart, BorderLayout.CENTER);
    }

    private JScrollPane wrapKeyStoreTableInScrollPane(JTable jtKeyStore) {

        jtKeyStore.setOpaque(true);
        jtKeyStore.setShowGrid(false);
        jtKeyStore.setFillsViewportHeight(true);
        JScrollPane jspKeyStoreTable = PlatformUtil.createScrollPane(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                                     ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jspKeyStoreTable.setViewportView(jtKeyStore);
        jspKeyStoreTable.setBorder(BorderFactory.createEtchedBorder());
        jspKeyStoreTable.setFocusable(false);

        return jspKeyStoreTable;
    }

    private JTable createEmptyKeyStoreTable() {
        KeyStoreTableModel ksModel = new KeyStoreTableModel(keyStoreTableColumns, preferences.getExpiryWarnDays());
        final JTable jtKeyStore = new ToolTipTable(ksModel);

        RowSorter<KeyStoreTableModel> sorter = new TableRowSorter<>(ksModel);
        jtKeyStore.setRowSorter(sorter);

        jtKeyStore.setShowGrid(false);
        jtKeyStore.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        jtKeyStore.getTableHeader().setReorderingAllowed(false);
        jtKeyStore.setRowHeight(Math.max(18, jtKeyStore.getRowHeight())); // min. height of 18 because of 16x16 icons

        // Register cut, copy and paste actions with the relevant keystrokes
        jtKeyStore.getInputMap().put((KeyStroke) cutAction.getValue(Action.ACCELERATOR_KEY), CUT_KEY);
        jtKeyStore.getActionMap().put(CUT_KEY, cutAction);

        jtKeyStore.getInputMap().put((KeyStroke) copyAction.getValue(Action.ACCELERATOR_KEY), COPY_KEY);
        jtKeyStore.getActionMap().put(COPY_KEY, copyAction);

        jtKeyStore.getInputMap().put((KeyStroke) pasteAction.getValue(Action.ACCELERATOR_KEY), PASTE_KEY);
        jtKeyStore.getActionMap().put(PASTE_KEY, pasteAction);

        jtKeyStore.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_F10, InputEvent.SHIFT_DOWN_MASK, true), CONTEXT_MENU_KEY);
        jtKeyStore.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_CONTEXT_MENU, 0, true), CONTEXT_MENU_KEY);
        jtKeyStore.getActionMap().put(CONTEXT_MENU_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent e) {
                maybeShowSelectedEntryPopupMenu();
            }
        });

        // Add mouse listener to table header for context menu
        jtKeyStore.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent evt) {
                if (evt.isPopupTrigger()) {
                    jpmTableHeader.show(evt.getComponent(), evt.getX(), evt.getY());
                }
            }

            @Override
            public void mouseReleased(MouseEvent evt) {
                if (evt.isPopupTrigger()) {
                    jpmTableHeader.show(evt.getComponent(), evt.getX(), evt.getY());
                }
            }
        });

        // open keystore entry details when user presses enter key
        KeyStroke enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0);
        jtKeyStore.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(enter, ENTER_KEY);
        jtKeyStore.getActionMap().put(ENTER_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent ae) {
                try {
                    int selectedRowCount = jtKeyStore.getSelectedRowCount();
                    CursorUtil.setCursorBusy(frame);
                    if (selectedRowCount == 1) {
                        int selectedRow = jtKeyStore.getSelectedRow();
                        showSelectedEntryDetails(jtKeyStore, selectedRow);
                    }
                    else if (selectedRowCount > 1) {
                        selectedCertificatesChainDetailsAction.showCertificatesSelectedEntries();
                    }
                } finally {
                    CursorUtil.setCursorFree(frame);
                }
            }
        });

        // Add DnD source support to KeyStore
        DragSource ds = DragSource.getDefaultDragSource();
        ds.createDefaultDragGestureRecognizer(jtKeyStore, DnDConstants.ACTION_MOVE,
                                              new KeyStoreEntryDragGestureListener(this));

        // Add custom renderers for headers and cells
        TableUtil.addCustomRenderers(jtKeyStore, keyStoreTableColumns);

        TableUtil.setColumnsToIconSize(jtKeyStore, 0, 1, 2);

        // Add mouse listener to table header for context menu
        jtKeyStore.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent evt) {
                if (evt.isPopupTrigger()) {
                    jpmTableHeader.show(evt.getComponent(), evt.getX(), evt.getY());
                }
            }

            @Override
            public void mouseReleased(MouseEvent evt) {
                if (evt.isPopupTrigger()) {
                    jpmTableHeader.show(evt.getComponent(), evt.getX(), evt.getY());
                }
            }
        });

        jtKeyStore.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent evt) {
                maybeShowSelectedEntryDetails(evt);
            }

            @Override
            public void mousePressed(MouseEvent evt) {
                maybeShowSelectedEntryPopupMenu(evt);
            }

            @Override
            public void mouseReleased(MouseEvent evt) {
                maybeShowSelectedEntryPopupMenu(evt);
            }
        });

        jtKeyStore.addKeyListener(new KeyAdapter() {
            boolean deleteLastPressed = false;

            @Override
            public void keyPressed(KeyEvent evt) {
                // Record delete pressed on non-Macs
                if (!OperatingSystem.isMacOs()) {
                    deleteLastPressed = evt.getKeyCode() == KeyEvent.VK_DELETE;
                }

                if (evt.getKeyCode() == KeyEvent.VK_F2) {
                    renameSelectedEntry();
                }

                if (evt.getKeyChar() == '+') {
                    showPublicKeySelectedEntry();
                }

                if (evt.getKeyChar() == '-') {
                    showPrivateKeySelectedEntry();
                }
            }

            @Override
            public void keyReleased(KeyEvent evt) {
                // Delete on non-Mac if delete was pressed and is now released
                if (!OperatingSystem.isMacOs() && deleteLastPressed && evt.getKeyCode() == KeyEvent.VK_DELETE) {
                    deleteLastPressed = false;
                    handleDeleteSelectedEntry();
                }
            }

            @Override
            public void keyTyped(KeyEvent evt) {
                // Delete on Mac if backspace typed
                if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
                    handleDeleteSelectedEntry();
                }
            }
        });

        return jtKeyStore;
    }

    private void handleDeleteSelectedEntry() {
        String nextAlias = getNextEntrysAlias();
        int nrEntriesBeforeDeletion = getNumberOfEntries();

        try {
            String[] aliases = getSelectedEntryAliases();
            if (aliases.length == 1) {
                // if only one entry is selected, use the specific action as it displays a nice warning dialog
                handleSelectedEntry(
                    deleteKeyPairAction::deleteSelectedEntry,
                    deleteTrustedCertificateAction::deleteSelectedEntry,
                    deleteKeyAction::deleteSelectedEntry
                );
            } else {
                deleteMultipleEntriesAction.deleteSelectedEntries();
            }

            // if one entry was deleted, select next entry
            if ((getNumberOfEntries() < nrEntriesBeforeDeletion) && (nextAlias != null)) {
                setSelectedEntriesByAliases(nextAlias);
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private void initStatusBar() {
        jlStatusBar = new JLabel();

        int rightPadding = 3;

        if (OperatingSystem.isMacOs()) {
            rightPadding = 15; // Allow extra padding in the grow box status bar
            // if using macOS
        }

        jlStatusBar.setBorder(new CompoundBorder(new MatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY),
                                                 new EmptyBorder(3, 3, 3, rightPadding)));

        setDefaultStatusBarText();

        if (preferences.isShowStatusBar()) {
            frame.getContentPane().add(jlStatusBar, BorderLayout.SOUTH);
        }
    }

    private void initKeyStoreTabPopupMenu() {
        jpmKeyStoreTab = new JPopupMenu();

        jmiKeyStoreTabSave = new JMenuItem(saveAction);
        jmiKeyStoreTabSave.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabSave, (String) saveAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStoreTab.add(jmiKeyStoreTabSave);

        jmiKeyStoreTabSaveAll = new JMenuItem(saveAllAction);
        jmiKeyStoreTabSaveAll.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabSaveAll, (String) saveAllAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jpmKeyStoreTab.add(jmiKeyStoreTabSaveAll);

        jpmKeyStoreTab.addSeparator();

        jmiKeyStoreTabPaste = new JMenuItem(pasteAction);
        jmiKeyStoreTabPaste.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabPaste, (String) pasteAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStoreTab.add(jmiKeyStoreTabPaste);

        jpmKeyStoreTab.addSeparator();

        jmiKeyStoreTabClose = new JMenuItem(closeAction);
        jmiKeyStoreTabClose.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabClose, (String) closeAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStoreTab.add(jmiKeyStoreTabClose);

        jmiKeyStoreTabCloseOthers = new JMenuItem(closeOthersAction);
        jmiKeyStoreTabCloseOthers.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabCloseOthers,
                                   (String) closeOthersAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStoreTab.add(jmiKeyStoreTabCloseOthers);

        jmiKeyStoreTabCloseAll = new JMenuItem(closeAllAction);
        jmiKeyStoreTabCloseAll.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabCloseAll, (String) closeAllAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jpmKeyStoreTab.add(jmiKeyStoreTabCloseAll);

        jpmKeyStoreTab.addSeparator();

        jmiKeyStoreTabProperties = new JMenuItem(propertiesAction);
        jmiKeyStoreTabProperties.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabProperties,
                                   (String) propertiesAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStoreTab.add(jmiKeyStoreTabProperties);

        jmiKeyStoreTabExportCsv = new JMenuItem(exportCsvAction);
        jmiKeyStoreTabExportCsv.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreTabExportCsv,
                (String) exportCsvAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStoreTab.add(jmiKeyStoreTabExportCsv);
    }

    private void initKeyStorePopupMenu() {
        jpmKeyStore = new JPopupMenu();

        jmiKeyStoreGenerateKeyPair = new JMenuItem(generateKeyPairAction);
        PlatformUtil.setMnemonic(jmiGenerateKeyPair, res.getString("KseFrame.jmiGenerateKeyPair.mnemonic").charAt(0));
        jmiKeyStoreGenerateKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreGenerateKeyPair,
                                   (String) generateKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStore.add(jmiKeyStoreGenerateKeyPair);

        jmiKeyStoreGenerateSecretKey = new JMenuItem(generateSecretKeyAction);
        PlatformUtil.setMnemonic(jmiKeyStoreGenerateSecretKey,
                                 res.getString("KseFrame.jmiGenerateSecretKey.mnemonic").charAt(0));
        jmiKeyStoreGenerateSecretKey.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreGenerateSecretKey,
                                   (String) generateSecretKeyAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStore.add(jmiKeyStoreGenerateSecretKey);

        jmiKeyStoreImportTrustedCertificate = new JMenuItem(importTrustedCertificateAction);
        PlatformUtil.setMnemonic(jmiKeyStoreImportTrustedCertificate,
                                 res.getString("KseFrame.jmiImportTrustedCertificate.mnemonic").charAt(0));
        jmiKeyStoreImportTrustedCertificate.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreImportTrustedCertificate,
                                   (String) importTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStore.add(jmiKeyStoreImportTrustedCertificate);

        jmiKeyStoreImportKeyPair = new JMenuItem(importKeyPairAction);
        PlatformUtil.setMnemonic(jmiKeyStoreImportKeyPair,
                                 res.getString("KseFrame.jmiImportKeyPair.mnemonic").charAt(0));
        jmiKeyStoreImportKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreImportKeyPair,
                                   (String) importKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStore.add(jmiKeyStoreImportKeyPair);

        jmiKeyStoreStorePassphrase = new JMenuItem(storePassphraseAction);
        PlatformUtil.setMnemonic(jmiKeyStoreStorePassphrase,
                                 res.getString("KseFrame.jmiStorePassphrase.mnemonic").charAt(0));
        jmiKeyStoreStorePassphrase.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreStorePassphrase,
                                   (String) storePassphraseAction.getValue(Action.LONG_DESCRIPTION), this);
        jpmKeyStore.add(jmiKeyStoreStorePassphrase);

        jpmKeyStore.addSeparator();

        jmiVerifySignature = new JMenuItem(verifySignatureAction);
        PlatformUtil.setMnemonic(jmiVerifySignature, res.getString("KseFrame.jmiVerifySignature.mnemonic").charAt(0));
        jmiVerifySignature.setToolTipText(null);
        new StatusBarChangeHandler(jmiVerifySignature, (String) verifySignatureAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jpmKeyStore.add(jmiVerifySignature);

        jmiVerifyJar = new JMenuItem(verifyJarAction);
        PlatformUtil.setMnemonic(jmiVerifyJar, res.getString("KseFrame.jmiVerifyJar.mnemonic").charAt(0));
        jmiVerifyJar.setToolTipText(null);
        new StatusBarChangeHandler(jmiVerifyJar, (String) verifyJarAction.getValue(Action.LONG_DESCRIPTION),
                this);
        jpmKeyStore.add(jmiVerifyJar);

        jpmKeyStore.addSeparator();

        jmiKeyStoreSetPassword = new JMenuItem(setPasswordAction);
        PlatformUtil.setMnemonic(jmiKeyStoreSetPassword, res.getString("KseFrame.jmiSetPassword.mnemonic").charAt(0));
        jmiKeyStoreSetPassword.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreSetPassword, (String) setPasswordAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jpmKeyStore.add(jmiKeyStoreSetPassword);

        jmKeyStoreChangeType = new JMenu(res.getString("KseFrame.jmChangeType.text"));
        jmKeyStoreChangeType.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/keystoretype.png"))));
        PlatformUtil.setMnemonic(jmKeyStoreChangeType, res.getString("KseFrame.jmChangeType.mnemonic").charAt(0));
        jpmKeyStore.add(jmKeyStoreChangeType);

        jrbmiKeyStoreChangeTypePkcs12 = new JRadioButtonMenuItem(changeTypePkcs12Action);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypePkcs12,
                                 res.getString("KseFrame.jrbmiChangeTypePkcs12.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypePkcs12.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypePkcs12,
                                   (String) changeTypePkcs12Action.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypePkcs12);

        jrbmiKeyStoreChangeTypeJceks = new JRadioButtonMenuItem(changeTypeJceksAction);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypeJceks,
                                 res.getString("KseFrame.jrbmiChangeTypeJceks.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypeJceks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypeJceks,
                                   (String) changeTypeJceksAction.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypeJceks);

        jrbmiKeyStoreChangeTypeJks = new JRadioButtonMenuItem(changeTypeJksAction);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypeJks,
                                 res.getString("KseFrame.jrbmiChangeTypeJks.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypeJks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypeJks,
                                   (String) changeTypeJksAction.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypeJks);

        jrbmiKeyStoreChangeTypeBks = new JRadioButtonMenuItem(changeTypeBksAction);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypeBks,
                                 res.getString("KseFrame.jrbmiChangeTypeBks.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypeBks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypeBks,
                                   (String) changeTypeBksAction.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypeBks);

        jrbmiKeyStoreChangeTypeUber = new JRadioButtonMenuItem(changeTypeUberAction);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypeUber,
                                 res.getString("KseFrame.jrbmiChangeTypeUber.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypeUber.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypeUber,
                                   (String) changeTypeUberAction.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypeUber);

        jrbmiKeyStoreChangeTypeBcfks = new JRadioButtonMenuItem(changeTypeBcfksAction);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypeBcfks,
                                 res.getString("KseFrame.jrbmiChangeTypeBcfks.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypeBcfks.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypeBcfks,
                                   (String) changeTypeBcfksAction.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypeBcfks);

        jrbmiKeyStoreChangeTypePem = new JRadioButtonMenuItem(changeTypePemAction);
        PlatformUtil.setMnemonic(jrbmiKeyStoreChangeTypePem,
                res.getString("KseFrame.jrbmiChangeTypePem.mnemonic").charAt(0));
        jrbmiKeyStoreChangeTypePem.setToolTipText(null);
        new StatusBarChangeHandler(jrbmiKeyStoreChangeTypePem,
                (String) changeTypePemAction.getValue(Action.LONG_DESCRIPTION), this);
        jmKeyStoreChangeType.add(jrbmiKeyStoreChangeTypePem);

        ButtonGroup changeTypeGroup = new ButtonGroup();
        changeTypeGroup.add(jrbmiKeyStoreChangeTypePkcs12);
        changeTypeGroup.add(jrbmiKeyStoreChangeTypeJceks);
        changeTypeGroup.add(jrbmiKeyStoreChangeTypeJks);
        changeTypeGroup.add(jrbmiKeyStoreChangeTypeBks);
        changeTypeGroup.add(jrbmiKeyStoreChangeTypeUber);
        changeTypeGroup.add(jrbmiKeyStoreChangeTypeBcfks);
        changeTypeGroup.add(jrbmiKeyStoreChangeTypePem);

        jmiKeyStoreProperties = new JMenuItem(propertiesAction);
        PlatformUtil.setMnemonic(jmiKeyStoreProperties, res.getString("KseFrame.jmiProperties.mnemonic").charAt(0));
        jmiKeyStoreProperties.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreProperties, (String) propertiesAction.getValue(Action.LONG_DESCRIPTION),
                                   this);
        jpmKeyStore.add(jmiKeyStoreProperties);

        jmiKeyStoreExportCsv = new JMenuItem(exportCsvAction);
        PlatformUtil.setMnemonic(jmiKeyStoreExportCsv, res.getString("KseFrame.jmiExportCsv.mnemonic").charAt(0));
        jmiKeyStoreExportCsv.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreExportCsv, (String) exportCsvAction.getValue(Action.LONG_DESCRIPTION),
                this);
        jpmKeyStore.add(jmiKeyStoreExportCsv);
    }

    private void initKeyStoreEntryPopupMenus() {

        //
        // Popup menu for key pair entry
        //

        jpmKeyPair = new JPopupMenu();

        jmKeyPairDetails = new JMenu(res.getString("KseFrame.jmKeyPairDetails.text"));
        jmKeyPairDetails.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/keypairdetails.png"))));

        jmiKeyPairCertificateChainDetails = new JMenuItem(keyPairCertificateChainDetailsAction);
        jmiKeyPairCertificateChainDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairCertificateChainDetails,
                                   (String) keyPairCertificateChainDetailsAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairPrivateKeyDetails = new JMenuItem(keyPairPrivateKeyDetailsAction);
        jmiKeyPairPrivateKeyDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairPrivateKeyDetails,
                                   (String) keyPairPrivateKeyDetailsAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairPublicKeyDetails = new JMenuItem(keyPairPublicKeyDetailsAction);
        jmiKeyPairPublicKeyDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairPublicKeyDetails,
                                   (String) keyPairPublicKeyDetailsAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairCut = new JMenuItem(cutKeyPairAction);
        jmiKeyPairCut.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairCut, (String) cutKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairCopy = new JMenuItem(copyKeyPairAction);
        jmiKeyPairCopy.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairCopy, (String) copyKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);

        jmKeyPairExport = new JMenu(res.getString("KseFrame.jmKeyPairExport.text"));
        jmKeyPairExport.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/keypairexport.png"))));

        jmiKeyPairExport = new JMenuItem(exportKeyPairAction);
        jmiKeyPairExport.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairExport, (String) exportKeyPairAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairExportCertificateChain = new JMenuItem(exportKeyPairCertificateChainAction);
        jmiKeyPairExportCertificateChain.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairExportCertificateChain,
                                   (String) exportKeyPairCertificateChainAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairExportPrivateKey = new JMenuItem(exportKeyPairPrivateKeyAction);
        jmiKeyPairExportPrivateKey.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairExportPrivateKey,
                                   (String) exportKeyPairPrivateKeyAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairExportPublicKey = new JMenuItem(exportKeyPairPublicKeyAction);
        jmiKeyPairExportPublicKey.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairExportPublicKey,
                                   (String) exportKeyPairPublicKeyAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairGenerateCsr = new JMenuItem(generateCsrAction);
        jmiKeyPairGenerateCsr.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairGenerateCsr, (String) generateCsrAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairVerifyCertificate = new JMenuItem(verifyCertificateAction);
        jmiKeyPairVerifyCertificate.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairVerifyCertificate,
                                   (String) verifyCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmKeyPairImportCaReply = new JMenu(res.getString("KseFrame.jmKeyPairImportCaReply.text"));
        jmKeyPairImportCaReply.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
                getClass().getResource("images/menu/keypairimportcareply.png"))));

        jmiKeyPairImportCaReplyFile = new JMenuItem(importCaReplyFromFileAction);
        jmiKeyPairImportCaReplyFile.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairImportCaReplyFile,
                                   (String) importCaReplyFromFileAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairImportCaReplyClipboard = new JMenuItem(importCaReplyFromClipboardAction);
        jmiKeyPairImportCaReplyClipboard.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairImportCaReplyClipboard,
                                   (String) importCaReplyFromClipboardAction.getValue(Action.LONG_DESCRIPTION), this);

        jmKeyPairEditCertChain = new JMenu(res.getString("KseFrame.jmKeyPairEditCertChain.text"));
        jmKeyPairEditCertChain.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
                getClass().getResource("images/menu/keypaireditcertchain.png"))));

        jmiKeyPairEditCertChainAppendCert = new JMenuItem(appendToCertificateChainAction);
        jmiKeyPairEditCertChainAppendCert.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairEditCertChainAppendCert,
                                   (String) appendToCertificateChainAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairEditCertChainRemoveCert = new JMenuItem(removeFromCertificateChainAction);
        jmiKeyPairEditCertChainRemoveCert.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairEditCertChainRemoveCert,
                                   (String) removeFromCertificateChainAction.getValue(Action.LONG_DESCRIPTION), this);

        jmKeyPairSign = new JMenu(res.getString("KseFrame.jmKeyPairSign.text"));
        jmKeyPairSign.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/keypairsign.png"))));

        jmiKeyPairSignCsr = new JMenuItem(signCsrAction);
        jmiKeyPairSignCsr.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignCsr, (String) signCsrAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairSignJar = new JMenuItem(signJarAction);
        jmiKeyPairSignJar.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignJar, (String) signJarAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairSignMidlet = new JMenuItem(signMidletAction);
        jmiKeyPairSignMidlet.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignMidlet, (String) signMidletAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairSignCrl = new JMenuItem(signCrlAction);
        jmiKeyPairSignCrl.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignCrl, (String) signCrlAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairSignJwt = new JMenuItem(signJwtAction);
        jmiKeyPairSignJwt.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignJwt, (String) signJwtAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairSignFile = new JMenuItem(signFileAction);
        jmiKeyPairSignFile.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignFile, (String) signFileAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairSignNewKeyPair = new JMenuItem(signNewKeyPairAction);
        jmiKeyPairSignNewKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSignNewKeyPair,
                                   (String) signNewKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairUnlock = new JMenuItem(unlockKeyPairAction);
        jmiKeyPairUnlock.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairUnlock, (String) unlockKeyPairAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairSetPassword = new JMenuItem(setKeyPairPasswordAction);
        jmiKeyPairSetPassword.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairSetPassword,
                                   (String) setKeyPairPasswordAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyPairDelete = new JMenuItem(deleteKeyPairAction);
        jmiKeyPairDelete.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairDelete, (String) deleteKeyPairAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyPairRename = new JMenuItem(renameKeyPairAction);
        jmiKeyPairRename.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyPairRename, (String) renameKeyPairAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jpmKeyPair.add(jmKeyPairDetails);
        jmKeyPairDetails.add(jmiKeyPairCertificateChainDetails);
        jmKeyPairDetails.add(jmiKeyPairPrivateKeyDetails);
        jmKeyPairDetails.add(jmiKeyPairPublicKeyDetails);
        jpmKeyPair.addSeparator();
        jpmKeyPair.add(jmiKeyPairCut);
        jpmKeyPair.add(jmiKeyPairCopy);
        jpmKeyPair.addSeparator();
        jpmKeyPair.add(jmKeyPairExport);
        jmKeyPairExport.add(jmiKeyPairExport);
        jmKeyPairExport.add(jmiKeyPairExportCertificateChain);
        jmKeyPairExport.add(jmiKeyPairExportPrivateKey);
        jmKeyPairExport.add(jmiKeyPairExportPublicKey);
        jpmKeyPair.add(jmiKeyPairGenerateCsr);
        jpmKeyPair.add(jmiKeyPairVerifyCertificate);
        jpmKeyPair.add(jmKeyPairImportCaReply);
        jmKeyPairImportCaReply.add(jmiKeyPairImportCaReplyFile);
        jmKeyPairImportCaReply.add(jmiKeyPairImportCaReplyClipboard);
        jpmKeyPair.add(jmKeyPairEditCertChain);
        jmKeyPairEditCertChain.add(jmiKeyPairEditCertChainAppendCert);
        jmKeyPairEditCertChain.add(jmiKeyPairEditCertChainRemoveCert);
        jpmKeyPair.addSeparator();
        jpmKeyPair.add(jmKeyPairSign);
        jmKeyPairSign.add(jmiKeyPairSignNewKeyPair);
        jmKeyPairSign.add(jmiKeyPairSignCsr);
        jmKeyPairSign.add(jmiKeyPairSignJar);
        jmKeyPairSign.add(jmiKeyPairSignMidlet);
        jmKeyPairSign.add(jmiKeyPairSignCrl);
        jmKeyPairSign.add(jmiKeyPairSignJwt);
        jmKeyPairSign.add(jmiKeyPairSignFile);
        jpmKeyPair.addSeparator();
        jpmKeyPair.add(jmiKeyPairUnlock);
        jpmKeyPair.add(jmiKeyPairSetPassword);
        jpmKeyPair.add(jmiKeyPairDelete);
        jpmKeyPair.add(jmiKeyPairRename);

        //
        // Popup menu for trusted cert entry
        //

        jpmTrustedCertificate = new JPopupMenu();

        jmTrustedCertificateDetails = new JMenu(res.getString("KseFrame.jmTrustedCertificateDetails.text"));
        jmTrustedCertificateDetails.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/trustcertdetails.png"))));

        jmiTrustedCertificateDetails = new JMenuItem(trustedCertificateDetailsAction);
        jmiTrustedCertificateDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateDetails,
                                   (String) trustedCertificateDetailsAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiTrustedCertificatePublicKeyDetails = new JMenuItem(trustedCertificatePublicKeyDetailsAction);
        jmiTrustedCertificatePublicKeyDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificatePublicKeyDetails,
                                   (String) trustedCertificatePublicKeyDetailsAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiTrustedCertificateCut = new JMenuItem(cutTrustedCertificateAction);
        jmiTrustedCertificateCut.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateCut,
                                   (String) cutTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiTrustedCertificateCopy = new JMenuItem(copyTrustedCertificateAction);
        jmiTrustedCertificateCopy.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateCopy,
                                   (String) copyTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmTrustedCertificateExport = new JMenu(res.getString("KseFrame.jmTrustedCertificateExport.text"));
        jmTrustedCertificateExport.setIcon(new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/menu/trustcertexport.png"))));

        jmiTrustedCertificateExport = new JMenuItem(exportTrustedCertificateAction);
        jmiTrustedCertificateExport.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateExport,
                                   (String) exportTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiTrustedCertificateExportPublicKey = new JMenuItem(exportTrustedCertificatePublicKeyAction);
        jmiTrustedCertificateExportPublicKey.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateExportPublicKey,
                                   (String) exportTrustedCertificatePublicKeyAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiTrustedCertificateVerifyCertificate = new JMenuItem(verifyCertificateAction);
        jmiTrustedCertificateVerifyCertificate.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateVerifyCertificate,
                                   (String) verifyCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiTrustedCertificateDelete = new JMenuItem(deleteTrustedCertificateAction);
        jmiTrustedCertificateDelete.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateDelete,
                                   (String) deleteTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiTrustedCertificateRename = new JMenuItem(renameTrustedCertificateAction);
        jmiTrustedCertificateRename.setToolTipText(null);
        new StatusBarChangeHandler(jmiTrustedCertificateRename,
                                   (String) renameTrustedCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jpmTrustedCertificate.add(jmTrustedCertificateDetails);
        jmTrustedCertificateDetails.add(jmiTrustedCertificateDetails);
        jmTrustedCertificateDetails.add(jmiTrustedCertificatePublicKeyDetails);
        jpmTrustedCertificate.addSeparator();
        jpmTrustedCertificate.add(jmiTrustedCertificateCut);
        jpmTrustedCertificate.add(jmiTrustedCertificateCopy);
        jpmTrustedCertificate.addSeparator();
        jpmTrustedCertificate.add(jmTrustedCertificateExport);
        jmTrustedCertificateExport.add(jmiTrustedCertificateExport);
        jmTrustedCertificateExport.add(jmiTrustedCertificateExportPublicKey);
        jpmTrustedCertificate.add(jmiTrustedCertificateVerifyCertificate);
        jpmTrustedCertificate.addSeparator();
        jpmTrustedCertificate.add(jmiTrustedCertificateDelete);
        jpmTrustedCertificate.add(jmiTrustedCertificateRename);

        //
        // Popup menu for secret key entry
        //

        jpmKey = new JPopupMenu();

        jmiKeyDetails = new JMenuItem(keyDetailsAction);
        jmiKeyDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyDetails, (String) keyDetailsAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyCut = new JMenuItem(cutAction);
        jmiKeyCut.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyCut, (String) cutAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyCopy = new JMenuItem(copyAction);
        jmiKeyCopy.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyCopy, (String) copyAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyUnlock = new JMenuItem(unlockKeyAction);
        jmiKeyUnlock.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyUnlock, (String) unlockKeyAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeySetPassword = new JMenuItem(setKeyPasswordAction);
        jmiKeySetPassword.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeySetPassword, (String) setKeyPasswordAction.getValue(Action.LONG_DESCRIPTION),
                                   this);

        jmiKeyDelete = new JMenuItem(deleteKeyAction);
        jmiKeyDelete.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyDelete, (String) deleteKeyAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiKeyRename = new JMenuItem(renameKeyAction);
        jmiKeyRename.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyRename, (String) renameKeyAction.getValue(Action.LONG_DESCRIPTION), this);

        jpmKey.add(jmiKeyDetails);
        jpmKey.addSeparator();
        jpmKey.add(jmiKeyCut);
        jpmKey.add(jmiKeyCopy);
        jpmKey.addSeparator();
        jpmKey.add(jmiKeyUnlock);
        jpmKey.add(jmiKeySetPassword);
        jpmKey.add(jmiKeyDelete);
        jpmKey.add(jmiKeyRename);

        //
        // Popup menu for when multiple entries are selected
        //

        jmiMultiEntryDetails = new JMenuItem(selectedCertificatesChainDetailsAction);
        jmiMultiEntryDetails.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultiEntryDetails, (String) selectedCertificatesChainDetailsAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiMultiEntrySelCut = new JMenuItem(cutAction);
        jmiMultiEntrySelCut.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultiEntrySelCut, (String) cutAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiMultEntrySelCopy = new JMenuItem(copyAction);
        jmiMultEntrySelCopy.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultEntrySelCopy, (String) copyAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiMultiEntrySelDelete = new JMenuItem(deleteMultipleEntriesAction);
        jmiMultiEntrySelDelete.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultiEntrySelDelete,
                                   (String) deleteMultipleEntriesAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiMultiEntryCompare = new JMenuItem(compareCertificateAction);
        jmiMultiEntryCompare.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultiEntryCompare,
                (String) compareCertificateAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiMultiEntryExport = new  JMenuItem(exportSelectedCertificatesAction);
        jmiMultiEntryExport.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultiEntryExport,
                (String) exportSelectedCertificatesAction.getValue(Action.LONG_DESCRIPTION), this);

        jmiMultiEntryUnlock = new  JMenuItem(unlockKeyAction);
        jmiMultiEntryUnlock.setToolTipText(null);
        new StatusBarChangeHandler(jmiMultiEntryUnlock,
                (String) unlockKeyAction.getValue(Action.LONG_DESCRIPTION), this);

        jpmMultiEntrySel = new JPopupMenu();
        jpmMultiEntrySel.add(jmiMultiEntryDetails);
        jpmMultiEntrySel.addSeparator();
        jpmMultiEntrySel.add(jmiMultiEntrySelCut);
        jpmMultiEntrySel.add(jmiMultEntrySelCopy);
        jpmMultiEntrySel.add(jmiMultiEntrySelDelete);
        jpmMultiEntrySel.addSeparator();
        jpmMultiEntrySel.add(jmiMultiEntryExport);
        jpmMultiEntrySel.add(jmiMultiEntryCompare);
        jpmMultiEntrySel.addSeparator();
        jpmMultiEntrySel.add(jmiMultiEntryUnlock);

    }

    // Helper interface for actions on a selected entry
    @FunctionalInterface
    private interface KeyStoreEntryAction {
        void perform() throws Exception;
    }

    // Helper to select the right action depending on entry type, with exception handling
    private void handleSelectedEntry(
            KeyStoreEntryAction keyPairAction,
            KeyStoreEntryAction trustedCertAction,
            KeyStoreEntryAction keyAction
    ) {
        KeyStoreHistory history = getActiveKeyStoreHistory();
        KseKeyStore keyStore = history.getCurrentState().getKeyStore();
        String alias = getSelectedEntryAlias();

        if (alias == null) {
            return;
        }

        try {
            if (keyPairAction != null && KeyStoreUtil.isKeyPairEntry(alias, keyStore)) {
                keyPairAction.perform();
            } else if (trustedCertAction != null && KeyStoreUtil.isTrustedCertificateEntry(alias, keyStore)) {
                trustedCertAction.perform();
            } else if (keyAction != null && KeyStoreUtil.isKeyEntry(alias, keyStore)) {
                keyAction.perform();
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private void maybeShowSelectedEntryDetails(MouseEvent evt) {
        // Check if a double click occurred on the KeyStore table. If it has
        // shown the relevant details of the entry clicked upon
        if (evt.getClickCount() > 1) {
            JTable jtKeyStore = (JTable) evt.getComponent();

            Point point = new Point(evt.getX(), evt.getY());
            int row = jtKeyStore.rowAtPoint(point);

            if (row != -1) {
                try {
                    CursorUtil.setCursorBusy(frame);
                    showSelectedEntryDetails(jtKeyStore, row);
                } finally {
                    CursorUtil.setCursorFree(frame);
                }
            }
        }
    }

    private void showSelectedEntryDetails(JTable jtKeyStore, int row) {
        jtKeyStore.setRowSelectionInterval(row, row);
        updateCutCopyPasteControls(); // Selection changed - update edit controls
        handleSelectedEntry(
            keyPairCertificateChainDetailsAction::showCertificateSelectedEntry,
            trustedCertificateDetailsAction::showCertificateSelectedEntry,
            keyDetailsAction::showKeySelectedEntry
        );
    }

    private void maybeShowSelectedEntryPopupMenu(MouseEvent evt) {

        JTable jtKeyStore = (JTable) evt.getComponent();

        Point point = new Point(evt.getX(), evt.getY());
        int row = jtKeyStore.rowAtPoint(point);

        if (evt.isPopupTrigger()) {

            showKeyStoreContextMenu(jtKeyStore, row, evt.getX(), evt.getY());
        } else if (evt.getClickCount() > 1 && row == -1) {
            // double click on free space opens generate key pair dialog
            generateKeyPairAction.generateKeyPair();
        }

        // Selection changed - update edit controls
        updateCutCopyPasteControls();
    }

    private void maybeShowSelectedEntryPopupMenu() {

        JTable jtKeyStore = getActiveKeyStoreTable();

        // Pops up the menu at the selected row, unless the row is not visible,
        // then it uses the origin of the JTable.
        int row = jtKeyStore.getSelectedRow();
        Rectangle visibleRect = jtKeyStore.getVisibleRect();
        Rectangle cellRect = jtKeyStore.getCellRect(row, 0, true);
        int y = visibleRect.y;
        if (cellRect.y > y && cellRect.y < y + visibleRect.height) {
            y = cellRect.y;
        }
        showKeyStoreContextMenu(jtKeyStore, row, jtKeyStore.getX(), y);

        // Selection changed - update edit controls
        updateCutCopyPasteControls();
    }

    private void showKeyStoreContextMenu(JTable jtKeyStore, int row, int x, int y) {
        if (row != -1) {

            KeyStoreType type = KeyStoreType
                    .resolveJce(getActiveKeyStoreHistory().getCurrentState().getKeyStore().getType());

            if (jtKeyStore.getSelectedRows().length > 1) {

                boolean hasKeyEntry = false;
                boolean hasCertEntry = false;
                for (int r : jtKeyStore.getSelectedRows()) {
                    hasKeyEntry |= KeyStoreTableModel.EntryType.KEY_PAIR.equals(jtKeyStore.getValueAt(r, 0))
                            || KeyStoreTableModel.EntryType.KEY.equals(jtKeyStore.getValueAt(r, 0));
                    hasCertEntry |= KeyStoreTableModel.EntryType.KEY_PAIR.equals(jtKeyStore.getValueAt(r, 0))
                            || KeyStoreTableModel.EntryType.TRUST_CERT.equals(jtKeyStore.getValueAt(r, 0));
                }

                selectedCertificatesChainDetailsAction.setEnabled(hasCertEntry);
                exportSelectedCertificatesAction.setEnabled(hasCertEntry);
                compareCertificateAction.setEnabled(hasCertEntry);
                unlockKeyAction.setEnabled(hasKeyEntry);

                jpmMultiEntrySel.show(jtKeyStore, x, y);
            } else {
                jtKeyStore.setRowSelectionInterval(row, row);

                if (KeyStoreTableModel.EntryType.KEY_PAIR.equals(jtKeyStore.getValueAt(row, 0))) {

                    // For KeyStore types that support password protected entries...
                    if (type.hasEntryPasswords()) {
                        // Only allow unlocking from menu if entry is currently locked
                        boolean locked = (Boolean) jtKeyStore.getValueAt(row, 1);
                        unlockKeyPairAction.setEnabled(locked);
                    }

                    PublicKey publicKey = null;
                    try {
                        Certificate cert = getActiveKeyStore().getCertificate(getSelectedEntryAlias());
                        // Convert to BC provider implementation (Java 25 returns ML-DSA or ML-KEM) rather
                        // specific algorithm names like ML-DSA-44 or ML-KEM-512.
                        publicKey = OpenSslPubUtil.load(cert.getPublicKey().getEncoded());
                    } catch (KeyStoreException | CryptoException e) {
                        // Not possible to sign if there is a keystore exception.
                    }

                    boolean isSignAvailable = publicKey != null && !KeyPairType.isMlKEM(KeyPairUtil.getKeyPairType(publicKey));
                    if (isSignAvailable) {
                        jmiKeyPairGenerateCsr.setEnabled(true);
                        jmiKeyPairGenerateCsr.setToolTipText(null);

                        jmKeyPairSign.setEnabled(true);
                        jmKeyPairSign.setToolTipText(null);

                        signMidletAction.setEnabled(signMidletAction.isKeySupported(publicKey));
                        jmiKeyPairSignMidlet.setToolTipText(signMidletAction.getToolTip());

                        signJwtAction.setEnabled(signJwtAction.isKeySupported(publicKey));
                        jmiKeyPairSignJwt.setToolTipText(signJwtAction.getToolTip());
                    } else {
                        // Cannot request PKCS#10 CSR for ML-KEM since a signature is required for proof of possession
                        // Generating a CSR can be re-enabled once CRMF is supported
                        jmiKeyPairGenerateCsr.setEnabled(false);
                        jmiKeyPairGenerateCsr.setToolTipText(res.getString("KseFrame.jmiKeyPairGenerateCsr.tooltip"));

                        // Signing is not possible.
                        jmKeyPairSign.setEnabled(false);
                        jmKeyPairSign.setToolTipText(res.getString("KseFrame.jmKeyPairSign.tooltip"));
                    }

                    jpmKeyPair.show(jtKeyStore, x, y);

                } else if (KeyStoreTableModel.EntryType.TRUST_CERT.equals(jtKeyStore.getValueAt(row, 0))) {

                    jpmTrustedCertificate.show(jtKeyStore, x, y);

                } else if (KeyStoreTableModel.EntryType.KEY.equals(jtKeyStore.getValueAt(row, 0))) {

                    // For KeyStore types that support password protected entries...
                    if (type.hasEntryPasswords()) {
                        // Only allow unlocking from menu if entry is currently locked
                        boolean locked = (Boolean) jtKeyStore.getValueAt(row, 1);
                        unlockKeyAction.setEnabled(locked);
                    }

                    jpmKey.show(jtKeyStore, x, y);
                }
            }
        } else {
            jpmKeyStore.show(jtKeyStore, x, y);
        }
    }

    private void maybeShowKeyStoreTabPopup(MouseEvent evt) {
        if (evt.isPopupTrigger()) {
            int tabCount = jkstpKeyStores.getTabCount();
            TabbedPaneUI tpu = jkstpKeyStores.getUI();

            for (int i = 0; i < tabCount; i++) {
                Rectangle rect = tpu.getTabBounds(jkstpKeyStores, i);

                int x = evt.getX();
                int y = evt.getY();

                if (x < rect.x || x > rect.x + rect.width || y < rect.y || y > rect.y + rect.height) {
                    continue;
                }

                jpmKeyStoreTab.show(evt.getComponent(), evt.getX(), evt.getY());
                break;
            }
        }
    }

    private void maybeShowKeyStoreTabPopup() {
        int selectedTab = jkstpKeyStores.getSelectedIndex();

        if (selectedTab > -1) {
            TabbedPaneUI tpu = jkstpKeyStores.getUI();
            Rectangle rect = tpu.getTabBounds(jkstpKeyStores, selectedTab);

            jpmKeyStoreTab.show(jkstpKeyStores.getSelectedComponent(), rect.x, rect.y);
        }
    }

    private void renameSelectedEntry() {
        handleSelectedEntry(
            renameKeyPairAction::renameSelectedEntry,
            renameTrustedCertificateAction::renameSelectedEntry,
            renameKeyAction::renameSelectedEntry
        );
    }

    private void showPublicKeySelectedEntry() {
        handleSelectedEntry(
            keyPairPublicKeyDetailsAction::showPublicKeySelectedEntry,
            trustedCertificatePublicKeyDetailsAction::showPublicKeySelectedEntry,
            null // Not applicable for simple key entries
        );
    }

    private void showPrivateKeySelectedEntry() {
        handleSelectedEntry(
            keyPairPrivateKeyDetailsAction::showPrivateKeySelectedEntry,
            null, // Not applicable for trusted certs
            null  // Not applicable for simple key entries
        );
    }

    /**
     * Add a KeyStore to the set of loaded KeyStores.
     *
     * @param history KeyStore history
     */
    public void addKeyStoreHistory(KeyStoreHistory history) {
        histories.add(history);

        JTable jtKeyStore = createEmptyKeyStoreTable();
        jtKeyStore.getSelectionModel().addListSelectionListener(event -> setDefaultStatusBarText());
        keyStoreTables.add(jtKeyStore);

        JScrollPane jspKeyStore = wrapKeyStoreTableInScrollPane(jtKeyStore);

        KeyStoreTab keyStoreTab = new KeyStoreTab(history.getName(), this, history);
        jkstpKeyStores.addTab(null, jspKeyStore);
        jkstpKeyStores.setTabComponentAt(jkstpKeyStores.getTabCount() - 1, keyStoreTab);
        jkstpKeyStores.setSelectedIndex(jkstpKeyStores.getTabCount() - 1);

        updateControls(true);

        new TableColumnAdjuster(jtKeyStore, keyStoreTableColumns).adjustColumns();

        // If KeyStore is backed up by a file add it to the recent files menu
        if (history.getFile() != null) {
            jmrfRecentFiles.add(createRecentFileMenuItem(jmrfRecentFiles, history.getFile()));
        }
    }

    /**
     * Removed the supplied KeyStore from the set of loaded KeyStores.
     *
     * @param keyStore KeyStore
     */
    public void removeKeyStore(KseKeyStore keyStore) {
        int index = findKeyStoreIndex(keyStore);

        if (index >= 0) {
            keyStoreTables.remove(index);
            histories.remove(index).nullPasswords();
            jkstpKeyStores.remove(index);
        }
    }

    /**
     * Re-draw all keystore tables after preferences have changed.
     *
     * @param preferences settings
     */
    public void redrawKeyStores(KsePreferences preferences) {
        if (keyStoreTables != null) {

            keyStoreTableColumns = preferences.getKeyStoreTableColumns();
            updateTableHeaderPopupMenu();

            int expiryWarnDays = preferences.getExpiryWarnDays();

            for (JTable keyStoreTable : keyStoreTables) {
                KeyStoreHistory history = ((KeyStoreTableModel) keyStoreTable.getModel()).getHistory();
                KeyStoreTableModel ksModel = new KeyStoreTableModel(keyStoreTableColumns, expiryWarnDays);
                try {
                    ksModel.load(history);
                    keyStoreTable.setModel(ksModel);

                    keyStoreTable.setRowSorter(new TableRowSorter<>(ksModel));
                    TableUtil.setColumnsToIconSize(keyStoreTable, 0, 1, 2);
                    TableUtil.addCustomRenderers(keyStoreTable, keyStoreTableColumns);

                    new TableColumnAdjuster(keyStoreTable, keyStoreTableColumns).adjustColumns();
                } catch (GeneralSecurityException | CryptoException e) {
                    DError.displayError(frame, e);
                }
            }
        }
    }

    /**
     * Find the supplied KeyStore in the set of loaded KeyStores.
     *
     * @param keyStore KeyStore to find
     * @return The KeyStore's index
     */
    public int findKeyStoreIndex(KseKeyStore keyStore) {
        for (int i = 0; i < histories.size(); i++) {
            if (keyStore.equals(histories.get(i).getCurrentState().getKeyStore())) {
                return i;
            }
        }

        return -1;
    }

    /**
     * Get the active KeyStore.
     *
     * @return The KeyStore or null if no KeyStore is active
     */
    public KseKeyStore getActiveKeyStore() {
        KeyStoreHistory history = getActiveKeyStoreHistory();
        if (history == null) {
            return null;
        }

        KeyStoreState currentState = history.getCurrentState();
        return currentState.getKeyStore();
    }

    /**
     * Get the active KeyStore history.
     *
     * @return The KeyStore history or null if no KeyStore is active
     */
    public KeyStoreHistory getActiveKeyStoreHistory() {
        if (histories.isEmpty()) {
            return null;
        }

        int selected = jkstpKeyStores.getSelectedIndex();
        return histories.get(selected);
    }

    /**
     * Get all loaded KeyStore histories in display order.
     *
     * @return KeyStore histories
     */
    public KeyStoreHistory[] getKeyStoreHistories() {
        return histories.toArray(KeyStoreHistory[]::new);
    }

    /**
     * Focus on the supplied KeyStore.
     *
     * @param keyStore KeyStore
     */
    public void focusOnKeyStore(KseKeyStore keyStore) {
        int index = findKeyStoreIndex(keyStore);

        if (index >= 0) {
            jkstpKeyStores.setSelectedIndex(index);
        }
    }

    public JTable getActiveKeyStoreTable() {
        if (keyStoreTables.isEmpty()) {
            return null;
        }

        int selected = jkstpKeyStores.getSelectedIndex();
        return keyStoreTables.get(selected);
    }

    /**
     * Get the selected entry as a drag entry for DnD.
     *
     * @return Drag entry or null if entry could not be dragged
     */
    public DragEntry dragSelectedEntry() {
        try {
            KeyStoreHistory history = getActiveKeyStoreHistory();

            if (history == null) {
                return null; // No KeyStore to drag from
            }

            KeyStoreState currentState = history.getCurrentState();
            KseKeyStore keyStore = currentState.getKeyStore();
            String alias = getSelectedEntryAlias();
            KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

            if (alias == null) {
                // No selected entry to drag
                return null;
            }

            if (KeyStoreUtil.isKeyEntry(alias, keyStore)) {
                JOptionPane.showMessageDialog(frame, res.getString("KseFrame.NoDragKeyEntry.message"),
                                              KSE.getApplicationName(), JOptionPane.WARNING_MESSAGE);
                return null;
            }

            if (KeyStoreUtil.isKeyPairEntry(alias, keyStore) && type.hasExportablePrivateKeys()) {

                // Otherwise entry must already be unlocked to get password
                Password password = currentState.getEntryPassword(alias);

                if (password == null && type.hasEntryPasswords()) {
                    JOptionPane.showMessageDialog(frame, res.getString("KseFrame.NoDragLockedKeyPairEntry.message"),
                                                  KSE.getApplicationName(), JOptionPane.WARNING_MESSAGE);
                    return null;
                }

                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias,
                        password != null ? password.toCharArray() : null);
                Certificate[] certificateChain = keyStore.getCertificateChain(alias);

                return new DragKeyPairEntry(alias, privateKey, password, certificateChain);
            } else {
                Certificate trustedCertificate = keyStore.getCertificate(alias);
                return new DragTrustedCertificateEntry(alias, trustedCertificate);
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
            return null;
        }
    }

    /**
     * Get the alias of the entry currently selected in the KeyStore table if
     * any.
     *
     * @return Alias or null if none selected
     */
    public String getSelectedEntryAlias() {
        JTable jtKeyStore = getActiveKeyStoreTable();
        int row = jtKeyStore.getSelectedRow();

        if (row == -1) {
            return null;
        }

        return (String) jtKeyStore.getValueAt(row, 3);
    }

    /**
     * Get the aliases of all entries currently selected in the KeyStore
     *
     * @return Selected aliases (may be an empty array, but never null)
     */
    public String[] getSelectedEntryAliases() {
        JTable jtKeyStore = getActiveKeyStoreTable();
        int[] rows = jtKeyStore.getSelectedRows();

        String[] retval = new String[rows.length];

        for (int i = 0; i < rows.length; i++) {
            retval[i] = (String) jtKeyStore.getValueAt(rows[i], 3);
        }

        return retval;
    }

    public String getNextEntrysAlias() {
        JTable jtKeyStore = getActiveKeyStoreTable();
        int[] rows = jtKeyStore.getSelectedRows();

        // no row selected
        if (rows.length == 0) {
            return null;
        }

        int rowCount = jtKeyStore.getModel().getRowCount();
        if (rows.length == rowCount) {
            // all rows are selected
            return null;
        } else {
            int idx;
            int max = Arrays.stream(rows).max().getAsInt();
            if (max < (rowCount - 1)) {
                // last selected row is not the last one, return alias of next row
                idx = max + 1;
            } else {
                // last selected row is the last one, return alias of previous row
                int min = Arrays.stream(rows).min().getAsInt();
                if (min >= 1) {
                    idx = min - 1;
                } else {
                    idx = -1;
                    Arrays.sort(rows);
                    for (int i = rows.length - 1; i >= 1; i--) {
                        if (rows[i] - rows[i - 1] > 1) { // found a gap
                            idx = rows[i] - 1;
                            break;
                        }
                    }
                }
            }
            if (idx >= 0) {
                return (String) jtKeyStore.getValueAt(idx, 3);
            } else {
                return null;
            }
        }
    }

    private int getNumberOfEntries() {
        JTable jtKeyStore = getActiveKeyStoreTable();
        return jtKeyStore.getModel().getRowCount();
    }

    public void setSelectedEntriesByAliases(String... aliases) {
        JTable jtKeyStore = getActiveKeyStoreTable();
        jtKeyStore.requestFocusInWindow();

        ListSelectionModel selectionModel = jtKeyStore.getSelectionModel();
        selectionModel.clearSelection();
        Set<String> aliasesToSelect = new HashSet<>(Arrays.asList(aliases));
        for (int i = 0; i < jtKeyStore.getRowCount(); i++) {
            if (aliasesToSelect.contains(jtKeyStore.getValueAt(i, 3))) {
                selectionModel.addSelectionInterval(i, i);
            }
        }
    }

    public void keyStoreclearSelection() {
        JTable jtKeyStore = getActiveKeyStoreTable();
        ListSelectionModel selectionModel = jtKeyStore.getSelectionModel();
        selectionModel.clearSelection();
    }

    public void setSelectedEntriesByAliases(Set<String> aliasesToSelect) {
        JTable jtKeyStore = getActiveKeyStoreTable();
        jtKeyStore.requestFocusInWindow();

        ListSelectionModel selectionModel = jtKeyStore.getSelectionModel();
        for (int i = 0; i < jtKeyStore.getRowCount(); i++) {
            if (aliasesToSelect.contains(jtKeyStore.getValueAt(i, 3))) {
                selectionModel.addSelectionInterval(i, i);
            }
        }
        jtKeyStore.scrollRectToVisible(jtKeyStore.getCellRect(jtKeyStore.getSelectedRow(), 0, false));
    }

    /**
     * Update the frame's controls dependent on the state of its open and active
     * KeyStores.
     *
     * @param keyStoreContentsChanged Have the active KeyStore's contents changed?
     */
    public void updateControls(boolean keyStoreContentsChanged) {
        KeyStoreHistory history = getActiveKeyStoreHistory();

        if (history == null) {
            updateControlsNoKeyStoresOpen();
            return;
        }

        KeyStoreState currentState = history.getCurrentState();

        // Reload KeyStore in table if it has changed
        if (keyStoreContentsChanged) {
            try {
                String[] selectedAliases = getSelectedEntryAliases();

                ((KeyStoreTableModel) getActiveKeyStoreTable().getModel()).load(history);

                // Loading the model loses the selected entry - preserve it
                if (selectedAliases.length > 0) {
                    setSelectedEntriesByAliases(selectedAliases);
                }
            } catch (GeneralSecurityException | CryptoException ex) {
                DError.displayError(frame, ex);
            }
        }

        // Can save if active KeyStore has not been saved
        saveAction.setEnabled(!currentState.isSavedState());

        // Can save all if any KeyStore has been changed since saved
        boolean saveAll = false;
        for (KeyStoreHistory h : histories) {
            if (!h.getCurrentState().isSavedState()) {
                saveAll = true; // Yes - can Save All
                break;
            }
        }

        saveAllAction.setEnabled(saveAll);

        // Can close
        closeAction.setEnabled(true);
        closeAllAction.setEnabled(true);

        // Can close others?
        closeOthersAction.setEnabled(jkstpKeyStores.getTabCount() > 1);

        KseKeyStore keyStore = currentState.getKeyStore();
        KeyStoreType type = KeyStoreType.resolveJce(keyStore.getType());

        // Can Save As
        if (type.isFileBased()) {
            saveAsAction.setEnabled(true);
        }

        // May be able to undo/redo
        updateUndoRedoControls(currentState);

        // May be able to cut/copy/paste
        if (type.isFileBased()) {
            updateCutCopyPasteControls();
        }

        // Can find
        findAction.setEnabled(true);

        // Can use tools on
        generateKeyPairAction.setEnabled(true);
        generateSecretKeyAction.setEnabled(type.supportsKeyEntries());
        importTrustedCertificateAction.setEnabled(true);
        importKeyPairAction.setEnabled(true);
        storePassphraseAction.setEnabled(true);
        storePassphraseAction.setEnabled(type.supportsKeyEntries());
        propertiesAction.setEnabled(true);
        exportCsvAction.setEnabled(true);
        if (type.isFileBased()) {
            setPasswordAction.setEnabled(true);
        }

        // Show default status bar display
        setDefaultStatusBarText();

        // Passwords, and therefore unlocking, are not relevant for PKCS #12 or KeyStores that are not file-based
        if (!type.hasEntryPasswords() || !type.isFileBased()) {
            unlockKeyPairAction.setEnabled(false);
            setKeyPairPasswordAction.setEnabled(false);
            unlockKeyAction.setEnabled(false);
            setKeyPasswordAction.setEnabled(false);
        } else {
            unlockKeyPairAction.setEnabled(true);
            setKeyPairPasswordAction.setEnabled(true);
            unlockKeyAction.setEnabled(true);
            setKeyPasswordAction.setEnabled(true);
        }

        // Special restrictions for MSCAPI and PKCS#11 type
        if (type == KeyStoreType.MS_CAPI_PERSONAL || type == KeyStoreType.MS_CAPI_ROOT || type == KeyStoreType.PKCS11) {

            keyPairPrivateKeyDetailsAction.setEnabled(false);
            keyDetailsAction.setEnabled(false);

            importTrustedCertificateAction.setEnabled(true);

            renameKeyAction.setEnabled(false);
            renameKeyPairAction.setEnabled(false);
            renameTrustedCertificateAction.setEnabled(false);

            exportKeyPairAction.setEnabled(false);
            exportKeyPairPrivateKeyAction.setEnabled(false);

            jmKeyPairEditCertChain.setEnabled(false);
            appendToCertificateChainAction.setEnabled(false);
            removeFromCertificateChainAction.setEnabled(false);

            // "UnsupportedOperationException" ...
            jmKeyPairImportCaReply.setEnabled(false);
        } else if (type == KeyStoreType.KEYCHAIN) {

            keyPairPrivateKeyDetailsAction.setEnabled(true);
            keyDetailsAction.setEnabled(true);

            importTrustedCertificateAction.setEnabled(false);

            renameKeyAction.setEnabled(true);
            renameKeyPairAction.setEnabled(true);
            renameTrustedCertificateAction.setEnabled(false);

            exportKeyPairAction.setEnabled(true);
            exportKeyPairPrivateKeyAction.setEnabled(true);

            // Keychain manages the hierarchy. Edits are not persisted.
            jmKeyPairEditCertChain.setEnabled(false);
            appendToCertificateChainAction.setEnabled(false);
            removeFromCertificateChainAction.setEnabled(false);

            jmKeyPairImportCaReply.setEnabled(true);
        } else {
            keyPairPrivateKeyDetailsAction.setEnabled(true);
            keyDetailsAction.setEnabled(true);

            importTrustedCertificateAction.setEnabled(true);

            renameKeyAction.setEnabled(true);
            renameKeyPairAction.setEnabled(true);
            renameTrustedCertificateAction.setEnabled(true);

            exportKeyPairAction.setEnabled(true);
            exportKeyPairPrivateKeyAction.setEnabled(true);

            jmKeyPairEditCertChain.setEnabled(true);
            appendToCertificateChainAction.setEnabled(true);
            removeFromCertificateChainAction.setEnabled(true);

            jmKeyPairImportCaReply.setEnabled(true);
        }

        // KeyStore type menu items
        if (type.isFileBased()) {
            jmChangeType.setEnabled(true);

            if (type == JKS) {
                jrbmiChangeTypeJks.setSelected(true);
                jrbmiKeyStoreChangeTypeJks.setSelected(true);
            } else if (type == JCEKS) {
                jrbmiChangeTypeJceks.setSelected(true);
                jrbmiKeyStoreChangeTypeJceks.setSelected(true);
            } else if (type == PKCS12) {
                jrbmiChangeTypePkcs12.setSelected(true);
                jrbmiKeyStoreChangeTypePkcs12.setSelected(true);
            } else if (type == BKS) {
                jrbmiChangeTypeBks.setSelected(true);
                jrbmiKeyStoreChangeTypeBks.setSelected(true);
            } else if (type == BCFKS) {
                jrbmiChangeTypeBcfks.setSelected(true);
                jrbmiKeyStoreChangeTypeBcfks.setSelected(true);
            } else if (type == PEM) {
                jrbmiChangeTypePem.setSelected(true);
                jrbmiKeyStoreChangeTypePem.setSelected(true);
            } else {
                jrbmiChangeTypeUber.setSelected(true);
                jrbmiKeyStoreChangeTypeUber.setSelected(true);
            }
        } else {
            jmKeyStoreChangeType.setEnabled(false);
        }

        // Show KeyStores tabbed pane
        frame.getContentPane().remove(jQuickStart);
        frame.getContentPane().add(jkstpKeyStores, BorderLayout.CENTER);

        updateKeyStoreTabsText();
        updateApplicationTitle();

        getActiveKeyStoreTable().requestFocusInWindow();

        frame.repaint();
    }

    private void updateControlsNoKeyStoresOpen() {
        // Nothing to close
        closeAction.setEnabled(false);
        closeOthersAction.setEnabled(false);
        closeAllAction.setEnabled(false);

        // Nothing to save
        saveAction.setEnabled(false);
        saveAsAction.setEnabled(false);
        saveAllAction.setEnabled(false);

        // Nothing to undo/redo
        undoAction.setEnabled(false);
        redoAction.setEnabled(false);

        // Nothing to cut/copy/paste
        cutAction.setEnabled(false);
        cutKeyPairAction.setEnabled(false);
        cutTrustedCertificateAction.setEnabled(false);
        copyAction.setEnabled(false);
        compareCertificateAction.setEnabled(false);
        findAction.setEnabled(false);
        copyKeyPairAction.setEnabled(false);
        copyTrustedCertificateAction.setEnabled(false);
        pasteAction.setEnabled(false);

        // Nothing to use tools on
        generateKeyPairAction.setEnabled(false);
        generateSecretKeyAction.setEnabled(false);
        importTrustedCertificateAction.setEnabled(false);
        importKeyPairAction.setEnabled(false);
        storePassphraseAction.setEnabled(false);
        setPasswordAction.setEnabled(false);
        jmChangeType.setEnabled(false);
        propertiesAction.setEnabled(false);
        exportCsvAction.setEnabled(false);

        // No current KeyStore type
        jrbmiChangeTypeJks.setSelected(false);
        jrbmiChangeTypeJceks.setSelected(false);
        jrbmiChangeTypePkcs12.setSelected(false);
        jrbmiChangeTypePem.setSelected(false);
        jrbmiChangeTypeBks.setSelected(false);
        jrbmiChangeTypeBcfks.setSelected(false);
        jrbmiChangeTypeUber.setSelected(false);
        jrbmiKeyStoreChangeTypeJks.setSelected(false);
        jrbmiKeyStoreChangeTypeJceks.setSelected(false);
        jrbmiKeyStoreChangeTypePkcs12.setSelected(false);
        jrbmiKeyStoreChangeTypePem.setSelected(false);
        jrbmiKeyStoreChangeTypeBks.setSelected(false);
        jrbmiKeyStoreChangeTypeBcfks.setSelected(false);
        jrbmiKeyStoreChangeTypeUber.setSelected(false);

        // Show Quick Start pane
        frame.getContentPane().remove(jkstpKeyStores);
        frame.getContentPane().add(jQuickStart, BorderLayout.CENTER);

        updateApplicationTitle();

        setDefaultStatusBarText();

        frame.repaint();
    }

    private void updateUndoRedoControls(KeyStoreState state) {
        undoAction.setEnabled(state.hasPreviousState());
        redoAction.setEnabled(state.hasNextState());
    }

    private void updateCutCopyPasteControls() {
        // Can cut and copy if a KeyStore entry is selected
        boolean cutAndCopyEnabled = getActiveKeyStoreTable().getSelectedRow() != -1;

        cutAction.setEnabled(cutAndCopyEnabled);
        compareCertificateAction.setEnabled(getActiveKeyStoreTable().getSelectedRowCount() == 2);
        cutKeyPairAction.setEnabled(cutAndCopyEnabled);
        cutTrustedCertificateAction.setEnabled(cutAndCopyEnabled);
        copyAction.setEnabled(cutAndCopyEnabled);
        copyKeyPairAction.setEnabled(cutAndCopyEnabled);
        copyTrustedCertificateAction.setEnabled(cutAndCopyEnabled);

        // Can paste if anything is in buffer
        pasteAction.setEnabled(Buffer.isPopulated());
    }

    private void updateKeyStoreTabsText() {
        for (int i = 0; i < histories.size(); i++) {
            KeyStoreHistory history = histories.get(i);

            KeyStoreTab keyStoreTab = (KeyStoreTab) jkstpKeyStores.getTabComponentAt(i);

            // Tab component may not be available yet
            if (keyStoreTab != null) {
                if (!history.getCurrentState().isSavedState()) {
                    // Unsaved Changes - append '*'
                    String title = MessageFormat.format("{0} *", history.getName());
                    keyStoreTab.updateTitle(title);
                } else {
                    String title = history.getName();
                    keyStoreTab.updateTitle(title);
                }

                // Set tooltip text to be the same as is displayed for the
                // KeyStore's status bar text
                jkstpKeyStores.setToolTipTextAt(i, getKeyStoreStatusText(history));
                keyStoreTab.validate();
            }
        }
    }

    private void updateApplicationTitle() {
        // Title: "[KeyStore Name [*] - ] Application Name and Version"

        String appName = MessageFormat.format("{0} {1}", KSE.getApplicationName(), KSE.getApplicationVersion());

        KeyStoreHistory history = getActiveKeyStoreHistory();

        if (history == null) {
            frame.setTitle(appName);
        } else {
            String keyStoreName = history.getName();

            if (!history.getCurrentState().isSavedState()) {
                frame.setTitle(MessageFormat.format("{0} * - {1}", keyStoreName, appName));
            } else {
                frame.setTitle(MessageFormat.format("{0} - {1}", keyStoreName, appName));
            }
        }
    }

    /**
     * Display the supplied text in the status bar.
     *
     * @param status Text to display
     */
    @Override
    public void setStatusBarText(String status) {
        jlStatusBar.setText(status);
    }

    /**
     * Set the text in the status bar to reflect the status of the active
     * KeyStore.
     */
    @Override
    public void setDefaultStatusBarText() {
        KeyStoreHistory history = getActiveKeyStoreHistory();

        if (history == null) {
            setStatusBarText(res.getString("KseFrame.noKeyStore.statusbar"));
        } else {
            setStatusBarText(getKeyStoreStatusText(history));
        }
    }

    private String getKeyStoreStatusText(KeyStoreHistory history) {
        // Status Text: 'KeyStore Type, Size, Path'
        KeyStoreState currentState = history.getCurrentState();

        KseKeyStore ksLoaded = currentState.getKeyStore();

        int size;
        try {
            size = ksLoaded.size();
        } catch (KeyStoreException ex) {
            DError.displayError(frame, ex);
            return "";
        }

        KeyStoreType keyStoreType = currentState.getType();
        String[] aliases = getSelectedEntryAliases();

        return MessageFormat.format(res.getString("KseFrame.entries.statusbar"), keyStoreType.friendly(), size,
                                    aliases.length, history.getPath());
    }

    /**
     * Get frame's size and position. Used to get size on exit.
     *
     * @param keyStoresClosed Were all KeyStores closed on exit?
     * @return Size and position
     */
    public Rectangle getSizeAndPosition(boolean keyStoresClosed) {
        Rectangle sizeAndPosition = new Rectangle();

        if (keyStoresClosed) {
            sizeAndPosition.width = jkstpKeyStores.getWidth();
            sizeAndPosition.height = jkstpKeyStores.getHeight();
        } else {
            sizeAndPosition.width = jQuickStart.getWidth();
            sizeAndPosition.height = jQuickStart.getHeight();
        }

        sizeAndPosition.x = frame.getX();
        sizeAndPosition.y = frame.getY();

        return sizeAndPosition;
    }

    /**
     * Get recently opened files.
     *
     * @return Recently opened files
     */
    public File[] getRecentFiles() {
        return jmrfRecentFiles.getRecentFiles();
    }

    /**
     * Add a file to the top of the recently opened files.
     *
     * @param recentFile Recent file
     */
    public void addRecentFile(File recentFile) {
        jmrfRecentFiles.add(createRecentFileMenuItem(jmrfRecentFiles, recentFile));
    }

    /**
     * Set tab layout policy - must be one of JTabbedPane.WRAP_TAB_LAYOUT or
     * JTabbedPane.SCROLL_TAB_LAYOUT to take effect.
     *
     * @param tabLayoutPolicy Tab layout policy
     */
    public void setKeyStoreTabLayoutPolicy(int tabLayoutPolicy) {
        if (tabLayoutPolicy == JTabbedPane.WRAP_TAB_LAYOUT || tabLayoutPolicy == JTabbedPane.SCROLL_TAB_LAYOUT) {
            jkstpKeyStores.setTabLayoutPolicy(tabLayoutPolicy);
            preferences.setTabLayout(tabLayoutPolicy);
        }
    }

    /**
     * If the toolbar is currently displayed hide it and vice versa.
     */
    public void showHideToolBar() {
        Container contentPane = frame.getContentPane();
        boolean toolBarShown = false;
        for (int i = 0; i < contentPane.getComponentCount(); i++) {
            if (contentPane.getComponent(i).equals(jtbToolBar)) {
                toolBarShown = true;
                break;
            }
        }

        if (toolBarShown) {
            frame.getContentPane().remove(jtbToolBar);
            preferences.setShowToolBar(false);
        } else {
            frame.getContentPane().add(jtbToolBar, BorderLayout.NORTH);
            preferences.setShowToolBar(true);
        }
    }

    /**
     * If the status bar is currently displayed hide it and vice versa.
     */
    public void showHideStatusBar() {
        Container contentPane = frame.getContentPane();
        boolean statusBarShown = false;
        for (int i = 0; i < contentPane.getComponentCount(); i++) {
            if (contentPane.getComponent(i).equals(jlStatusBar)) {
                statusBarShown = true;
                break;
            }
        }

        if (statusBarShown) {
            frame.getContentPane().remove(jlStatusBar);
            preferences.setShowStatusBar(false);
        } else {
            frame.getContentPane().add(jlStatusBar, BorderLayout.SOUTH);
            preferences.setShowStatusBar(true);
        }
    }

    private void initTableHeaderPopupMenu() {
        jpmTableHeader = new JPopupMenu();

        // Create checkbox menu items for each column
        jcbmiHeaderAlgorithm = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.AlgorithmColumn"));
        jcbmiHeaderAlgorithm.setSelected(keyStoreTableColumns.getEnableAlgorithm());
        jcbmiHeaderAlgorithm.addActionListener(e -> toggleColumnVisibility("Algorithm"));
        jpmTableHeader.add(jcbmiHeaderAlgorithm);

        jcbmiHeaderKeySize = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.KeySizeColumn"));
        jcbmiHeaderKeySize.setSelected(keyStoreTableColumns.getEnableKeySize());
        jcbmiHeaderKeySize.addActionListener(e -> toggleColumnVisibility("KeySize"));
        jpmTableHeader.add(jcbmiHeaderKeySize);

        jcbmiHeaderCurve = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.CurveColumn"));
        jcbmiHeaderCurve.setSelected(keyStoreTableColumns.getEnableCurve());
        jcbmiHeaderCurve.addActionListener(e -> toggleColumnVisibility("Curve"));
        jpmTableHeader.add(jcbmiHeaderCurve);

        jcbmiHeaderCertificateValidityStart = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.CertValidityStartColumn"));
        jcbmiHeaderCertificateValidityStart.setSelected(keyStoreTableColumns.getEnableCertificateValidityStart());
        jcbmiHeaderCertificateValidityStart.addActionListener(e -> toggleColumnVisibility("CertificateValidityStart"));
        jpmTableHeader.add(jcbmiHeaderCertificateValidityStart);

        jcbmiHeaderCertificateExpiry = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.CertExpiryColumn"));
        jcbmiHeaderCertificateExpiry.setSelected(keyStoreTableColumns.getEnableCertificateExpiry());
        jcbmiHeaderCertificateExpiry.addActionListener(e -> toggleColumnVisibility("CertificateExpiry"));
        jpmTableHeader.add(jcbmiHeaderCertificateExpiry);

        jcbmiHeaderLastModified = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.LastModifiedColumn"));
        jcbmiHeaderLastModified.setSelected(keyStoreTableColumns.getEnableLastModified());
        jcbmiHeaderLastModified.addActionListener(e -> toggleColumnVisibility("LastModified"));
        jpmTableHeader.add(jcbmiHeaderLastModified);

        jpmTableHeader.addSeparator();

        jcbmiHeaderAKI = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.AKIColumn"));
        jcbmiHeaderAKI.setSelected(keyStoreTableColumns.getEnableAKI());
        jcbmiHeaderAKI.addActionListener(e -> toggleColumnVisibility("AKI"));
        jpmTableHeader.add(jcbmiHeaderAKI);

        jcbmiHeaderSKI = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.SKIColumn"));
        jcbmiHeaderSKI.setSelected(keyStoreTableColumns.getEnableSKI());
        jcbmiHeaderSKI.addActionListener(e -> toggleColumnVisibility("SKI"));
        jpmTableHeader.add(jcbmiHeaderSKI);

        jcbmiHeaderIssuerDN = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.IssuerDNColumn"));
        jcbmiHeaderIssuerDN.setSelected(keyStoreTableColumns.getEnableIssuerDN());
        jcbmiHeaderIssuerDN.addActionListener(e -> toggleColumnVisibility("IssuerDN"));
        jpmTableHeader.add(jcbmiHeaderIssuerDN);

        jcbmiHeaderSubjectDN = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.SubjectDNColumn"));
        jcbmiHeaderSubjectDN.setSelected(keyStoreTableColumns.getEnableSubjectDN());
        jcbmiHeaderSubjectDN.addActionListener(e -> toggleColumnVisibility("SubjectDN"));
        jpmTableHeader.add(jcbmiHeaderSubjectDN);

        jcbmiHeaderIssuerCN = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.IssuerCNColumn"));
        jcbmiHeaderIssuerCN.setSelected(keyStoreTableColumns.getEnableIssuerCN());
        jcbmiHeaderIssuerCN.addActionListener(e -> toggleColumnVisibility("IssuerCN"));
        jpmTableHeader.add(jcbmiHeaderIssuerCN);

        jcbmiHeaderSubjectCN = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.SubjectCNColumn"));
        jcbmiHeaderSubjectCN.setSelected(keyStoreTableColumns.getEnableSubjectCN());
        jcbmiHeaderSubjectCN.addActionListener(e -> toggleColumnVisibility("SubjectCN"));
        jpmTableHeader.add(jcbmiHeaderSubjectCN);

        jcbmiHeaderIssuerO = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.IssuerOColumn"));
        jcbmiHeaderIssuerO.setSelected(keyStoreTableColumns.getEnableIssuerO());
        jcbmiHeaderIssuerO.addActionListener(e -> toggleColumnVisibility("IssuerO"));
        jpmTableHeader.add(jcbmiHeaderIssuerO);

        jcbmiHeaderSubjectO = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.SubjectOColumn"));
        jcbmiHeaderSubjectO.setSelected(keyStoreTableColumns.getEnableSubjectO());
        jcbmiHeaderSubjectO.addActionListener(e -> toggleColumnVisibility("SubjectO"));
        jpmTableHeader.add(jcbmiHeaderSubjectO);

        jpmTableHeader.addSeparator();

        jcbmiHeaderSerialNumberHex = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.SerialNumberHex"));
        jcbmiHeaderSerialNumberHex.setSelected(keyStoreTableColumns.getEnableSerialNumberHex());
        jcbmiHeaderSerialNumberHex.addActionListener(e -> toggleColumnVisibility("SerialNumberHex"));
        jpmTableHeader.add(jcbmiHeaderSerialNumberHex);

        jcbmiHeaderSerialNumberDec = new JCheckBoxMenuItem(res.getString("KeyStoreTableModel.SerialNumberDec"));
        jcbmiHeaderSerialNumberDec.setSelected(keyStoreTableColumns.getEnableSerialNumberDec());
        jcbmiHeaderSerialNumberDec.addActionListener(e -> toggleColumnVisibility("SerialNumberDec"));
        jpmTableHeader.add(jcbmiHeaderSerialNumberDec);

        if (keyStoreTableColumns.getFingerprintAlg() == null) {
            keyStoreTableColumns.setFingerprintAlg(preferences.getCertificateFingerprintAlgorithm());
        }
        jcbmiHeaderFingerprint = new JCheckBoxMenuItem(
                MessageFormat.format(res.getString("KeyStoreTableModel.Fingerprint"),
                                     keyStoreTableColumns.getFingerprintAlg()));
        jcbmiHeaderFingerprint.setSelected(keyStoreTableColumns.getEnableFingerprint());
        jcbmiHeaderFingerprint.addActionListener(e -> toggleColumnVisibility("Fingerprint"));
        jpmTableHeader.add(jcbmiHeaderFingerprint);
    }

    private void updateTableHeaderPopupMenu() {
        jcbmiHeaderAlgorithm.setSelected(keyStoreTableColumns.getEnableAlgorithm());
        jcbmiHeaderKeySize.setSelected(keyStoreTableColumns.getEnableKeySize());
        jcbmiHeaderCurve.setSelected(keyStoreTableColumns.getEnableCurve());
        jcbmiHeaderCertificateValidityStart.setSelected(keyStoreTableColumns.getEnableCertificateValidityStart());
        jcbmiHeaderCertificateExpiry.setSelected(keyStoreTableColumns.getEnableCertificateExpiry());
        jcbmiHeaderLastModified.setSelected(keyStoreTableColumns.getEnableLastModified());
        jcbmiHeaderAKI.setSelected(keyStoreTableColumns.getEnableAKI());
        jcbmiHeaderSKI.setSelected(keyStoreTableColumns.getEnableSKI());
        jcbmiHeaderIssuerDN.setSelected(keyStoreTableColumns.getEnableIssuerDN());
        jcbmiHeaderSubjectDN.setSelected(keyStoreTableColumns.getEnableSubjectDN());
        jcbmiHeaderIssuerCN.setSelected(keyStoreTableColumns.getEnableIssuerCN());
        jcbmiHeaderSubjectCN.setSelected(keyStoreTableColumns.getEnableSubjectCN());
        jcbmiHeaderIssuerO.setSelected(keyStoreTableColumns.getEnableIssuerO());
        jcbmiHeaderSubjectO.setSelected(keyStoreTableColumns.getEnableSubjectO());
        jcbmiHeaderSerialNumberHex.setSelected(keyStoreTableColumns.getEnableSerialNumberHex());
        jcbmiHeaderSerialNumberDec.setSelected(keyStoreTableColumns.getEnableSerialNumberDec());
        jcbmiHeaderFingerprint.setSelected(keyStoreTableColumns.getEnableFingerprint());
        jcbmiHeaderFingerprint.setText(MessageFormat.format(res.getString("KeyStoreTableModel.Fingerprint"),
                                                                     keyStoreTableColumns.getFingerprintAlg()));
    }

    private void toggleColumnVisibility(String columnType) {
        switch (columnType) {
        case "Algorithm":
            keyStoreTableColumns.setEnableAlgorithm(jcbmiHeaderAlgorithm.isSelected());
            break;
        case "KeySize":
            keyStoreTableColumns.setEnableKeySize(jcbmiHeaderKeySize.isSelected());
            break;
        case "Curve":
            keyStoreTableColumns.setEnableCurve(jcbmiHeaderCurve.isSelected());
            break;
        case "CertificateValidityStart":
            keyStoreTableColumns.setEnableCertificateValidityStart(jcbmiHeaderCertificateValidityStart.isSelected());
            break;
        case "CertificateExpiry":
            keyStoreTableColumns.setEnableCertificateExpiry(jcbmiHeaderCertificateExpiry.isSelected());
            break;
        case "LastModified":
            keyStoreTableColumns.setEnableLastModified(jcbmiHeaderLastModified.isSelected());
            break;
        case "AKI":
            keyStoreTableColumns.setEnableAKI(jcbmiHeaderAKI.isSelected());
            break;
        case "SKI":
            keyStoreTableColumns.setEnableSKI(jcbmiHeaderSKI.isSelected());
            break;
        case "IssuerDN":
            keyStoreTableColumns.setEnableIssuerDN(jcbmiHeaderIssuerDN.isSelected());
            break;
        case "SubjectDN":
            keyStoreTableColumns.setEnableSubjectDN(jcbmiHeaderSubjectDN.isSelected());
            break;
        case "IssuerCN":
            keyStoreTableColumns.setEnableIssuerCN(jcbmiHeaderIssuerCN.isSelected());
            break;
        case "SubjectCN":
            keyStoreTableColumns.setEnableSubjectCN(jcbmiHeaderSubjectCN.isSelected());
            break;
        case "IssuerO":
            keyStoreTableColumns.setEnableIssuerO(jcbmiHeaderIssuerO.isSelected());
            break;
        case "SubjectO":
            keyStoreTableColumns.setEnableSubjectO(jcbmiHeaderSubjectO.isSelected());
            break;
        case "SerialNumberHex":
            keyStoreTableColumns.setEnableSerialNumberHex(jcbmiHeaderSerialNumberHex.isSelected());
            break;
        case "SerialNumberDec":
            keyStoreTableColumns.setEnableSerialNumberDec(jcbmiHeaderSerialNumberDec.isSelected());
            break;
        case "Fingerprint":
            keyStoreTableColumns.setEnableFingerprint(jcbmiHeaderFingerprint.isSelected());
        }

        preferences.setKeyStoreTableColumns(keyStoreTableColumns);
        redrawKeyStores(preferences);
    }
}
