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
package org.kse.gui.actions;

import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.kse.crypto.encryption.EncryptionException;
import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CursorUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DSavingPasswords;
import org.kse.gui.dialogs.DUnlockingPasswords;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetNewPassword;
import org.kse.gui.password.DGetPassword;
import org.kse.gui.passwordmanager.DInitPasswordManager;
import org.kse.gui.passwordmanager.DUnlockPasswordManager;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.passwordmanager.PasswordAndDecision;
import org.kse.gui.passwordmanager.PasswordManager;
import org.kse.gui.preferences.data.KsePreferences;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Abstract base class for all KeyStore Explorer actions.
 */
public abstract class KeyStoreExplorerAction extends AbstractAction {
    private static final long serialVersionUID = 1L;

    /**
     * Resource bundle
     */
    protected static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/actions/resources");

    /**
     * KeyStore Explorer frame
     */
    protected KseFrame kseFrame;

    /**
     * Underlying JFrame
     */
    protected JFrame frame;

    /**
     * Application settings
     */
    protected KsePreferences preferences;

    /**
     * Construct a KeyStoreExplorerAction.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public KeyStoreExplorerAction(KseFrame kseFrame) {
        this.kseFrame = kseFrame;
        frame = kseFrame.getUnderlyingFrame();
        preferences = kseFrame.getPreferences();
    }

    /**
     * Perform action. Calls doAction.
     *
     * @param evt Action event
     */
    @Override
    public void actionPerformed(ActionEvent evt) {
        try {
            kseFrame.setDefaultStatusBarText();
            CursorUtil.setCursorBusy(frame);
            kseFrame.getUnderlyingFrame().repaint();
            doAction();
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        } finally {
            CursorUtil.setCursorFree(frame);
        }
    }

    /**
     * Do the action.
     */
    protected abstract void doAction();

    /**
     * Get an entry's password. Queries the KeyStore history first and, if the
     * password is not found there, asks the user for it.
     *
     * @param alias Entry alias
     * @param state KeyStore state
     * @return Password or null if it could not be retrieved
     */
    protected Password getEntryPassword(String alias, KeyStoreState state) {
        Password password = state.getEntryPassword(alias);

        if (password == null) {
            if (!KeyStoreType.resolveJce(state.getKeyStore().getType()).hasEntryPasswords()) {
                password = new Password((char[]) null);
            } else {
                password = unlockEntry(alias, state);
            }
        }

        return password;
    }

    /**
     * Unlock a key or key pair entry. Updates the KeyStore history with the
     * password.
     *
     * @param alias Entry's alias
     * @param state KeyStore state
     * @return Key pair password if successful, null otherwise
     */
    protected Password unlockEntry(String alias, KeyStoreState state) {
        try {
            KseKeyStore keyStore = state.getKeyStore();
            KeyStoreHistory history = state.getHistory();
            KeyStoreType keyStoreType = history.getCurrentState().getType();
            Password password = null;

            // try to get password from password manager
            if (history.getFile() != null) {
                password = PasswordManager.getInstance()
                                          .getKeyStoreEntryPassword(history.getFile(), alias)
                                          .map(Password::new)
                                          .orElse(null);
            }

            // for PKCS#12 keystores, the entry password is usually the same as the keystore password
            if (password == null && (keyStoreType == KeyStoreType.PKCS12 || keyStoreType == KeyStoreType.KEYCHAIN)) {
                Password keystorePassword = state.getPassword();
                if (keystorePassword != null) {
                    password = new Password(keystorePassword.toCharArray());
                    try {
                        // test if password is correct
                        keyStore.getKey(alias, password.toCharArray());
                    } catch (GeneralSecurityException ex) {
                        password = null;
                    }
                }
            }

            // no password found, ask user to enter it
            if (password == null) {
                DGetPassword dGetPassword = new DGetPassword(frame, MessageFormat.format(
                        res.getString("KeyStoreExplorerAction.UnlockEntry.Title"), alias));
                dGetPassword.setLocationRelativeTo(frame);
                dGetPassword.setVisible(true);
                password = dGetPassword.getPassword();
            }

            if (password == null) {
                return null;
            }

            keyStore.getKey(alias, password.toCharArray()); // Test password is correct

            // add pwd to pwd-mgr - no-op if the keystore (and its pwd) is not known by the pwd-mgr (all or nothing)
            PasswordManager.getInstance().updateEntryPassword(history.getFile(), alias, password.toCharArray());

            state.setEntryPassword(alias, password);
            kseFrame.updateControls(true);

            return password;
        } catch (GeneralSecurityException ex) {
            String problemStr =
                    MessageFormat.format(res.getString("KeyStoreExplorerAction.NoUnlockEntry.Problem"), alias);

            String[] causes = new String[] { res.getString("KeyStoreExplorerAction.PasswordIncorrectEntry.Cause") };

            Problem problem = new Problem(problemStr, causes, ex);

            DProblem dProblem =
                    new DProblem(frame, res.getString("KeyStoreExplorerAction.ProblemUnlockingEntry.Title"), problem);
            dProblem.setLocationRelativeTo(frame);
            dProblem.setVisible(true);

            return null;
        }
    }

    /**
     * Open a certificate file.
     *
     * @param certificateFile The certificate file
     * @return The certificates found in the file or null if open failed
     */
    protected X509Certificate[] openCertificate(File certificateFile) {
        try {
            return openCertificate(Files.readAllBytes(certificateFile.toPath()), certificateFile.getName());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(frame, MessageFormat.format(
                                                  res.getString("KeyStoreExplorerAction.NoReadFile.message"),
                                                  certificateFile),
                                          res.getString("KeyStoreExplorerAction.OpenCertificate.Title"),
                                          JOptionPane.WARNING_MESSAGE);
            return new X509Certificate[0];
        }
    }

    /**
     * Open a certificate input stream.
     *
     * @param data Certificate data
     * @param name The name of the certificate (could be a file name for example)
     * @return The certificates found in the file or null if open failed
     */
    protected X509Certificate[] openCertificate(byte[] data, String name) {

        try {
            X509Certificate[] certs = X509CertUtil.loadCertificates(data);

            if (certs.length == 0) {
                JOptionPane.showMessageDialog(frame, MessageFormat.format(
                                                      res.getString("KeyStoreExplorerAction.NoCertsFound.message"),
                                                      name),
                                              res.getString("KeyStoreExplorerAction.OpenCertificate.Title"),
                                              JOptionPane.WARNING_MESSAGE);
            }

            return certs;
        } catch (Exception ex) {
            String problemStr = MessageFormat.format(res.getString("KeyStoreExplorerAction.NoOpenCert.Problem"), name);

            String[] causes = new String[] { res.getString("KeyStoreExplorerAction.NotCert.Cause"),
                                             res.getString("KeyStoreExplorerAction.CorruptedCert.Cause") };

            Problem problem = new Problem(problemStr, causes, ex);

            DProblem dProblem =
                    new DProblem(frame, res.getString("KeyStoreExplorerAction.ProblemOpeningCert.Title"), problem);
            dProblem.setLocationRelativeTo(frame);
            dProblem.setVisible(true);

            return null;
        }
    }

    /**
     * Gets a key store entry password.
     *
     * For PKCS #12 key stores, the entry password is always going to be the same as the key store
     * password. If a key store password is not set, this method will prompt for the key store
     * password and set it.
     *
     * For other key stores that has entry passwords, the user is always prompted to supply an entry
     * password.
     *
     * @param keyStoreType The key store type.
     * @param title        The new entry password dialog title.
     * @param currentState The current key store state.
     * @param newState     The new key store state.
     * @return
     */
    protected Password getNewEntryPassword(KeyStoreType keyStoreType, String title, KeyStoreState currentState,
            KeyStoreState newState) {
        Password password = new Password((char[]) null);

        if (keyStoreType.hasEntryPasswords()
                && (keyStoreType != KeyStoreType.PKCS12 && keyStoreType != KeyStoreType.KEYCHAIN)) {
            DGetNewPassword dGetNewPassword = new DGetNewPassword(frame, title, preferences);
            dGetNewPassword.setLocationRelativeTo(frame);
            dGetNewPassword.setVisible(true);
            password = dGetNewPassword.getPassword();

            if (password == null) {
                return null;
            }
        }
        if (keyStoreType == KeyStoreType.PKCS12 || keyStoreType == KeyStoreType.KEYCHAIN) {
            if (currentState.getPassword() == null) {
                var passwordAndDecision = getNewKeyStorePassword(true, newState.isStoredInPasswordManager());
                password = passwordAndDecision.getPassword();
                if (password == null) {
                    return null;
                }
                newState.setPassword(password);
                newState.setStoredInPasswordManager(passwordAndDecision.isSavePassword());
            } else {
                password = new Password(currentState.getPassword());
            }
        }

        return password;
    }

    /**
     * Get a new KeyStore password.
     *
     * @param askUserForPasswordManager True if user should be asked if they want to store the KeyStore password in the
     *                                  password manager
     * @param isPasswordManagerWanted Current decision of user to store KeyStore password in the pwd mgr
     * @return The new KeyStore password, or null if none entered by the user
     */
    protected PasswordAndDecision getNewKeyStorePassword(boolean askUserForPasswordManager,
                                                         boolean isPasswordManagerWanted) {
        DGetNewPassword dGetNewPassword =
                new DGetNewPassword(frame, res.getString("KeyStoreExplorerAction.SetKeyStorePassword.Title"),
                                    preferences, askUserForPasswordManager, isPasswordManagerWanted);
        dGetNewPassword.setLocationRelativeTo(frame);
        dGetNewPassword.setVisible(true);

        if (dGetNewPassword.isPasswordManagerWanted()) {
            unlockPasswordManager();
        }

        return new PasswordAndDecision(dGetNewPassword.getPassword(), dGetNewPassword.isPasswordManagerWanted());
    }

    protected void unlockPasswordManager() {
        try {
            if (!PasswordManager.getInstance().isInitialized()) {
                var dInitPasswordManager = new DInitPasswordManager(frame, preferences.getPasswordQualityConfig());
                dInitPasswordManager.setLocationRelativeTo(frame);
                dInitPasswordManager.setVisible(true);
                if (dInitPasswordManager.getPassword() != null) {
                    PasswordManager.getInstance().initialize(dInitPasswordManager.getPassword().toCharArray());
                }
            }
            if (!PasswordManager.getInstance().isUnlocked()) {
                var dUnlockPasswordManager = new DUnlockPasswordManager(frame);
                dUnlockPasswordManager.setLocationRelativeTo(frame);
                dUnlockPasswordManager.setVisible(true);
                if (!dUnlockPasswordManager.isCancelled()) {
                    unlockPasswordManagerWithProgress(dUnlockPasswordManager.getPassword().toCharArray());
                }
            }
        } catch (EncryptionException e) {
            JOptionPane.showMessageDialog(frame,
                                          res.getString("KeyStoreExplorerAction.WrongPasswordManagerPassword.message"),
                                          res.getString("KeyStoreExplorerAction.UnlockPasswordManager.title"),
                                          JOptionPane.WARNING_MESSAGE);
        } catch (Exception e) {
            DError.displayError(frame, e);
        }
    }

    private void unlockPasswordManagerWithProgress(char[] password) throws Exception {
        DUnlockingPasswords dUnlockingPasswords = new DUnlockingPasswords(frame);
        dUnlockingPasswords.setLocationRelativeTo(frame);
        dUnlockingPasswords.startPasswordUnlocking(() -> PasswordManager.getInstance().unlock(password));
        dUnlockingPasswords.setVisible(true);

        if (!dUnlockingPasswords.isUnlockCompleted()) {
            Exception unlockException = dUnlockingPasswords.getUnlockException();
            if (unlockException != null) {
                throw unlockException;
            }
        }
    }

    protected static void saveInPasswordManager(KeyStoreState currentState, File saveFile, Password password,
                                                JFrame parent) throws KeyStoreException {
        if (PasswordManager.getInstance().isUnlocked() && currentState.isStoredInPasswordManager()) {
            var entryPasswords = new HashMap<String, char[]>();
            for (String alias : Collections.list(currentState.getKeyStore().aliases())) {
                if (currentState.getEntryPassword(alias) != null) {
                    char[] entryPassword = currentState.getEntryPassword(alias).toCharArray();
                    if (entryPassword != null) {
                        entryPasswords.put(alias, entryPassword);
                    }
                }
            }
            PasswordManager.getInstance().update(saveFile, password.toCharArray(), entryPasswords);
            savePasswordManagerWithProgress(parent);
        }
    }

    /**
     * Save the Password Manager with a progress dialog to prevent UI blocking.
     *
     * @param parent The parent frame for the dialog
     */
    protected static void savePasswordManagerWithProgress(JFrame parent) {
        DSavingPasswords dSavingPasswords = new DSavingPasswords(parent);
        dSavingPasswords.setLocationRelativeTo(parent);
        dSavingPasswords.startPasswordSaving(() -> PasswordManager.getInstance().save());
        dSavingPasswords.setVisible(true);

        if (!dSavingPasswords.isSaveCompleted()) {
            Exception saveException = dSavingPasswords.getSaveException();
            if (saveException != null) {
                DError.displayError(parent, saveException);
            }
        }
    }

    /**
     * Is the supplied KeyStore file open?
     *
     * @param keyStoreFile KeyStore file
     * @return True if it is
     */
    protected boolean isKeyStoreFileOpen(File keyStoreFile) {
        KeyStoreHistory[] histories = kseFrame.getKeyStoreHistories();

        for (KeyStoreHistory history : histories) {
            File f = history.getFile();

            if (f != null && f.equals(keyStoreFile)) {
                return true;
            }
        }

        return false;
    }
}
