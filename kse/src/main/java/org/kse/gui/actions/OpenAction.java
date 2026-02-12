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

import java.awt.Toolkit;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.NoSuchFileException;
import java.text.MessageFormat;
import java.util.HashMap;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreLoadException;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetPassword;
import org.kse.gui.passwordmanager.Password;
import org.kse.gui.passwordmanager.PasswordManager;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to open a KeyStore.
 */
public class OpenAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    private boolean newKeyStoreWasAdded = false;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public OpenAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('O',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        putValue(LONG_DESCRIPTION, res.getString("OpenAction.statusbar"));
        putValue(NAME, res.getString("OpenAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("OpenAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/open.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("OpenAction.OpenKeyStore.Title"));
        chooser.setMultiSelectionEnabled(false);

        int rtnValue = chooser.showOpenDialog(frame);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File openFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(openFile);

            openKeyStore(openFile);
        }
    }

    /**
     * Open the supplied KeyStore file from disk.
     *
     * @param keyStoreFile The KeyStore file
     */
    public void openKeyStore(File keyStoreFile) {
        openKeyStore(keyStoreFile, null);
    }

    /**
     * Open the supplied KeyStore file from disk.
     *
     * @param keyStoreFile The KeyStore file
     * @param defaultPassword An optional password to use by default for the first try.
     */
    public void openKeyStore(File keyStoreFile, String defaultPassword) {
        try {
            if (!keyStoreFile.isFile()) {
                JOptionPane.showMessageDialog(frame, MessageFormat.format(res.getString("OpenAction.NotFile.message"),
                                                                          keyStoreFile),
                                              res.getString("OpenAction.OpenKeyStore.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (isKeyStoreFileOpen(keyStoreFile)) {
                JOptionPane.showMessageDialog(frame, MessageFormat.format(
                                                      res.getString("OpenAction.NoOpenKeyStoreAlreadyOpen.message"),
                                                      keyStoreFile),
                                              res.getString("OpenAction.OpenKeyStore.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }

            Password password;
            PasswordManager passwordManager = PasswordManager.getInstance();
            if (passwordManager.isKeyStorePasswordKnown(keyStoreFile)) {
                unlockPasswordManager();
                password = passwordManager.getKeyStorePassword(keyStoreFile).map(Password::new).orElse(null);
            } else {
                // use (optional) default password for first try
                password = (defaultPassword != null) ? new Password(defaultPassword.toCharArray()) : null;
            }

            KseKeyStore openedKeyStore;
            boolean firstTry = true;
            while (true) {
                boolean passwordManagerWanted = false;

                // user might have cancelled password manager dialog, then no decision from user is required here
                boolean askForPasswordManager = !passwordManager.isKeyStorePasswordKnown(keyStoreFile);

                // show password dialog if no default password was passed or if last try to unlock ks has failed
                if (password == null) {
                    DGetPassword dGetPassword = new DGetPassword(frame, MessageFormat.format(
                            res.getString("OpenAction.UnlockKeyStore.Title"), keyStoreFile.getName()),
                            askForPasswordManager);
                    dGetPassword.setLocationRelativeTo(frame);
                    dGetPassword.setVisible(true);

                    password = dGetPassword.getPassword();
                    passwordManagerWanted = dGetPassword.isPasswordManagerWanted();
                }

                // user did not enter password -> abort
                if (password == null) {
                    return;
                }

                // try to load keystore
                try {
                    openedKeyStore = KeyStoreUtil.load(keyStoreFile, password);

                    // store password in password manager
                    if (passwordManagerWanted) {
                        unlockPasswordManager();
                        passwordManager.update(keyStoreFile, password.toCharArray(), new HashMap<>());
                    }

                    break;
                } catch (KeyStoreLoadException klex) {

                    // show error message only after first try with default password or if no default password set
                    if (defaultPassword == null || !firstTry) {

                        int tryAgainChoice = showErrorMessage(keyStoreFile, klex);
                        if (tryAgainChoice == JOptionPane.NO_OPTION) {
                            return;
                        }
                    }
                }

                // failure, reset password
                password.nullPassword();
                password = null;
                firstTry = false;
            }

            if (openedKeyStore == null) {
                JOptionPane.showMessageDialog(frame, MessageFormat.format(
                                                      res.getString("OpenAction.FileNotRecognisedType.message"),
                                                      keyStoreFile.getName()),
                                              res.getString("OpenAction.OpenKeyStore.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return;
            }

            KeyStoreHistory history = new KeyStoreHistory(openedKeyStore, keyStoreFile, password);

            history.getCurrentState().setStoredInPasswordManager(passwordManager.isKeyStorePasswordKnown(keyStoreFile));

            kseFrame.addKeyStoreHistory(history);
            this.newKeyStoreWasAdded = true;
        } catch (FileNotFoundException | NoSuchFileException ex) {
            JOptionPane.showMessageDialog(frame, MessageFormat.format(res.getString("OpenAction.NoReadFile.message"),
                                                                      keyStoreFile),
                                          res.getString("OpenAction.OpenKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private int showErrorMessage(File keyStoreFile, KeyStoreLoadException klex) {
        String problemStr = MessageFormat.format(res.getString("OpenAction.NoOpenKeyStore.Problem"),
                                                 klex.getKeyStoreType().friendly(), keyStoreFile.getName());

        String[] causes = new String[] { res.getString("OpenAction.PasswordIncorrectKeyStore.Cause"),
                                         res.getString("OpenAction.CorruptedKeyStore.Cause") };

        Problem problem = new Problem(problemStr, causes, klex);

        DProblem dProblem = new DProblem(frame, res.getString("OpenAction.ProblemOpeningKeyStore.Title"), problem);
        dProblem.setLocationRelativeTo(frame);
        dProblem.setVisible(true);

        return JOptionPane.showConfirmDialog(frame, res.getString("OpenAction.TryAgain.message"),
                                             res.getString("OpenAction.TryAgain.Title"), JOptionPane.YES_NO_OPTION);
    }

    /**
     * @return True if a new key store was added by the open action.
     */
    public boolean hasNewKeyStoreBeenAdded() {
        return newKeyStoreWasAdded;
    }
}
