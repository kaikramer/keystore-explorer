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
import java.awt.event.InputEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.crypto.keystore.KeyStoreType;
import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.keystore.kdb.stash.StashFile;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

/**
 * Action to save KeyStore as.
 */
public class SaveAsAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public SaveAsAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('S',
                                                         Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() +
                                                         InputEvent.ALT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("SaveAsAction.statusbar"));
        putValue(NAME, res.getString("SaveAsAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SaveAsAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/saveas.png"))));
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {
        saveKeyStoreAs(kseFrame.getActiveKeyStoreHistory());
    }

    /**
     * Save the supplied opened KeyStore to disk to what may be a different file
     * from the one it was opened from (if any).
     *
     * @param history KeyStore history
     * @return True if the KeyStore is saved to disk, false otherwise
     */
    protected boolean saveKeyStoreAs(KeyStoreHistory history) {
        File saveFile = null;

        try {
            KeyStoreState currentState = history.getCurrentState();

            Password password = currentState.getPassword();

            if (password == null || password.isNulled()) {
                SetPasswordAction setPasswordAction = new SetPasswordAction(kseFrame);

                if (setPasswordAction.setKeyStorePassword()) {
                    currentState = history.getCurrentState();
                    password = currentState.getPassword();
                } else {
                    return false;
                }
            }

            JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
            chooser.setCurrentDirectory(CurrentDirectory.get());
            chooser.setDialogTitle(res.getString("SaveAsAction.SaveKeyStoreAs.Title"));
            chooser.setMultiSelectionEnabled(false);

            int rtnValue = chooser.showSaveDialog(frame);
            if (rtnValue != JFileChooser.APPROVE_OPTION) {
                return false;
            }
            saveFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(saveFile);

            // TODO check for response if JavaFX file dialog (because overwrite dialog is shown 2x)
            if (saveFile.isFile()) {
                String message = MessageFormat.format(res.getString("SaveAsAction.OverWriteFile.message"), saveFile);

                int selected = JOptionPane.showConfirmDialog(frame, message,
                                                             res.getString("SaveAsAction.SaveKeyStoreAs.Title"),
                                                             JOptionPane.YES_NO_OPTION);
                if (selected != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            if (isKeyStoreFileOpen(saveFile)) {
                JOptionPane.showMessageDialog(frame, res.getString("SaveAsAction.NoSaveKeyStoreAlreadyOpen.message"),
                                              res.getString("SaveAsAction.SaveKeyStoreAs.Title"),
                                              JOptionPane.WARNING_MESSAGE);
                return false;
            }

            saveInPasswordManager(currentState, saveFile, password, frame);

            history.setSuppressWatcherEvents(true);
            KeyStoreUtil.save(currentState.getKeyStore(), saveFile, password);

            updateStashFile(currentState.getKeyStore(), saveFile, password, true);

            currentState.setPassword(password);
            history.setFile(saveFile);
            currentState.setAsSavedState();

            kseFrame.updateControls(false);

            kseFrame.addRecentFile(saveFile);

            return true;
        } catch (FileNotFoundException | NoSuchFileException ex) {
            JOptionPane.showMessageDialog(frame, MessageFormat.format(res.getString("SaveAsAction.NoWriteFile.message"),
                                                                      saveFile),
                                          res.getString("SaveAsAction.SaveKeyStoreAs.Title"),
                                          JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (Exception ex) {
            DError.displayError(frame, ex);
            return false;
        } finally {
            history.setSuppressWatcherEvents(false);
        }
    }

    /**
     * If a CMS key database (KDB) has a sidecar stash file (.sth) that no longer matches the password
     * the KeyStore was just saved with, offer to update the stash file. If no stash file exists
     * yet and {@code offerCreate} is set (i.e. the KeyStore was saved to a new file), offer to
     * create one.
     *
     * @param keyStore    The saved KeyStore
     * @param saveFile    The file the KeyStore was saved to
     * @param password    The password the KeyStore was saved with
     * @param offerCreate Whether to offer creating a stash file if none exists
     */
    protected void updateStashFile(KseKeyStore keyStore, File saveFile, Password password, boolean offerCreate) {
        if (!KeyStoreType.KDB.jce().equals(keyStore.getType())) {
            return;
        }

        String name = saveFile.getName();
        int extension = name.lastIndexOf('.');
        File sthFile = new File(saveFile.getParentFile(),
                                (extension > 0 ? name.substring(0, extension) : name) + ".sth");

        try {
            String newPassword = new String(password.toCharArray());

            if (sthFile.isFile()) {
                byte[] stashBytes = Files.readAllBytes(sthFile.toPath());

                if (newPassword.equals(StashFile.decode(stashBytes))) {
                    // stash file already matches the keystore password
                    return;
                }

                int selected = JOptionPane.showConfirmDialog(frame, MessageFormat.format(
                                                                     res.getString(
                                                                             "SaveAsAction.UpdateStashFile.message"),
                                                                     sthFile.getName()),
                                                             res.getString("SaveAsAction.UpdateStashFile.Title"),
                                                             JOptionPane.YES_NO_OPTION);
                if (selected == JOptionPane.YES_OPTION) {
                    Files.write(sthFile.toPath(), StashFile.encode(newPassword, StashFile.versionOf(stashBytes)));
                }
            } else if (offerCreate) {
                int selected = JOptionPane.showConfirmDialog(frame, MessageFormat.format(
                                                                     res.getString(
                                                                             "SaveAsAction.CreateStashFile.message"),
                                                                     sthFile.getName()),
                                                             res.getString("SaveAsAction.CreateStashFile.Title"),
                                                             JOptionPane.YES_NO_OPTION);
                if (selected == JOptionPane.YES_OPTION) {
                    Files.write(sthFile.toPath(), StashFile.encode(newPassword));
                }
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }
}
