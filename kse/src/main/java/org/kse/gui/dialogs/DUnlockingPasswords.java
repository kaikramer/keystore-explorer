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
package org.kse.gui.dialogs;

import java.awt.Dialog;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UnsupportedLookAndFeelException;

import org.kse.gui.components.JEscDialog;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Unlocks passwords from a file with a progress dialog to prevent UI blocking.
 */
public class DUnlockingPasswords extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private boolean unlockCompleted = false;
    private Exception unlockException = null;

    /**
     * Creates a new DUnlockingPasswords dialog.
     *
     * @param parent The parent frame
     */
    public DUnlockingPasswords(JFrame parent) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    private void initComponents() {
        ImageIcon icon = new ImageIcon(getClass().getResource("images/open.png"));

        JLabel jlUnlockingPasswords = new JLabel(res.getString("DUnlockingPasswords.jlUnlockingPasswords.text"));
        jlUnlockingPasswords.setIcon(icon);
        jlUnlockingPasswords.setHorizontalTextPosition(SwingConstants.TRAILING);
        jlUnlockingPasswords.setIconTextGap(10);

        JProgressBar jpbUnlockingPasswords = new JProgressBar();
        jpbUnlockingPasswords.setIndeterminate(true);

        getContentPane().setLayout(new MigLayout("insets dialog", "", ""));
        getContentPane().add(jlUnlockingPasswords, "growx, wrap unrel");
        getContentPane().add(jpbUnlockingPasswords, "growx, wrap rel");

        setTitle(res.getString("DUnlockingPasswords.Title"));
        setResizable(false);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        pack();
    }

    /**
     * Start password unlocking in a separate thread.
     *
     * @param operation The operation to execute (e.g., password unlocking)
     */
    public void startPasswordUnlocking(Runnable operation) {
        Thread unlockThread = new Thread(new UnlockPasswords(operation));
        unlockThread.setPriority(Thread.MIN_PRIORITY);
        unlockThread.start();
    }

    /**
     * Check if the unlock operation completed successfully.
     *
     * @return true if completed successfully, false if there was an error
     */
    public boolean isUnlockCompleted() {
        return unlockCompleted && unlockException == null;
    }

    /**
     * Get the exception that occurred during unlocking, if any.
     *
     * @return The exception or null if no error occurred
     */
    public Exception getUnlockException() {
        return unlockException;
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // little helper class to run the unlock operation in a separate thread
    private class UnlockPasswords implements Runnable {
        private final Runnable operation;

        public UnlockPasswords(Runnable operation) {
            this.operation = operation;
        }

        @Override
        public void run() {
            try {
                operation.run();
                unlockCompleted = true;
                invokeCloseDialog();
            } catch (final Exception ex) {
                unlockException = ex;
                invokeCloseDialog();
            }
        }

        private void invokeCloseDialog() {
            SwingUtilities.invokeLater(() -> {
                if (DUnlockingPasswords.this.isShowing()) {
                    closeDialog();
                }
            });
        }
    }

    // for quick UI tests
    public static void main(String[] args) throws UnsupportedLookAndFeelException {
        int duration = 5000;

        DialogViewer.prepare();

        DUnlockingPasswords dialog = new DUnlockingPasswords(new JFrame());
        dialog.startPasswordUnlocking(() -> {
            try {
                Thread.sleep(duration);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });

        DialogViewer.run(dialog);
    }
}
