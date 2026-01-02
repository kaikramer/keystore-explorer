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
 * Saves passwords in a file with a progress dialog to prevent UI blocking.
 */
public class DSavingPasswords extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private boolean saveCompleted = false;
    private Exception saveException = null;

    /**
     * Creates a new DSavingPasswords dialog.
     *
     * @param parent The parent frame
     */
    public DSavingPasswords(JFrame parent) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents();
    }

    private void initComponents() {
        ImageIcon icon = new ImageIcon(getClass().getResource("images/save.png"));

        JLabel jlSavingPasswords = new JLabel(res.getString("DSavingPasswords.jlSavingPasswords.text"));
        jlSavingPasswords.setIcon(icon);
        jlSavingPasswords.setHorizontalTextPosition(SwingConstants.TRAILING);
        jlSavingPasswords.setIconTextGap(10);

        JProgressBar jpbSavingPasswords = new JProgressBar();
        jpbSavingPasswords.setIndeterminate(true);

        getContentPane().setLayout(new MigLayout("insets dialog", "", ""));
        getContentPane().add(jlSavingPasswords, "growx, wrap unrel");
        getContentPane().add(jpbSavingPasswords, "growx, wrap rel");

        setTitle(res.getString("DSavingPasswords.Title"));
        setResizable(false);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        pack();
    }

    /**
     * Start password saving in a separate thread.
     *
     * @param operation The operation to execute (e.g., password saving)
     */
    public void startPasswordSaving(Runnable operation) {
        Thread saveThread = new Thread(new SavePasswords(operation));
        saveThread.setPriority(Thread.MIN_PRIORITY);
        saveThread.start();
    }

    /**
     * Check if the save operation completed successfully.
     *
     * @return true if completed successfully, false if there was an error
     */
    public boolean isSaveCompleted() {
        return saveCompleted && saveException == null;
    }

    /**
     * Get the exception that occurred during saving, if any.
     *
     * @return The exception or null if no error occurred
     */
    public Exception getSaveException() {
        return saveException;
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    // little helper class to run the save operation in a separate thread
    private class SavePasswords implements Runnable {
        private final Runnable operation;

        public SavePasswords(Runnable operation) {
            this.operation = operation;
        }

        @Override
        public void run() {
            try {
                operation.run();

                saveCompleted = true;
                invokeCloseDialog();
            } catch (final Exception ex) {
                saveException = ex;
                invokeCloseDialog();
            }
        }

        private void invokeCloseDialog() {
            SwingUtilities.invokeLater(() -> {
                if (DSavingPasswords.this.isShowing()) {
                    closeDialog();
                }
            });
        }
    }

    // for quick UI tests
    public static void main(String[] args) throws UnsupportedLookAndFeelException {
        int duration = 5000;

        DialogViewer.prepare();

        DSavingPasswords dialog = new DSavingPasswords(new JFrame());
        dialog.startPasswordSaving(() -> {
            try {
                Thread.sleep(duration);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });

        DialogViewer.run(dialog);
    }
}
