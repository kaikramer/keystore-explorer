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

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;

import org.kse.gui.components.JEscDialog;

import net.miginfocom.swing.MigLayout;

/**
 * A dialog class to use for operations that display a progress bar.
 */
public class JWaitDialog extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlMessage;
    private JProgressBar jpbProgress;
    private JButton jbCancel;

    private String title;
    private String message;
    private String icon;
    private String cancel;
    private Thread thread;

    private boolean successStatus = true;

    protected JWaitDialog(JFrame parent, String title, String message, String icon,
            String cancel) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.title = title;
        this.message = message;
        this.icon = icon;
        this.cancel = cancel;
        initComponents();
    }

    private void initComponents() {
        jlMessage = new JLabel(message);
        if (icon != null) {
            jlMessage.setIcon(new ImageIcon(getClass().getResource(icon)));
            jlMessage.setHorizontalTextPosition(SwingConstants.LEADING);
            jlMessage.setIconTextGap(15);
        }

        jpbProgress = new JProgressBar();
        jpbProgress.setIndeterminate(true);

        jbCancel = new JButton(cancel);
        jbCancel.addActionListener(evt -> cancelPressed());
        // Need to use WHEN_FOCUSED since the cancel button will always have focus.
        jbCancel.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]", "[]"));
        pane.add(jlMessage, "wrap para");
        pane.add(jpbProgress, "growx, wrap para");
        pane.add(jbCancel, "tag cancel");

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                cancelPressed();
            }
        });

        setTitle(title);
        setResizable(false);

        pack();
    }

    protected void initProgressBar(int min, int max) {
        jpbProgress.setMinimum(min);
        jpbProgress.setMaximum(max);
        jpbProgress.setIndeterminate(false);
    }

    protected void updateProgress(int value) {
        jpbProgress.setValue(value);
    }

    protected void startTask(Runnable task) {
        thread = new Thread(task);
        thread.setPriority(Thread.MIN_PRIORITY);
        thread.setDaemon(true);
        thread.start();
    }

    protected void cancelPressed() {
        if ((thread != null) && (thread.isAlive())) {
            thread.interrupt();
        }
        successStatus = false;
        closeDialog();
    }

    /**
     * Returns the current success status
     *
     * @return successStatus The success status boolean
     */
    public boolean isSuccessful() {
        return successStatus;
    }

    /**
     * Closes the dialog.
     */
    public void closeDialog() {
        setVisible(false);
        dispose();
    }

}
