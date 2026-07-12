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
package org.kse.gui.error;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Enumeration;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.kse.gui.CursorUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.components.JEscDialog;

import net.miginfocom.swing.MigLayout;

/**
 * Displays an error's stack trace. Cause error's stack trace will be show
 * recursively also.
 */
public class DErrorDetail extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/error/resources");

    private JButton jbCopy;
    private JButton jbOK;
    private JTree jtrError;
    private JScrollPane jspError;

    private Throwable error;

    /**
     * Creates new DErrorDetail dialog where the parent is a window.
     *
     * @param parent   Parent window
     * @param modality Dialog modality
     * @param error    Error to display
     */
    public DErrorDetail(Window parent, Dialog.ModalityType modality, Throwable error) {
        super(parent, modality);
        this.error = error;
        initComponents();
    }

    /**
     * Creates new DErrorDetail dialog where the parent is a window.
     *
     * @param parent Parent window
     * @param error  Error to display
     */
    public DErrorDetail(Window parent, Throwable error) {
        this(parent, ModalityType.DOCUMENT_MODAL, error);
    }

    private void initComponents() {
        jbCopy = new JButton(res.getString("DErrorDetail.jbCopy.text"));
        PlatformUtil.setMnemonic(jbCopy, res.getString("DErrorDetail.jbCopy.mnemonic").charAt(0));
        jbCopy.setToolTipText(res.getString("DErrorDetail.jbCopy.tooltip"));
        jbCopy.addActionListener(evt -> {
            try {
                CursorUtil.setCursorBusy(DErrorDetail.this);
                copyPressed();
            } finally {
                CursorUtil.setCursorFree(DErrorDetail.this);
            }
        });

        jbOK = new JButton(res.getString("DErrorDetail.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jtrError = new JTree(createErrorNodes());
        jtrError.setRowHeight(Math.max(18, jtrError.getRowHeight()));
        jtrError.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        ToolTipManager.sharedInstance().registerComponent(jtrError);
        jtrError.setCellRenderer(new ErrorTreeCellRend());

        TreeNode topNode = (TreeNode) jtrError.getModel().getRoot();
        expandTree(jtrError, new TreePath(topNode));

        jspError = PlatformUtil.createScrollPane(jtrError, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        jspError.setPreferredSize(new Dimension(500, 250));

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]", "[]"));
        pane.add(jspError, "wrap para");
        pane.add(jbCopy, "split 2");
        pane.add(jbOK, "tag ok");

        setTitle(res.getString("DErrorDetail.Title"));
        setResizable(true);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();

        SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }

    private DefaultMutableTreeNode createErrorNodes() {
        DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(res.getString("DErrorDetail.RootNode.text"));

        Throwable createError = error;

        while (createError != null) {
            DefaultMutableTreeNode errorNode = new DefaultMutableTreeNode(createError);
            topNode.add(errorNode);

            for (StackTraceElement stackTrace : createError.getStackTrace()) {
                errorNode.add(new DefaultMutableTreeNode(stackTrace));
            }

            createError = createError.getCause();
        }

        return topNode;
    }

    private void expandTree(JTree tree, TreePath parent) {
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() >= 0) {
            for (Enumeration<?> children = node.children(); children.hasMoreElements();) {
                TreeNode subNode = (TreeNode) children.nextElement();
                TreePath path = parent.pathByAddingChild(subNode);
                expandTree(tree, path);
            }
        }

        tree.expandPath(parent);
    }

    private void copyPressed() {
        StringBuilder strBuff = new StringBuilder();
        TreePath root =  jtrError.getPathForRow(0);
        TreePath treePath = jtrError.getSelectionPath();
        if (treePath == null || root.equals(treePath)) {
            Throwable copyError = error;
            while (copyError != null) {
                strBuff.append(copyError);
                strBuff.append('\n');

                for (StackTraceElement stackTrace : copyError.getStackTrace()) {
                    strBuff.append("\tat ");
                    strBuff.append(stackTrace);
                    strBuff.append('\n');
                }

                copyError = copyError.getCause();

                if (copyError != null) {
                    strBuff.append('\n');
                }
            }
        } else {
            strBuff.append(treePath.toString());
        }

        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection copy = new StringSelection(strBuff.toString());
        clipboard.setContents(copy, copy);
    }

    private void okPressed() {
        closeDialog();
    }

    private void closeDialog() {
        setVisible(false);
        dispose();
    }
}
