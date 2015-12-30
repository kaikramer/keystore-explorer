package net.sf.keystore_explorer.gui.dnd;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.SwingUtilities;

import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.actions.ExamineFileAction;
import net.sf.keystore_explorer.gui.error.DError;

public class DroppedFileHandler {

    public static void drop(DropTargetDropEvent evt, final KseFrame kseFrame) {
        evt.acceptDrop(DnDConstants.ACTION_MOVE);
        Transferable trans = evt.getTransferable();

        if (trans.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
            try {

                @SuppressWarnings("unchecked")
                final List<File> droppedFiles = (List<File>) trans.getTransferData(DataFlavor.javaFileListFlavor);

                // open files in new thread, so we can return quickly
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        openFiles(kseFrame, droppedFiles);
                    }
                });

            } catch (IOException e) {
                DError.displayError(kseFrame.getUnderlyingFrame(), e);
            } catch (UnsupportedFlavorException e) {
                DError.displayError(kseFrame.getUnderlyingFrame(), e);
            }
        }
    }

    public static void openFiles(KseFrame kseFrame, List<File> droppedFiles) {

        ExamineFileAction examineFileAction = new ExamineFileAction(kseFrame);

        for (File droppedFile : droppedFiles) {

            try {

                examineFileAction.openFile(droppedFile);

            } catch (Exception e) {
                DError.displayError(kseFrame.getUnderlyingFrame(), e);
            }
        }
    }
}
