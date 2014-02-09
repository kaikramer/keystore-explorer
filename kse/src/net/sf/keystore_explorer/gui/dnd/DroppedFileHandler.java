package net.sf.keystore_explorer.gui.dnd;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import net.sf.keystore_explorer.crypto.filetype.CryptoFileType;
import net.sf.keystore_explorer.crypto.filetype.CryptoFileUtil;
import net.sf.keystore_explorer.gui.KseFrame;
import net.sf.keystore_explorer.gui.actions.ExamineCertificateAction;
import net.sf.keystore_explorer.gui.actions.ExamineCrlAction;
import net.sf.keystore_explorer.gui.actions.ExamineCsrAction;
import net.sf.keystore_explorer.gui.actions.OpenAction;
import net.sf.keystore_explorer.gui.error.DError;

public class DroppedFileHandler {

    public static void drop(DropTargetDropEvent evt, KseFrame kseFrame) {
        try {
            evt.acceptDrop(DnDConstants.ACTION_MOVE);

            Transferable trans = evt.getTransferable();

            if (trans.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                List<File> droppedFiles = (List<File>) trans.getTransferData(DataFlavor.javaFileListFlavor);

                OpenAction openAction = new OpenAction(kseFrame);
                ExamineCertificateAction examineCertificateAction = new ExamineCertificateAction(kseFrame);
                ExamineCrlAction examineCrlAction = new ExamineCrlAction(kseFrame);
                ExamineCsrAction examineCsrAction = new ExamineCsrAction(kseFrame);

                for (File droppedFile : droppedFiles) {

                    // detect file type and use the right action class for opening the file
                    CryptoFileType fileType = CryptoFileUtil.detectFileType(new FileInputStream(droppedFile));
                    switch (fileType) {
                    case JCEKS_KS:
                    case JKS_KS:
                    case PKCS12_KS:
                    case BKS_KS:
                    case UBER_KS:
                        openAction.openKeyStore(droppedFile);
                        break;
                    case CERT:
                        examineCertificateAction.openCert(droppedFile);
                        break;
                    case CRL:
                        examineCrlAction.openCrl(droppedFile);
                        break;
                    case PKCS10_CSR:
                    case SPKAC_CSR:
                        examineCsrAction.openCsr(droppedFile);
                        break;
                    default:
                        break;
                    }
                }
            }
        } catch (IOException e) {
            DError.displayError(kseFrame.getUnderlyingFrame(), e);
        } catch (UnsupportedFlavorException e) {
            DError.displayError(kseFrame.getUnderlyingFrame(), e);
        }
    }
}
