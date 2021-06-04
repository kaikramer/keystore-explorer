package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.kse.ApplicationSettings;
import org.kse.crypto.CryptoException;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.JavaFXFileChooser;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

import net.miginfocom.swing.MigLayout;

public class DViewDHParameters extends JEscDialog {
	

	/**
	 * 
	 */
	private static final long serialVersionUID = -1711814777923997727L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");
	
	private JTextArea jtAreaPem;
	private JButton jbExport;
	private JButton jbOK;
	private JButton jbCopy;
	private static int keySize;
	private byte [] dhParameters;
	private static final String FILE_SUFFIX = ".pem";
	private static final String EB = "DH PARAMETERS"; //Encapsulation Boundary
	
	
	public DViewDHParameters (JFrame parent, String title, byte[] dhParams)
		throws CryptoException {

		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.dhParameters = dhParams;
		initComponents(dhParameters);
	}
	
	private void initComponents(byte[] dhParams) throws CryptoException {
		//TODO Generate DH Parameters icon
	    PemInfo pemInfo = new PemInfo(EB, null, dhParams);
		jtAreaPem = new JTextArea(PemUtil.encode(pemInfo));
		jtAreaPem.setToolTipText(res.getString("DViewDHParameters.jtAreaPem.tooltip"));
		jtAreaPem.setEditable(false);
		jtAreaPem.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		// keep uneditable color same as editable
		jtAreaPem.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);	

		jbExport = new JButton(res.getString("DViewDHParameters.jbExport.export.text"));
		jbExport.setToolTipText(res.getString("DViewDHParameters.jbExport.export.tooltip"));
		PlatformUtil.setMnemonic(jbExport, res.getString("DViewDHParameters.jbExport.mnemonic").charAt(0));
		
		jbCopy = new JButton(res.getString("DViewDHParameters.jbCopy.text"));
		jbCopy.setToolTipText(res.getString("DViewDHParameters.jbCopy.tooltip"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DViewDHParameters.jbCopy.mnemonic").charAt(0));

		jbOK = new JButton(res.getString("DViewDHParameters.jbOK.text"));
		
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets 10"));
		pane.add(jtAreaPem, "span");
		pane.add(jbCopy);
		pane.add(jbExport);
		pane.add(jbOK);
	
		jbOK.addActionListener(evt -> okPressed());

		jbExport.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DViewDHParameters.this);
				exportPressed();
			} finally {
				CursorUtil.setCursorFree(DViewDHParameters.this);
			}
		});
		
		jbCopy.addActionListener(evt -> {
			try {
				CursorUtil.setCursorBusy(DViewDHParameters.this);
				copyPressed();
			} finally {
				CursorUtil.setCursorFree(DViewDHParameters.this);
			}
		});
		
		setResizable(false);

		getRootPane().setDefaultButton(jbCopy);

		pack();

		SwingUtilities.invokeLater(() -> jbOK.requestFocus());
    }
	
   private void writeDHParams(String filePath, byte[] DEREncodedDHParams) {
        PemWriter pemWrt;

        try {
            pemWrt = new PemWriter(new FileWriter(filePath));
            pemWrt.writeObject(new PemObject(EB, DEREncodedDHParams));
            pemWrt.flush();
            pemWrt.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
   
	private void okPressed() {
		ApplicationSettings.getInstance();
		closeDialog();
	}
	
	private void closeDialog() {
		setVisible(false);
		dispose();
	}
	
	private void exportPressed() {
		File chosenFile = null;

		String title = res.getString("DViewDHParameters.ExportPem.Title");

		JFileChooser chooser = new JFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(title);
		chooser.setMultiSelectionEnabled(false);
		chooser.setFileFilter(new FileNameExtensionFilter("pem file", "pem"));

		int rtnValue = JavaFXFileChooser.isFxAvailable() ? chooser.showSaveDialog(this)
				: chooser.showDialog(this, res.getString("DViewDHParameters.ChooseExportFile.button"));

		if (rtnValue != JFileChooser.APPROVE_OPTION) {
			return;
		}

		chosenFile = chooser.getSelectedFile();
		CurrentDirectory.updateForFile(chosenFile);

		if (chosenFile.isFile()) {
			String message = MessageFormat.format(res.getString("DViewDHParameters.OverWriteFile.message"), chosenFile);

			int selected = JOptionPane.showConfirmDialog(this, message, title, JOptionPane.YES_NO_OPTION);
			if (selected != JOptionPane.YES_OPTION) {
				return;
			}
		}
		
		if(!chosenFile.getAbsolutePath().toString() .endsWith(FILE_SUFFIX)) {
			writeDHParams(chosenFile.getAbsolutePath().toString() + FILE_SUFFIX, dhParameters);
		}
		else {
			writeDHParams(chosenFile.getAbsolutePath().toString(), dhParameters);
		}
		
		JOptionPane.showMessageDialog(this, res.getString("DViewDHParameters.ExportPemSuccessful.message"),
				title, JOptionPane.INFORMATION_MESSAGE);		
	}
   
	private void copyPressed() {
		String policy = jtAreaPem.getText();

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(policy);
		clipboard.setContents(copy, copy);
	}
	
	//Quick UI test
	public static void main(String[] args) throws Exception, IOException, GeneralSecurityException {
		DialogViewer.prepare();
		keySize = 512;
		
		DGeneratingDHParameters testDH = new DGeneratingDHParameters(new javax.swing.JFrame(), keySize);
		testDH.startDHParametersGeneration();
		testDH.setVisible(true);
		
		DViewDHParameters dialog = new DViewDHParameters(new javax.swing.JFrame(), "Title", testDH.getDHParameters());
		DialogViewer.run(dialog);		
	}
	
}

