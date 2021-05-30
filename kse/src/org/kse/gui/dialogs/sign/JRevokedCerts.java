package org.kse.gui.dialogs.sign;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.kse.crypto.CryptoException;
import org.kse.crypto.filetype.CryptoFileType;
import org.kse.crypto.filetype.CryptoFileUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;

public class JRevokedCerts extends JPanel {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

	private JLabel jlRevokedCerts;
	private JScrollPane jspRevokedCertsTable;
	private JKseTable jtRevokedCerts;

	private JPanel jpRevokedButtons;
	private JButton jbRevCertFile;
	private JButton jbRevKeyStore;
	private JButton jbRevLoadCrl;

	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbRemove;

	private JFrame parent;

	private List<RevokedEntry> listRevokedEntry;
	private X509CRL crl;

	public JRevokedCerts(JFrame parent, X509CRL crl) {
		super();
		this.parent = parent;
		this.crl = crl;
		this.listRevokedEntry = new ArrayList<>();
		initComponents();
	}

	private void initComponents() {

		jbRevCertFile = new JButton(
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/revoked.png"))));
		jbRevCertFile.setMargin(new Insets(2, 2, 0, 0));
		jbRevCertFile.setToolTipText(res.getString("JRevokedCerts.jbRevCertFile.tooltip"));
		jbRevCertFile.setMnemonic(res.getString("JRevokedCerts.jbRevCertFile.mnemonic").charAt(0));

		jbRevKeyStore = new JButton(
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/revoked.png"))));
		jbRevKeyStore.setMargin(new Insets(2, 2, 0, 0));
		jbRevKeyStore.setToolTipText(res.getString("JRevokedCerts.jbRevKeyStore.tooltip"));
		jbRevKeyStore.setMnemonic(res.getString("JRevokedCerts.jbRevKeyStore.mnemonic").charAt(0));

		jbRevLoadCrl = new JButton(
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/revoked.png"))));
		jbRevLoadCrl.setMargin(new Insets(2, 2, 0, 0));
		jbRevLoadCrl.setToolTipText(res.getString("JRevokedCerts.jbRevLoadCrl.tooltip"));
		jbRevLoadCrl.setMnemonic(res.getString("JRevokedCerts.jbRevLoadCrl.mnemonic").charAt(0));

		jlRevokedCerts = new JLabel(res.getString("DSignCrl.jlRevokedCerts.text"));
		RevokedCertsTableModel rcModel = new RevokedCertsTableModel();

		jtRevokedCerts = new JKseTable(rcModel);
		RowSorter<RevokedCertsTableModel> sorter = new TableRowSorter<>(rcModel);
		jtRevokedCerts.setRowSorter(sorter);

		jtRevokedCerts.setShowGrid(false);
		jtRevokedCerts.setRowMargin(0);
		jtRevokedCerts.getColumnModel().setColumnMargin(0);
		jtRevokedCerts.getTableHeader().setReorderingAllowed(false);
		jtRevokedCerts.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);

		for (int i = 0; i < jtRevokedCerts.getColumnCount(); i++) {
			TableColumn column = jtRevokedCerts.getColumnModel().getColumn(i);

			if (i == 0) {
				column.setPreferredWidth(100);
			}

			column.setHeaderRenderer(
					new RevokedCertsTableHeadRend(jtRevokedCerts.getTableHeader().getDefaultRenderer()));
			column.setCellRenderer(new RevokedCertsTableCellRend());
		}

		jspRevokedCertsTable = PlatformUtil.createScrollPane(jtRevokedCerts,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspRevokedCertsTable.getViewport().setBackground(jtRevokedCerts.getBackground());

		jpRevokedButtons = new JPanel();
		jpRevokedButtons.setLayout(new BoxLayout(jpRevokedButtons, BoxLayout.Y_AXIS));
		jpRevokedButtons.add(Box.createVerticalGlue());
		jpRevokedButtons.add(jbRevCertFile);
		jpRevokedButtons.add(Box.createVerticalStrut(3));
		jpRevokedButtons.add(jbRevKeyStore);
		jpRevokedButtons.add(Box.createVerticalStrut(3));
		jpRevokedButtons.add(jbRevLoadCrl);
		jpRevokedButtons.add(Box.createVerticalGlue());

		jbRevCertFile.addActionListener(evt -> revCertFilePressed());
		jbRevLoadCrl.addActionListener(evt -> revLoadCrlPressed());
		
		populate();

		this.setLayout(new BorderLayout(5, 5));
		this.setPreferredSize(new Dimension(100, 200));
		this.add(jlRevokedCerts, BorderLayout.NORTH);
		this.add(jspRevokedCertsTable, BorderLayout.CENTER);
		this.add(jpRevokedButtons, BorderLayout.EAST);
		this.setBorder(new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5)));
	}

	private void populate()
	{
		if (crl != null) {
			Set<? extends X509CRLEntry> revokedCertsSet = crl.getRevokedCertificates();
			if (revokedCertsSet == null) {
				revokedCertsSet = new HashSet<>();
			}
			X509CRLEntry[] revokedCerts = revokedCertsSet.toArray(new X509CRLEntry[revokedCertsSet.size()]);
			for (X509CRLEntry entry : revokedCerts)
			{
				if (entry.getRevocationReason() == null) {
					listRevokedEntry.add(new RevokedEntry(entry.getSerialNumber(), entry.getRevocationDate(),0));
				}
				else {
					listRevokedEntry.add(new RevokedEntry(entry.getSerialNumber(), entry.getRevocationDate(),entry.getRevocationReason().ordinal()));	
				}
			}
			RevokedCertsTableModel revokedCertsTableModel = (RevokedCertsTableModel) jtRevokedCerts.getModel();
			
			revokedCertsTableModel.load(listRevokedEntry);

			if (revokedCertsTableModel.getRowCount() > 0) {
				jtRevokedCerts.changeSelection(0, 0, false, false);
			}			
		}
	}

	private void revCertFilePressed() {
		File file = chooseFile();
		if (file != null) {
			X509Certificate cerRev = openFileCertificate(file);
			if (cerRev != null) {
				listRevokedEntry.add(new RevokedEntry(cerRev.getSerialNumber(), new Date(), CRLReason.unspecified));
				RevokedCertsTableModel revokedCertsTableModel = (RevokedCertsTableModel) jtRevokedCerts.getModel();
				revokedCertsTableModel.load(listRevokedEntry);
			}
		}
	}

	private void revLoadCrlPressed() {
		File file = chooseFile();
		if (file != null) {
			X509CRL loadCrl = openFileCrl(file);
			if (loadCrl != null) {
				crl = loadCrl;
				populate();
			}
		}
	}

	private X509CRL openFileCrl (File file) {
		try {
			CryptoFileType fileType = CryptoFileUtil.detectFileType(file);
			if (fileType == CryptoFileType.CRL) {				
				return openCrl(file);
			}
		} catch (IOException e) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("ExamineFileAction.UnknownFileType.message"), file),
					res.getString("ExamineFileAction.ExamineFile.Title"), JOptionPane.WARNING_MESSAGE);
		}
		return null;
	}
	
	private X509CRL openCrl(File file) {
		try {
			try (FileInputStream is = new FileInputStream(file)) {
				X509CRL crl = X509CertUtil.loadCRL(IOUtils.toByteArray(is));
				return crl;
			}
		} catch (CryptoException | IOException e) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("ExamineFileAction.UnknownFileType.message"), file),
					res.getString("ExamineFileAction.ExamineFile.Title"), JOptionPane.WARNING_MESSAGE);
		}
		return null;
	}
	
	private X509Certificate openFileCertificate (File file) {
		try {
			CryptoFileType fileType = CryptoFileUtil.detectFileType(file);
			if (fileType == CryptoFileType.CERT) {
				X509Certificate[] certificates = openCertificate(file);
				return certificates[0];
			}
		} catch (IOException e) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("ExamineFileAction.UnknownFileType.message"), file),
					res.getString("ExamineFileAction.ExamineFile.Title"), JOptionPane.WARNING_MESSAGE);
		}
		return null;
	}

	protected X509Certificate[] openCertificate(File certificateFile) {
		try {
			return openCertificate(FileUtils.readFileToByteArray(certificateFile), certificateFile.getName());
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("KeyStoreExplorerAction.NoReadFile.message"), certificateFile),
					res.getString("KeyStoreExplorerAction.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
			return new X509Certificate[0];
		}
	}

	protected X509Certificate[] openCertificate(byte[] data, String name) {

		try {
			X509Certificate[] certs = X509CertUtil.loadCertificates(data);

			if (certs.length == 0) {
				JOptionPane.showMessageDialog(this,
						MessageFormat.format(res.getString("KeyStoreExplorerAction.NoCertsFound.message"), name),
						res.getString("KeyStoreExplorerAction.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
			}

			return certs;
		} catch (Exception ex) {
			String problemStr = MessageFormat.format(res.getString("KeyStoreExplorerAction.NoOpenCert.Problem"), name);

			String[] causes = new String[] { res.getString("KeyStoreExplorerAction.NotCert.Cause"),
					res.getString("KeyStoreExplorerAction.CorruptedCert.Cause") };

			Problem problem = new Problem(problemStr, causes, ex);

			DProblem dProblem = new DProblem(parent, res.getString("KeyStoreExplorerAction.ProblemOpeningCert.Title"),
					problem);
			dProblem.setLocationRelativeTo(this);
			dProblem.setVisible(true);

			return null;
		}
	}

	private File chooseFile() {

		JFileChooser chooser = FileChooserFactory.getCertFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("ExamineFileAction.ExamineFile.Title"));
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText(res.getString("ExamineFileAction.ExamineFile.button"));
		int rtnValue = chooser.showOpenDialog(this);
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			return openFile;
		}
		return null;
	}

	public List<RevokedEntry> getListRevokedEntry() {
		return listRevokedEntry;
	}
	
}
