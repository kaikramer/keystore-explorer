package org.kse.gui.crypto.distributionpoints;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.generalname.JGeneralNames;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

public class DDistributionPointsChooser extends JEscDialog {

	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/distributionpoints/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;
	private JLabel jlDistributionPointFullName;
	private JGeneralNames jgnDistributionPointFullName;
	private JLabel jlDistributionPointReasonFlags;
	private JPanel jpDistributionPointReasonFlags;
	private JLabel jlDistributionPointCrlIssuer;
	private JGeneralNames jgnDistributionPointCrlIssuer;
	private JPanel jpDistributionPoint;
	private JCheckBox jcbUnused;
	private JCheckBox jcbKeyCompromise;
	private JCheckBox jcbCACompromise;
	private JCheckBox jcbAffiliationChanged;
	private JCheckBox jcbSuperseded;
	private JCheckBox jcbCessationOfOperation;
	private JCheckBox jcbCertificateHold;
	private JCheckBox jcbPrivilegeWithdrawn;
	private JCheckBox jcbAACompromise;

	private DistributionPoint distributionPoint = null;

	public DDistributionPointsChooser(JFrame parent, String title, DistributionPoint distributionPoint) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(distributionPoint);
	}

	public DDistributionPointsChooser(JDialog parent, String title, DistributionPoint distributionPoint) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(distributionPoint);
	}

	private void initComponents(DistributionPoint distributionPoint) {

		jlDistributionPointFullName = new JLabel(
				res.getString("DDistributionPointsChooser.jlDistributionPointFullName.text"));

		GridBagConstraints gbc_jlDistributionPointFullName = new GridBagConstraints();
		gbc_jlDistributionPointFullName.gridx = 0;
		gbc_jlDistributionPointFullName.gridy = 0;
		gbc_jlDistributionPointFullName.gridwidth = 1;
		gbc_jlDistributionPointFullName.gridheight = 1;
		gbc_jlDistributionPointFullName.insets = new Insets(0, 5, 0, 5);
		gbc_jlDistributionPointFullName.anchor = GridBagConstraints.NORTHEAST;

		GridBagConstraints gbc_jgnDistributionPointFullName = new GridBagConstraints();
		gbc_jgnDistributionPointFullName.gridx = 1;
		gbc_jgnDistributionPointFullName.gridy = 0;
		gbc_jgnDistributionPointFullName.gridwidth = 1;
		gbc_jgnDistributionPointFullName.gridheight = 1;
		gbc_jgnDistributionPointFullName.insets = new Insets(0, 5, 0, 5);
		gbc_jgnDistributionPointFullName.anchor = GridBagConstraints.WEST;

		jgnDistributionPointFullName = new JGeneralNames(
				res.getString("DDistributionPointsChooser.DistributionPointFullName.Title"));
		jgnDistributionPointFullName.setPreferredSize(new Dimension(550, 150));

		jlDistributionPointReasonFlags = new JLabel(
				res.getString("DDistributionPointsChooser.jlDistributionPointReasonFlags.text"));

		GridBagConstraints gbc_jlDistributionPointReasonFlags = new GridBagConstraints();
		gbc_jlDistributionPointReasonFlags.gridx = 0;
		gbc_jlDistributionPointReasonFlags.gridy = 1;
		gbc_jlDistributionPointReasonFlags.gridwidth = 1;
		gbc_jlDistributionPointReasonFlags.gridheight = 1;
		gbc_jlDistributionPointReasonFlags.insets = new Insets(0, 5, 0, 5);
		gbc_jlDistributionPointReasonFlags.anchor = GridBagConstraints.NORTHEAST;

		jpDistributionPointReasonFlags = new JPanel();
		jpDistributionPointReasonFlags.setBorder(new CompoundBorder(new EmptyBorder(0,0,0,0), new EmptyBorder(0, 0, 0, 0)));
		jpDistributionPointReasonFlags.setLayout(new MigLayout("insets dialog, fill", "", ""));
		jpDistributionPointReasonFlags.setPreferredSize(new Dimension(550, 150));

		GridBagConstraints gbc_jpDistributionPointReasonFlags = new GridBagConstraints();
		gbc_jpDistributionPointReasonFlags.gridx = 1;
		gbc_jpDistributionPointReasonFlags.gridy = 1;
		gbc_jpDistributionPointReasonFlags.gridwidth = 1;
		gbc_jpDistributionPointReasonFlags.gridheight = 1;
		gbc_jpDistributionPointReasonFlags.insets = new Insets(0, 5, 0, 5);
		gbc_jpDistributionPointReasonFlags.anchor = GridBagConstraints.WEST;

		jcbUnused = new JCheckBox(res.getString("DDistributionPointsChooser.jcbUnused.text"));
		jcbKeyCompromise = new JCheckBox(res.getString("DDistributionPointsChooser.jcbKeyCompromise.text"));
		jcbCACompromise = new JCheckBox(res.getString("DDistributionPointsChooser.jcbCACompromise.text"));
		jcbAffiliationChanged = new JCheckBox(res.getString("DDistributionPointsChooser.jcbAffiliationChanged.text"));
		jcbSuperseded = new JCheckBox(res.getString("DDistributionPointsChooser.jcbSuperseded.text"));
		jcbCessationOfOperation = new JCheckBox(
				res.getString("DDistributionPointsChooser.jcbCessationOfOperation.text"));
		jcbCertificateHold = new JCheckBox(res.getString("DDistributionPointsChooser.jcbCertificateHold.text"));
		jcbPrivilegeWithdrawn = new JCheckBox(res.getString("DDistributionPointsChooser.jcbPrivilegeWithdrawn.text"));
		jcbAACompromise = new JCheckBox(res.getString("DDistributionPointsChooser.jcbAACompromise.text"));

		jpDistributionPointReasonFlags.add(jcbUnused, "");
		jpDistributionPointReasonFlags.add(jcbKeyCompromise, "");
		jpDistributionPointReasonFlags.add(jcbCACompromise, "wrap");
		jpDistributionPointReasonFlags.add(jcbAffiliationChanged, "");
		jpDistributionPointReasonFlags.add(jcbSuperseded, "");
		jpDistributionPointReasonFlags.add(jcbCessationOfOperation, "wrap");
		jpDistributionPointReasonFlags.add(jcbCertificateHold, "");
		jpDistributionPointReasonFlags.add(jcbPrivilegeWithdrawn, "");
		jpDistributionPointReasonFlags.add(jcbAACompromise, "wrap");

		jlDistributionPointCrlIssuer = new JLabel(
				res.getString("DDistributionPointsChooser.jlDistributionPointCrlIssuer.text"));

		GridBagConstraints gbc_jlDistributionPointCrlIssuer = new GridBagConstraints();
		gbc_jlDistributionPointCrlIssuer.gridx = 0;
		gbc_jlDistributionPointCrlIssuer.gridy = 2;
		gbc_jlDistributionPointCrlIssuer.gridwidth = 1;
		gbc_jlDistributionPointCrlIssuer.gridheight = 1;
		gbc_jlDistributionPointCrlIssuer.insets = new Insets(0, 5, 0, 5);
		gbc_jlDistributionPointCrlIssuer.anchor = GridBagConstraints.NORTHEAST;

		GridBagConstraints gbc_jgnDistributionPointCrlIssuer = new GridBagConstraints();
		gbc_jgnDistributionPointCrlIssuer.gridx = 1;
		gbc_jgnDistributionPointCrlIssuer.gridy = 2;
		gbc_jgnDistributionPointCrlIssuer.gridwidth = 1;
		gbc_jgnDistributionPointCrlIssuer.gridheight = 1;
		gbc_jgnDistributionPointCrlIssuer.insets = new Insets(0, 5, 0, 5);
		gbc_jgnDistributionPointCrlIssuer.anchor = GridBagConstraints.WEST;

		jgnDistributionPointCrlIssuer = new JGeneralNames(
				res.getString("DDistributionPointsChooser.DistributionPointCrlIssuer.Title"));
		jgnDistributionPointCrlIssuer.setPreferredSize(new Dimension(550, 150));

		jpDistributionPoint = new JPanel(new GridBagLayout());

		jpDistributionPoint.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpDistributionPoint.add(jlDistributionPointFullName, gbc_jlDistributionPointFullName);
		jpDistributionPoint.add(jgnDistributionPointFullName, gbc_jgnDistributionPointFullName);

		jpDistributionPoint.add(jlDistributionPointReasonFlags, gbc_jlDistributionPointReasonFlags);
		jpDistributionPoint.add(jpDistributionPointReasonFlags, gbc_jpDistributionPointReasonFlags);

		jpDistributionPoint.add(jlDistributionPointCrlIssuer, gbc_jlDistributionPointCrlIssuer);
		jpDistributionPoint.add(jgnDistributionPointCrlIssuer, gbc_jgnDistributionPointCrlIssuer);

		jbOK = new JButton(res.getString("DGeneralNameChooser.jbOK.text"));
		jbCancel = new JButton(res.getString("DGeneralNameChooser.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpDistributionPoint, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		jbOK.addActionListener(evt -> okPressed());
		jbCancel.addActionListener(evt -> cancelPressed());
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		populate(distributionPoint);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populate(DistributionPoint distributionPoint) {
		if (distributionPoint != null) {
			DistributionPointName dist = distributionPoint.getDistributionPoint();
			if (dist != null) {
				GeneralNames generalNames = GeneralNames.getInstance(dist.getName());
				jgnDistributionPointFullName.setGeneralNames(generalNames);
			}
			GeneralNames cRLIssuer = distributionPoint.getCRLIssuer();
			if (cRLIssuer != null) {
				jgnDistributionPointCrlIssuer.setGeneralNames(cRLIssuer);
			}

			ReasonFlags reasonFlags = distributionPoint.getReasons();
			if (reasonFlags != null) {

				DERBitString reasonFlagsBitString = (DERBitString) reasonFlags.toASN1Primitive();
				int reasonFlagsInt = reasonFlagsBitString.intValue();

				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.unused)) {
					jcbUnused.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.keyCompromise)) {
					jcbKeyCompromise.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.cACompromise)) {
					jcbCACompromise.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.affiliationChanged)) {
					jcbAffiliationChanged.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.superseded)) {
					jcbSuperseded.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.cessationOfOperation)) {
					jcbCessationOfOperation.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.certificateHold)) {
					jcbCertificateHold.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.privilegeWithdrawn)) {
					jcbPrivilegeWithdrawn.setSelected(true);
				}
				if (hasReasonFlag(reasonFlagsInt, ReasonFlags.aACompromise)) {
					jcbAACompromise.setSelected(true);
				}
			}
		}
	}

	private void okPressed() {

		DistributionPointName distributionPointName = null;

		ReasonFlags reasonFlags = null;
		int reasons = 0;

		if (jcbUnused.isSelected()) {
			reasons = reasons | ReasonFlags.unused;
		}
		if (jcbKeyCompromise.isSelected()) {
			reasons = reasons | ReasonFlags.keyCompromise;
		}
		if (jcbCACompromise.isSelected()) {
			reasons = reasons | ReasonFlags.cACompromise;
		}
		if (jcbAffiliationChanged.isSelected()) {
			reasons = reasons | ReasonFlags.affiliationChanged;
		}
		if (jcbSuperseded.isSelected()) {
			reasons = reasons | ReasonFlags.superseded;
		}
		if (jcbCessationOfOperation.isSelected()) {
			reasons = reasons | ReasonFlags.cessationOfOperation;
		}
		if (jcbCertificateHold.isSelected()) {
			reasons = reasons | ReasonFlags.certificateHold;
		}
		if (jcbPrivilegeWithdrawn.isSelected()) {
			reasons = reasons | ReasonFlags.privilegeWithdrawn;
		}
		if (jcbAACompromise.isSelected()) {
			reasons = reasons | ReasonFlags.aACompromise;
		}
		if (reasons > 0) {
			reasonFlags = new ReasonFlags(reasons);
		}

		if (jgnDistributionPointFullName.getGeneralNames().getNames().length == 0) {
			JOptionPane.showMessageDialog(this,
					res.getString("DDistributionPointsChooser.DistributionPointFullNameNumberNonZero.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		} else {
			distributionPointName = new DistributionPointName(jgnDistributionPointFullName.getGeneralNames());
		}

		GeneralNames cRLIssuer = null;
		if (jgnDistributionPointCrlIssuer.getGeneralNames().getNames().length > 0) {
			cRLIssuer = jgnDistributionPointCrlIssuer.getGeneralNames();
		}
		distributionPoint = new DistributionPoint(distributionPointName, reasonFlags, cRLIssuer);
		closeDialog();
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	public DistributionPoint getDistributionPoint() {
		return distributionPoint;
	}

	private static boolean hasReasonFlag(int reasonFlags, int reasonFlag) {
		return (reasonFlags & reasonFlag) == reasonFlag;
	}

	public static void main(String[] args) throws Exception {
		DialogViewer.run(new DDistributionPointsChooser(new javax.swing.JFrame(), "DistributionPointsChooser", null));
	}

}
