package org.kse.gui.crypto.crlDistributionPoints;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.Security;
import java.util.ResourceBundle;

import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.UIManager;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kse.gui.crypto.DAsn1Object;
import org.kse.gui.crypto.JBitFlag;
import org.kse.gui.crypto.generalname.JGeneralNames;
import org.kse.gui.dnchooser.RdnPanel;

public class DDistributionPoint extends DAsn1Object<DistributionPoint> {

	private static final long serialVersionUID = 6374222942197111228L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/crlDistributionPoints/resources");
	
	private static final String[] REASON_OPTIONS = {
			res.getString("DDistributionPoints.Reasons.unused"), 
			res.getString("DDistributionPoints.Reasons.keyCompromise"), 
			res.getString("DDistributionPoints.Reasons.cACompromise"), 
			res.getString("DDistributionPoints.Reasons.affiliationChanged"), 
			res.getString("DDistributionPoints.Reasons.superseded"), 
			res.getString("DDistributionPoints.Reasons.cessationOfOperation"), 
			res.getString("DDistributionPoints.Reasons.certificateHold"), 
			res.getString("DDistributionPoints.Reasons.privilegeWithdrawn"), 
			res.getString("DDistributionPoints.Reasons.aACompromise")
		};
	
	private ButtonGroup bgDistributionPointName;
	
	private JRadioButton jrbFullName;
	
	private JRadioButton jrbRelativeName;

	private JGeneralNames jgnDistributionPoint;

	private RdnPanel rdnpDistributionPoint;
	
	private JBitFlag jbfReasons;
	
	private JGeneralNames jgnCrlIssuer;

	public DDistributionPoint(JDialog parent, String title, DistributionPoint distributionPoint) {
		super(parent, title, distributionPoint, res, "CrlDistributionPoint");
		populate();
	}
	
	public DDistributionPoint(JFrame parent, String title, DistributionPoint distributionPoint) {
		super(parent, title, distributionPoint, res, "CrlDistributionPoint");
		populate();
	}

	private void populate() {
		DistributionPoint distributionPoint = getObject();
		
		if (distributionPoint == null) {
			return;
		}
		if (distributionPoint.getDistributionPoint().getType() == DistributionPointName.FULL_NAME) {
			jgnDistributionPoint.setGeneralNames(GeneralNames.getInstance(distributionPoint.getDistributionPoint().getName()));
			jrbFullName.doClick();
		} else {
			rdnpDistributionPoint.setRDN(RDN.getInstance(distributionPoint.getDistributionPoint().getName()));
			jrbRelativeName.doClick();
		}
		jbfReasons.setFlags(distributionPoint.getReasons());
		jgnCrlIssuer.setGeneralNames(GeneralNames.getInstance(distributionPoint.getCRLIssuer()));
	}

	protected JPanel createDialogBody() {
		rdnpDistributionPoint = new RdnPanel(null);

		JPanel jpDistributionPointNameType = new JPanel();
		jpDistributionPointNameType.setLayout(new BoxLayout(jpDistributionPointNameType, BoxLayout.X_AXIS));
		jrbFullName = new JRadioButton(res.getString("DDistributionPoints.DistributionPointName.FullName"));
		jrbRelativeName = new JRadioButton(res.getString("DDistributionPoints.DistributionPointName.RelativeName"));
		jpDistributionPointNameType.add(jrbFullName);
		jpDistributionPointNameType.add(jrbRelativeName);
		bgDistributionPointName = new ButtonGroup();
		bgDistributionPointName.add(jrbFullName);
		bgDistributionPointName.add(jrbRelativeName);
		
		jgnDistributionPoint = new JGeneralNames(res.getString("DDistributionPoints.DistributionPoints.Title"));
		jgnDistributionPoint.setPreferredSize(new Dimension(400, 150));
		

		JPanel jpDistributionPointName = new JPanel();
		jpDistributionPointName.setLayout(new BoxLayout(jpDistributionPointName, BoxLayout.Y_AXIS));
		jpDistributionPointName.add(rdnpDistributionPoint);
		jpDistributionPointName.add(jgnDistributionPoint);
		
		jbfReasons = new JBitFlag(3, REASON_OPTIONS);

		jgnCrlIssuer = new JGeneralNames(res.getString("DDistributionPoints.CrlIssuer.Title"));
		jgnCrlIssuer.setPreferredSize(new Dimension(400, 150));


		final JPanel jpPanel = new JPanel(new GridBagLayout());

		jpPanel.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		addLabelAndComponent(jpPanel, 0, "DDistributionPoints.DistributionPointName.Title", jpDistributionPointNameType);
		GridBagConstraints gbc_DistributionPointName = createConstraints(1, 1);
		gbc_DistributionPointName.gridwidth = 2;
		gbc_DistributionPointName.gridwidth  = GridBagConstraints.REMAINDER;
		jpPanel.add(jpDistributionPointName, gbc_DistributionPointName);
		addLabelAndComponent(jpPanel, 2, "DDistributionPoints.Reasons.Title", jbfReasons);
		addLabelAndComponent(jpPanel, 3, "DDistributionPoints.CrlIssuer.Title", jgnCrlIssuer);
		

		jrbFullName.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				rdnpDistributionPoint.setVisible(false);
				jgnDistributionPoint.setVisible(true);
				jpPanel.repaint();
			}
		});
		
		jrbRelativeName.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				rdnpDistributionPoint.setVisible(true);
				jgnDistributionPoint.setVisible(false);
				jpPanel.repaint();
			}
		});
		if (getObject() == null) {
			jrbRelativeName.doClick();
		}
		
		return jpPanel;
	}

	protected void addLabelAndComponent(JPanel jp, int rowNumber, String labelKey, JComponent ... components) {
		GridBagConstraints gbc_label = createConstraints(rowNumber, 0);
		jp.add(new JLabel(res.getString(labelKey)), gbc_label);
		
		for (JComponent component : components) {
			GridBagConstraints gbc_panel = createConstraints(rowNumber, 1);
			jp.add(component, gbc_panel);
		}
	}

	protected GridBagConstraints createConstraints(int rowNumber, int columnNumber) {
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.gridx = columnNumber;
		gbc_panel.gridy = rowNumber;
		gbc_panel.gridwidth = 1;
		gbc_panel.gridheight = 1;
		gbc_panel.insets = new Insets(5, 5, 5, 5);
		gbc_panel.anchor = GridBagConstraints.WEST;
		gbc_panel.gridwidth  = GridBagConstraints.RELATIVE;
		gbc_panel.fill  = GridBagConstraints.BOTH;
		return gbc_panel;
	}

	public void createObject() {
		DistributionPointName distributionPointName = null;
		if (jrbFullName.isSelected()) {
			distributionPointName = new DistributionPointName(jgnDistributionPoint.getGeneralNames());
		} else {
			RDN rdn = rdnpDistributionPoint.getRDN(true);
			if (rdn != null) {
				distributionPointName = new DistributionPointName(DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, rdn);
			}
		}
		ReasonFlags reasonFlags = new ReasonFlags(jbfReasons.getObject());
		GeneralNames crlIssuer = jgnCrlIssuer.getGeneralNames();
		setObject(new DistributionPoint(distributionPointName, reasonFlags, crlIssuer));
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					DDistributionPoint dialog = new DDistributionPoint(new javax.swing.JFrame(), "DDistributionPoint",
							null);
					dialog.addWindowListener(new java.awt.event.WindowAdapter() {
						@Override
						public void windowClosing(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
						@Override
						public void windowDeactivated(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}
