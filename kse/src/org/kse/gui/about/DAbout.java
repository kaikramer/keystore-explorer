/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.gui.about;

import java.awt.Color;
import java.awt.Desktop;
import java.awt.EventQueue;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.UIManager;

import org.kse.KSE;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.actions.AboutAction;
import org.kse.gui.ticker.JTicker;
import org.kse.utilities.net.URLs;

import net.miginfocom.swing.MigLayout;

/**
 * An About dialog which displays an image of about information, a ticker for
 * acknowledgements and a button to access system information.
 *
 */
public class DAbout extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/about/resources");

	private static final Color KSE_COLOR = LnfUtil.isDarkLnf() ? new Color(116, 131, 141) : new Color(0, 134, 201);

	private JPanel jpAbout = new JPanel();

	private JLabel jlKSE = new JLabel(KSE.getApplicationName());
	private JLabel jlIcon;
	private JLabel jlVersion;
	private JLabel jlLicense;

	private JTicker jtkDetails;
	private JButton jbOK;
	private JButton jbCredits;

	/**
	 * Creates new DAbout dialog.
	 *  @param parent
	 *            Parent frame
	 * @param title
	 *            The title of the dialog
	 * @param aboutImg
	 *            The image containing the about information
	 * @param tickerItems
	 */
	public DAbout(JFrame parent, String title, String licenseNotice, Image aboutImg, Object[] tickerItems) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		initComponents(aboutImg, licenseNotice, tickerItems);
	}

	private void initComponents(Image aboutImg, String licenseNotice, Object[] tickerItems) {

		// init ticker
		jtkDetails = new JTicker();
		jtkDetails.setIncrement(1);
		jtkDetails.setGap(40);
		jtkDetails.setInterval(20);

		for (int i = 0; i < tickerItems.length; i++) {
			jtkDetails.addItem(tickerItems[i]);
		}

		// prepare other elements
		jlKSE = new JLabel(KSE.getApplicationName());
		jlKSE.setFont(jlKSE.getFont().deriveFont(20f));
		jlKSE.setForeground(KSE_COLOR);

		jlIcon = new JLabel(new ImageIcon(aboutImg));

		jlVersion = new JLabel("Version " + KSE.getApplicationVersion());
		jlLicense = new JLabel(licenseNotice);

		jbOK = new JButton(res.getString("DAbout.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCredits = new JButton(res.getString("DAbout.jbCredits.text"));
		PlatformUtil.setMnemonic(jbCredits, res.getString("DAbout.jbCredits.mnemonic").charAt(0));
		jbCredits.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				openCreditsPageInBrowser();
			}
		});

		// layout
		jpAbout.setLayout(new MigLayout("insets dialog, fill"));
		jpAbout.add(jlKSE, "top");
		jpAbout.add(jlIcon, "top, right, spany 2, wrap unrel");
		jpAbout.add(jlVersion, "top, wrap para");
		jpAbout.add(jlLicense, "span, wrap unrel");
		jpAbout.add(jtkDetails, "width 100%, span, wrap para:push");

		jpAbout.add(jbCredits, "");
		jpAbout.add(jbOK, "tag ok");

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getContentPane().add(jpAbout);
		getRootPane().setDefaultButton(jbOK);
		setResizable(false);
		pack();

		jtkDetails.start();

		// because in windows laf default button follows focus, OK would not be the default button anymore
		jbOK.requestFocusInWindow();
	}

	protected void openCreditsPageInBrowser() {
		try {
			Desktop.getDesktop().browse(URI.create(URLs.KSE_WEBSITE_CONTRIBUTORS));
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					MessageFormat.format(res.getString("WebsiteAction.NoLaunchBrowser.message"),
							URLs.KSE_WEBSITE_CONTRIBUTORS),
					KSE.getApplicationName(), JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		jtkDetails.stop();
		dispose();
	}


	public static void main(String[] args) throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {

					Object[] tickerItems = { "Copyright 2004 -2013 Wayne Grant, 2013 - 2018 Kai Kramer ..." };
					javax.swing.JFrame frame = new javax.swing.JFrame();
					URL kseIconUrl = AboutAction.class.getResource("images/aboutdlg.png");
					DAbout dialog = new DAbout(frame, "About", "See help for details of the end user license agreement.",
							Toolkit.getDefaultToolkit().getImage(kseIconUrl), tickerItems);
					dialog.setLocationRelativeTo(frame);
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
