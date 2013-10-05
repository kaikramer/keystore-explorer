/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.Scanner;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;
import net.sf.keystore_explorer.version.Version;

/**
 * Check for an updated version of KeyStore Explorer. This check works over the
 * net so the user may cancel at any time by pressing the cancel button.
 * 
 */
public class DCheckUpdate extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpCheckUpdate;
	private JLabel jlCheckUpdate;
	private JPanel jpProgress;
	private JProgressBar jpbCheckUpdate;
	private JPanel jpCancel;
	private JButton jbCancel;

	private Thread checker;
	private Version latestVersion;

	/**
	 * Creates a new DCheckUpdate dialog.
	 * 
	 * @param parent
	 *            The parent frame
	 */
	public DCheckUpdate(JFrame parent) {
		super(parent, Dialog.ModalityType.APPLICATION_MODAL);
		initComponents();
	}

	private void initComponents() {
		jlCheckUpdate = new JLabel(res.getString("DCheckUpdate.jlCheckUpdate.text"));
		ImageIcon icon = new ImageIcon(getClass().getResource(res.getString("DCheckUpdate.jlCheckUpdate.image")));
		jlCheckUpdate.setIcon(icon);
		jlCheckUpdate.setHorizontalTextPosition(SwingConstants.LEADING);
		jlCheckUpdate.setIconTextGap(15);

		jpCheckUpdate = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpCheckUpdate.add(jlCheckUpdate);
		jpCheckUpdate.setBorder(new EmptyBorder(5, 5, 5, 5));

		jpbCheckUpdate = new JProgressBar();
		jpbCheckUpdate.setIndeterminate(true);
		jpbCheckUpdate.setString("DCheckUpdate.jlCheckUpdate.text");

		jpProgress = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpProgress.add(jpbCheckUpdate);
		jpProgress.setBorder(new EmptyBorder(5, 5, 5, 5));

		jbCancel = new JButton(res.getString("DCheckUpdate.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpCancel = PlatformUtil.createDialogButtonPanel(jbCancel, false);

		getContentPane().add(jpCheckUpdate, BorderLayout.NORTH);
		getContentPane().add(jpProgress, BorderLayout.CENTER);
		getContentPane().add(jpCancel, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				if ((checker != null) && (checker.isAlive())) {
					checker.interrupt();
				}
				closeDialog();
			}
		});

		setTitle(res.getString("DCheckUpdate.Title"));
		setResizable(false);

		pack();
	}

	/**
	 * Start key pair generation in a separate thread.
	 */
	public void startCheck() {
		checker = new Thread(new CheckForUpdate());
		checker.setPriority(Thread.MIN_PRIORITY);
		checker.start();
	}

	private void cancelPressed() {
		if ((checker != null) && (checker.isAlive())) {
			checker.interrupt();
		}
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	/**
	 * Get latest version found by check.
	 * 
	 * @return latest version or null if none found.
	 */
	public Version getLatestVersion() {
		return latestVersion;
	}

	private class CheckForUpdate implements Runnable {
		private void displayErrorCloseDialog(final String message) {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					JOptionPane.showMessageDialog(DCheckUpdate.this, message, DCheckUpdate.this.getTitle(),
							JOptionPane.ERROR_MESSAGE);
					closeDialog();
				}
			});
		}

		public void run() {
			HttpURLConnection urlConn = null;

			try {
				/*
				 * Get the version number of the latest KeyStore Explorer from
				 * the Internet - present in a serialised Version object on the
				 * KeyStore Explorer web site
				 */
				URL latestVersionUrl = new URL(res.getString("DCheckUpdate.LatestVersionAddress"));
				urlConn = (HttpURLConnection) latestVersionUrl.openConnection();

				int responseCode = urlConn.getResponseCode();

				if (responseCode != HttpURLConnection.HTTP_OK) {
					String errorMessage = MessageFormat.format(res.getString("DCheckUpdate.Non200Response.message"),
							responseCode, latestVersionUrl);
					displayErrorCloseDialog(errorMessage);
					return;
				}

				// trick from https://weblogs.java.net/blog/pat/archive/2004/10/stupid_scanner_1.html
				Scanner s = new Scanner(urlConn.getInputStream());
				s.useDelimiter("\\A");
			    String versionString = s.hasNext() ? s.next() : "";
			    s.close();
				latestVersion = new Version(versionString);

				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						closeDialog();
					}
				});
			} catch (final Exception ex) {
				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						if (DCheckUpdate.this.isShowing()) {
							String problemStr = res.getString("DCheckUpdate.NoCheckUpdate.Problem");

							String[] causes = new String[] { res.getString("DCheckUpdate.UpdateHostUnavailable.Cause"),
									res.getString("DCheckUpdate.ProxySettingsIncorrect.Cause") };

							Problem problem = new Problem(problemStr, causes, ex);

							DProblem dProblem = new DProblem(DCheckUpdate.this, res
									.getString("DCheckUpdate.ProblemCheckingUpdate.Title"), APPLICATION_MODAL, problem);
							dProblem.setLocationRelativeTo(DCheckUpdate.this);
							dProblem.setVisible(true);

							closeDialog();
						}
					}
				});
			} finally {
				if (urlConn != null) {
					urlConn.disconnect();
				}
			}
		}
	}
}
