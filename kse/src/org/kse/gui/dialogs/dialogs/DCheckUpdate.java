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
package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.URL;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import org.apache.commons.io.IOUtils;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.net.URLs;
import org.kse.version.Version;

/**
 * Check for an updated version of KeyStore Explorer. This check works over the
 * net so the user may cancel at any time by pressing the cancel button.
 *
 */
public class DCheckUpdate extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

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
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
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
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpCancel = PlatformUtil.createDialogButtonPanel(jbCancel, false);

		getContentPane().add(jpCheckUpdate, BorderLayout.NORTH);
		getContentPane().add(jpProgress, BorderLayout.CENTER);
		getContentPane().add(jpCancel, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
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
		@Override
		public void run() {
			try {
				// Get the version number of the latest KeyStore Explorer from its web site
				URL latestVersionUrl = new URL(URLs.LATEST_VERSION_ADDRESS);

				String versionString = IOUtils.toString(latestVersionUrl, "ASCII");
				latestVersion = new Version(versionString);

				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						closeDialog();
					}
				});
			} catch (final Exception ex) {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						if (DCheckUpdate.this.isShowing()) {
							String problemStr = res.getString("DCheckUpdate.NoCheckUpdate.Problem");

							String[] causes = new String[] { res.getString("DCheckUpdate.UpdateHostUnavailable.Cause"),
									res.getString("DCheckUpdate.ProxySettingsIncorrect.Cause") };

							Problem problem = new Problem(problemStr, causes, ex);

							DProblem dProblem = new DProblem(DCheckUpdate.this, res
									.getString("DCheckUpdate.ProblemCheckingUpdate.Title"), problem);
							dProblem.setLocationRelativeTo(DCheckUpdate.this);
							dProblem.setVisible(true);

							closeDialog();
						}
					}
				});
			}
		}
	}
}
