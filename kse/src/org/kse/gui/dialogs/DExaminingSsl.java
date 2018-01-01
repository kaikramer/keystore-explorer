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
import java.security.KeyStore;
import java.text.MessageFormat;
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

import org.kse.crypto.Password;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.ssl.SslConnectionInfos;
import org.kse.utilities.ssl.SslUtils;

/**
 * Examines an SSL connection's certificates - a process which the user may
 * cancel at any time by pressing the cancel button.
 *
 */
public class DExaminingSsl extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpExaminingSsl;
	private JLabel jlExaminingSsl;
	private JPanel jpProgress;
	private JProgressBar jpbExaminingSsl;
	private JPanel jpCancel;
	private JButton jbCancel;

	private String sslHost;
	private int sslPort;
	private KeyStore keyStore;
	private char[] password;
	private SslConnectionInfos sslInfos;
	private Thread examiner;

	/**
	 * Creates a new DExaminingSsl dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param sslHost
	 *            SSL connection's host name
	 * @param sslPort
	 *            SSL connection's port number
	 * @param useClientAuth
	 *            Try to connect with client certificate
	 * @param ksh
	 *            KeyStore with client certificate
	 */
	public DExaminingSsl(JFrame parent, String sslHost, int sslPort, boolean useClientAuth, KeyStoreHistory ksh) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);

		this.sslHost = sslHost;
		this.sslPort = sslPort;

		if (useClientAuth) {
			this.keyStore = ksh.getCurrentState().getKeyStore();

			// some keystore types like MSCAPI and PKCS#11 have no password stored in their state
			Password pwd = ksh.getCurrentState().getPassword();
			if (pwd != null) {
				this.password = pwd.toCharArray();
			}
		}
		initComponents();
	}

	private void initComponents() {
		jlExaminingSsl = new JLabel(res.getString("DExaminingSsl.jlExaminingSsl.text"));
		ImageIcon icon = new ImageIcon(getClass().getResource(res.getString("DExaminingSsl.jlExaminingSsl.image")));
		jlExaminingSsl.setIcon(icon);
		jlExaminingSsl.setHorizontalTextPosition(SwingConstants.LEADING);
		jlExaminingSsl.setIconTextGap(15);

		jpExaminingSsl = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpExaminingSsl.add(jlExaminingSsl);
		jpExaminingSsl.setBorder(new EmptyBorder(5, 5, 5, 5));

		jpbExaminingSsl = new JProgressBar();
		jpbExaminingSsl.setIndeterminate(true);

		jpProgress = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpProgress.add(jpbExaminingSsl);
		jpProgress.setBorder(new EmptyBorder(5, 5, 5, 5));

		jbCancel = new JButton(res.getString("DExaminingSsl.jbCancel.text"));
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

		getContentPane().add(jpExaminingSsl, BorderLayout.NORTH);
		getContentPane().add(jpProgress, BorderLayout.CENTER);
		getContentPane().add(jpCancel, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				if ((examiner != null) && (examiner.isAlive())) {
					examiner.interrupt();
				}
				closeDialog();
			}
		});

		setTitle(res.getString("DExaminingSsl.Title"));
		setResizable(false);

		pack();
	}

	/**
	 * Start SSL connection examination in a separate thread.
	 */
	public void startExamination() {
		examiner = new Thread(new ExamineSsl());
		examiner.setPriority(Thread.MIN_PRIORITY);
		examiner.start();
	}

	/**
	 * Get the SSL connection's certificates and some details like protocol version or cipher suite.
	 *
	 * @return The SSL connection's details or null if the user cancelled
	 *         the dialog or an error occurred
	 */
	public SslConnectionInfos getSSLConnectionInfos() {
		return sslInfos;
	}

	private void cancelPressed() {
		if ((examiner != null) && (examiner.isAlive())) {
			examiner.interrupt();
		}
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private class ExamineSsl implements Runnable {
		@Override
		public void run() {
			try {
				sslInfos = SslUtils.readSSLConnectionInfos(sslHost, sslPort, keyStore, password);

				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						if (DExaminingSsl.this.isShowing()) {
							closeDialog();
						}
					}
				});
			} catch (final Exception ex) {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						if (DExaminingSsl.this.isShowing()) {
							String problemStr = MessageFormat.format(
									res.getString("DExaminingSsl.NoExamineSsl.Problem"), sslHost, "" + sslPort);

							String[] causes = new String[] { res.getString("DExaminingSsl.SslHostPortIncorrect.Cause"),
									res.getString("DExaminingSsl.SslHostUnavailable.Cause"),
									res.getString("DExaminingSsl.ProxySettingsIncorrect.Cause") };

							Problem problem = new Problem(problemStr, causes, ex);

							DProblem dProblem = new DProblem(DExaminingSsl.this, res
									.getString("DExaminingSsl.ProblemExaminingSsl.Title"), problem);
							dProblem.setLocationRelativeTo(DExaminingSsl.this);
							dProblem.setVisible(true);

							closeDialog();
						}
					}
				});
			}
		}
	}
}
