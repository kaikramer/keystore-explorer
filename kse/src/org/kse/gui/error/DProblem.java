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
package org.kse.gui.error;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;

/**
 * Displays a problem and its possible causes.
 *
 */
public class DProblem extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/error/resources");

	private JPanel jpProblem;
	private JPanel jpProblemHeader;
	private JLabel jlProblemHeader;
	private JPanel jpCauses;
	private JLabel jlCauses;
	private JPanel jpButtons;
	private JButton jbDisplayError;
	private JButton jbOK;

	private Problem problem;

	/**
	 * Creates new DProblem dialog where the parent is a frame.
	 *  @param parent
	 *            Parent frame
	 * @param title
	 *            Dialog title
	 * @param problem
	 */
	public DProblem(JFrame parent, String title, Problem problem) {
		super(parent, ModalityType.DOCUMENT_MODAL);
		setTitle(title);
		this.problem = problem;

		initComponents();
	}

	/**
	 * Creates new DProblem dialog where the parent is a dialog.
	 *  @param parent
	 *            Parent dialog
	 * @param title
	 *            Dialog title
	 * @param problem
	 */
	public DProblem(JDialog parent, String title, Problem problem) {
		super(parent, ModalityType.DOCUMENT_MODAL);
		setTitle(title);
		this.problem = problem;

		initComponents();
	}

	private void initComponents() {
		jpProblemHeader = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpProblemHeader.setBorder(new EmptyBorder(5, 5, 5, 5));
		if (!LnfUtil.isDarkLnf()) {
			jpProblemHeader.setBackground(Color.WHITE);
		}
		jpProblemHeader.setBorder(new CompoundBorder(new MatteBorder(0, 0, 1, 0, Color.WHITE), new CompoundBorder(
				new MatteBorder(0, 0, 1, 0, Color.GRAY), new EmptyBorder(10, 10, 10, 10))));

		ImageIcon icon = new ImageIcon(getClass().getResource(res.getString("DProblem.Problem.image")));

		jlProblemHeader = new JLabel(formatProblem());
		jlProblemHeader.setIconTextGap(15);
		jlProblemHeader.setIcon(icon);

		jpProblemHeader.add(jlProblemHeader);

		jpCauses = new JPanel(new FlowLayout(FlowLayout.LEFT));

		jlCauses = new JLabel(formatCauses());

		jpCauses.add(jlCauses);
		jpCauses.setBorder(new CompoundBorder(new MatteBorder(0, 0, 1, 0, Color.WHITE), new CompoundBorder(
				new MatteBorder(0, 0, 1, 0, Color.GRAY), new EmptyBorder(0, 5, 5, 10))));

		jpProblem = new JPanel(new BorderLayout(0, 0));
		jpProblem.add(jpProblemHeader, BorderLayout.NORTH);
		jpProblem.add(jpCauses, BorderLayout.CENTER);

		jbDisplayError = new JButton(res.getString("DProblem.jbDisplayError.text"));
		PlatformUtil.setMnemonic(jbDisplayError, res.getString("DProblem.jbDisplayError.mnemonic").charAt(0));
		jbDisplayError.setToolTipText(res.getString("DProblem.jbDisplayError.tooltip"));
		jbDisplayError.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DProblem.this);
					showError();
				} finally {
					CursorUtil.setCursorFree(DProblem.this);
				}
			}
		});

		jbOK = new JButton(res.getString("DProblem.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbDisplayError, false);

		getContentPane().add(jpProblem, BorderLayout.NORTH);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setResizable(false);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		pack();

		// "requestFocusInWindow() has to be called after component has been realized, but before frame is displayed"
		getRootPane().setDefaultButton(jbOK);
		jbOK.requestFocusInWindow();
	}

	private String formatProblem() {
		return MessageFormat.format("<html>{0}</html>", breakLine(problem.getProblem(), 50));
	}

	private String formatCauses() {
		StringBuffer sb = new StringBuffer();

		sb.append("<html>");
		sb.append(res.getString("DProblem.PossibleReasons.text"));
		sb.append("<ul style='margin-left:20'>");
		for (String solution : problem.getCauses()) {
			sb.append("<li style='padding-top:5; padding-botton:5'>");
			sb.append(breakLine(solution, 55));
			sb.append("</li>");
		}
		sb.append("</ul>");
		sb.append("</html>");

		return sb.toString();
	}

	private String breakLine(String line, int maxLineLength) {
		StringBuffer sb = new StringBuffer();

		StringTokenizer strTok = new StringTokenizer(line, " ");

		String currentLine = "";

		while (strTok.hasMoreTokens()) {
			String word = strTok.nextToken();

			if (currentLine.length() == 0) {
				currentLine += word;
				continue;
			}

			if (currentLine.length() + word.length() + 1 <= maxLineLength) {
				currentLine += " ";
				currentLine += word;
			} else {
				if (sb.length() > 0) {
					sb.append("<br>");
				}

				sb.append(currentLine);
				currentLine = word;
			}
		}

		if (sb.length() > 0) {
			sb.append("<br>");
		}

		sb.append(currentLine);

		return sb.toString();
	}

	private void showError() {
		DError dError = new DError(this, res.getString("DProblem.CauseError.Title"),
				problem.getError());
		dError.setLocationRelativeTo(this);
		dError.setVisible(true);
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
