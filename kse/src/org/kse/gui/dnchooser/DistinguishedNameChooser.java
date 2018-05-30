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
package org.kse.gui.dnchooser;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collections;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.kse.crypto.x509.KseX500NameStyle;

/**
 * Flexible DN chooser/viewer component.
 *
 */
public class DistinguishedNameChooser extends JPanel {

	private static final long serialVersionUID = 2886549944489669970L;

	private boolean editable;
	private X500Name currentName;
	private String defaultName;
	private RdnPanelList listPanel;

	public DistinguishedNameChooser(X500Name dn, boolean editable, String defaultDN) {
		this.editable = editable;
		if (dn == null || dn.getRDNs().length == 0) {
			if (defaultDN == null || defaultDN.isEmpty()) {
				defaultDN = "CN=, OU=, O=, L=, ST=, C=";
			}
			currentName = new X500Name(KseX500NameStyle.INSTANCE, defaultDN);
		} else {
			this.currentName = dn;
		}
		this.defaultName = defaultDN;
		init();
	}

	private void init() {
		listPanel = new RdnPanelList(currentName, editable);

		JScrollPane jScrollPane = new JScrollPane(listPanel);
		jScrollPane.setViewportBorder(null);
		jScrollPane.setBorder(BorderFactory.createEmptyBorder());
		jScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		jScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

		setLayout(new BorderLayout());
		add(jScrollPane, BorderLayout.CENTER);
	}

	public X500Name getDN() {
		boolean noEmptyRdns = true;
		List<RDN> rdns = listPanel.getRdns(noEmptyRdns);
		Collections.reverse(rdns);
		return new X500Name(rdns.toArray(new RDN[rdns.size()]));
	}

	public X500Name getDNWithEmptyRdns() {
		List<RDN> rdns = listPanel.getRdns(false);
		Collections.reverse(rdns);
		return new X500Name(rdns.toArray(new RDN[rdns.size()]));
	}

	public void reset() {
		currentName = new X500Name(defaultName);
		removeAll();
		init();
		revalidate();
		repaint(50L);
	}

	public static void main(String[] args) throws Exception {

		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

		JFrame frame = new JFrame();
		frame.setSize(800, 400);

		X500Name dn = new X500Name(KseX500NameStyle.INSTANCE,
				"CN=test, OU=Development, OU=Software, O=ACME Ltd., C=UK, E=test@example.com");
		String defaultDN = "CN=, OU=, O=, C=";

		final DistinguishedNameChooser nameChooser = new DistinguishedNameChooser(dn, true, defaultDN);

		frame.getContentPane().setLayout(new BorderLayout());
		frame.getContentPane().add(nameChooser, BorderLayout.CENTER);

		JButton resetButton = new JButton("Reset to Default DN");
		resetButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				nameChooser.reset();
			}
		});
		frame.getContentPane().add(resetButton, BorderLayout.NORTH);

		JButton showNameButton = new JButton("Print Name");
		showNameButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				System.out.println(nameChooser.getDN().toString());
			}
		});
		frame.getContentPane().add(showNameButton, BorderLayout.SOUTH);

		frame.setVisible(true);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
}
