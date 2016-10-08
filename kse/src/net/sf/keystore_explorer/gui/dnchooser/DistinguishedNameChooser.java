package net.sf.keystore_explorer.gui.dnchooser;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

public class DistinguishedNameChooser extends JPanel {

	private boolean editable;
	private X500Name currentName;
	private String defaultName;
	private RdnPanelList listPanel;

	public DistinguishedNameChooser(X500Name dn, boolean editable, String defaultDN) {
		this.editable = editable;
		if (dn == null) {
			currentName = new X500Name(defaultDN);
		} else {
			this.currentName = dn;
		}
		this.defaultName = defaultDN;
		init();
	}

	private void init() {
		listPanel = new RdnPanelList(currentName, editable);

		JScrollPane jScrollPane = new JScrollPane(listPanel);
		jScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		jScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

		setLayout(new BorderLayout());
		add(jScrollPane, BorderLayout.CENTER);
	}

	public X500Name getDN() throws InvalidNameException {
		boolean noEmptyRdns = true;
		List<RDN> rdns = listPanel.getRdns(noEmptyRdns);
		return new X500Name(rdns.toArray(new RDN[rdns.size()]));
	}

	public X500Name getDNWithEmptyRdns() throws InvalidNameException {
		List<RDN> rdns = listPanel.getRdns(false);
		return new X500Name(rdns.toArray(new RDN[rdns.size()]));
	}

	public void reset() {
		currentName = new X500Name(defaultName);
		removeAll();
		init();
		revalidate();
		repaint(50L);
	}

	public static void main(String[] args) {

		JFrame frame = new JFrame();
		frame.setSize(800, 400);

		X500Name dn = new X500Name("CN=test, OU=Development, OU=Software, O=ACME Ltd., C=UK, E=test@example.com");
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
				try {
					System.out.println(nameChooser.getDN().toString());
				} catch (InvalidNameException e) {
					e.printStackTrace();
				}
			}
		});
		frame.getContentPane().add(showNameButton, BorderLayout.SOUTH);

		frame.setVisible(true);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
}
