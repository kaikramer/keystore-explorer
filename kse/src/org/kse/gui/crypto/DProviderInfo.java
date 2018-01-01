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
package org.kse.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreeSelectionModel;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Displays information on the currently loaded security providers.
 *
 */
public class DProviderInfo extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private JPanel jpButtons;
	private JButton jbCopy;
	private JButton jbOK;
	private JPanel jpProviders;
	private JTree jtrProviders;
	private JScrollPane jspProviders;

	/**
	 * Creates new DProviderInfo dialog where the parent is a frame.
	 *  @param parent
	 *            Parent frame
	 *
	 */
	public DProviderInfo(JFrame parent) {
		super(parent, ModalityType.DOCUMENT_MODAL);
		initComponents();
	}

	/**
	 * Creates new DProviderInfo dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param modality
	 *            Dialog modality
	 */
	public DProviderInfo(JDialog parent, Dialog.ModalityType modality) {
		super(parent, modality);
		initComponents();
	}

	private void initComponents() {
		jbCopy = new JButton(res.getString("DProviderInfo.jbCopy.text"));
		PlatformUtil.setMnemonic(jbCopy, res.getString("DProviderInfo.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(res.getString("DProviderInfo.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DProviderInfo.this);
					copyPressed();
				} finally {
					CursorUtil.setCursorFree(DProviderInfo.this);
				}
			}
		});

		jbOK = new JButton(res.getString("DProviderInfo.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null, jbCopy, true);

		jpProviders = new JPanel(new BorderLayout());
		jpProviders.setBorder(new EmptyBorder(5, 5, 5, 5));

		jtrProviders = new JTree(createProviderNodes());
		jtrProviders.setRowHeight(Math.max(18, jtrProviders.getRowHeight()));
		jtrProviders.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		ToolTipManager.sharedInstance().registerComponent(jtrProviders);
		jtrProviders.setCellRenderer(new ProviderTreeCellRend());

		jspProviders = PlatformUtil.createScrollPane(jtrProviders, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspProviders.setPreferredSize(new Dimension(500, 250));
		jpProviders.add(jspProviders, BorderLayout.CENTER);

		getContentPane().add(jpProviders, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(res.getString("DProviderInfo.Title"));
		setResizable(true);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				jbOK.requestFocus();
			}
		});
	}

	private DefaultMutableTreeNode createProviderNodes() {
		DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(res.getString("DProviderInfo.TopNode.text"));

		Provider[] providers = Security.getProviders();

		for (int i = 0; i < providers.length; i++) {
			Provider provider = providers[i];

			String nameVersion = MessageFormat.format(res.getString("DProviderInfo.ProviderNode.text"),
					provider.getName(), provider.getVersion());
			DefaultMutableTreeNode providerNode = new DefaultMutableTreeNode(nameVersion);
			topNode.add(providerNode);

			providerNode.add(new DefaultMutableTreeNode(provider.getInfo()));
			providerNode.add(new DefaultMutableTreeNode(provider.getClass().getName()));

			DefaultMutableTreeNode servicesNode = new DefaultMutableTreeNode(
					res.getString("DProviderInfo.ServicesNode.text"));
			providerNode.add(servicesNode);

			addServiceNode("AlgorithmParameterGenerator",
					res.getString("DProviderInfo.Service.AlgorithmParameterGenerator.text"), provider, servicesNode);
			addServiceNode("AlgorithmParameters", res.getString("DProviderInfo.Service.AlgorithmParameters.text"),
					provider, servicesNode);
			addServiceNode("CertificateFactory", res.getString("DProviderInfo.Service.CertificateFactory.text"),
					provider, servicesNode);
			addServiceNode("CertPathBuilder", res.getString("DProviderInfo.Service.CertPathBuilder.text"), provider,
					servicesNode);
			addServiceNode("CertPathValidator", res.getString("DProviderInfo.Service.CertPathValidator.text"),
					provider, servicesNode);
			addServiceNode("CertStore", res.getString("DProviderInfo.Service.CertStore.text"), provider, servicesNode);
			addServiceNode("Cipher", res.getString("DProviderInfo.Service.Cipher.text"), provider, servicesNode);
			addServiceNode("Configuration", res.getString("DProviderInfo.Service.Configuration.text"), provider,
					servicesNode);
			addServiceNode("GssApiMechanism", res.getString("DProviderInfo.Service.GssApiMechanism.text"), provider,
					servicesNode);
			addServiceNode("KeyAgreement", res.getString("DProviderInfo.Service.KeyAgreement.text"), provider,
					servicesNode);
			addServiceNode("KeyFactory", res.getString("DProviderInfo.Service.KeyFactory.text"), provider, servicesNode);
			addServiceNode("KeyGenerator", res.getString("DProviderInfo.Service.KeyGenerator.text"), provider,
					servicesNode);
			addServiceNode("KeyInfoFactory", res.getString("DProviderInfo.Service.KeyInfoFactory.text"), provider,
					servicesNode);
			addServiceNode("KeyManagerFactory", res.getString("DProviderInfo.Service.KeyManagerFactory.text"),
					provider, servicesNode);
			addServiceNode("KeyPairGenerator", res.getString("DProviderInfo.Service.KeyPairGenerator.text"), provider,
					servicesNode);
			addServiceNode("KeyStore", res.getString("DProviderInfo.Service.KeyStore.text"), provider, servicesNode);
			addServiceNode("Mac", res.getString("DProviderInfo.Service.Mac.text"), provider, servicesNode);
			addServiceNode("MessageDigest", res.getString("DProviderInfo.Service.MessageDigest.text"), provider,
					servicesNode);
			addServiceNode("Policy", res.getString("DProviderInfo.Service.Policy.text"), provider, servicesNode);
			addServiceNode("SecretKeyFactory", res.getString("DProviderInfo.Service.SecretKeyFactory.text"), provider,
					servicesNode);
			addServiceNode("SecureRandom", res.getString("DProviderInfo.Service.SecureRandom.text"), provider,
					servicesNode);
			addServiceNode("Signature", res.getString("DProviderInfo.Service.Signature.text"), provider, servicesNode);
			addServiceNode("SaslClientFactory", res.getString("DProviderInfo.Service.SaslClientFactory.text"),
					provider, servicesNode);
			addServiceNode("SaslServerFactory", res.getString("DProviderInfo.Service.SaslServerFactory.text"),
					provider, servicesNode);
			addServiceNode("SSLContext", res.getString("DProviderInfo.Service.SSLContext.text"), provider, servicesNode);
			addServiceNode("TerminalFactory", res.getString("DProviderInfo.Service.TerminalFactory.text"), provider,
					servicesNode);
			addServiceNode("TransformService", res.getString("DProviderInfo.Service.TransformService.text"), provider,
					servicesNode);
			addServiceNode("TrustManagerFactory", res.getString("DProviderInfo.Service.TrustManagerFactory.text"),
					provider, servicesNode);
			addServiceNode("XMLSignatureFactory", res.getString("DProviderInfo.Service.XMLSignatureFactory.text"),
					provider, servicesNode);
		}

		return topNode;
	}

	private void addServiceNode(String serviceType, String friendlyName, Provider provider,
			DefaultMutableTreeNode servicesNode) {
		DefaultMutableTreeNode serviceNode = new DefaultMutableTreeNode(friendlyName);

		String[] algorithms = getServiceAlgorithms(serviceType, provider);

		for (int algCnt = 0; algCnt < algorithms.length; algCnt++) {
			String algorithm = algorithms[algCnt];

			DefaultMutableTreeNode algorithmNode = new DefaultMutableTreeNode(algorithm);
			serviceNode.add(algorithmNode);

			String algClass = getAlgorithmClass(algorithm, serviceType, provider);
			DefaultMutableTreeNode classNode = new DefaultMutableTreeNode(algClass);
			algorithmNode.add(classNode);

			String[] attributes = getAlgorithmAttributes(algorithm, serviceType, provider);

			if (attributes.length > 0) {
				DefaultMutableTreeNode attributesNode = new DefaultMutableTreeNode(
						res.getString("DProviderInfo.AttributesNode.text"));
				algorithmNode.add(attributesNode);

				for (int attrCnt = 0; attrCnt < attributes.length; attrCnt++) {
					DefaultMutableTreeNode attributeNode = new DefaultMutableTreeNode(attributes[attrCnt]);
					attributesNode.add(attributeNode);
				}
			}

			String[] aliases = getAlgorithmAliases(algorithm, serviceType, provider);

			if (aliases.length > 0) {
				DefaultMutableTreeNode aliasesNode = new DefaultMutableTreeNode(
						res.getString("DProviderInfo.AliasesNode.text"));
				algorithmNode.add(aliasesNode);

				for (int aliasCnt = 0; aliasCnt < aliases.length; aliasCnt++) {
					DefaultMutableTreeNode aliasNode = new DefaultMutableTreeNode(aliases[aliasCnt]);
					aliasesNode.add(aliasNode);
				}
			}
		}

		if (serviceNode.getChildCount() > 0) {
			servicesNode.add(serviceNode);
		}
	}

	private String[] getServiceAlgorithms(String serviceType, Provider provider) {
		/*
		 * Match provider property names that start "<service type>." and do not
		 * contain a space. What follows the '.' is the algorithm name
		 */
		String match = serviceType + ".";

		ArrayList<String> algorithmList = new ArrayList<String>();

		for (Enumeration<?> names = provider.propertyNames(); names.hasMoreElements();) {
			String key = (String) names.nextElement();

			if (key.startsWith(match) && key.indexOf(' ') == -1) {
				String algorithm = key.substring(key.indexOf(".") + 1);
				algorithmList.add(algorithm);
			}
		}

		String[] algorithms = algorithmList.toArray(new String[algorithmList.size()]);
		Arrays.sort(algorithms);

		return algorithms;
	}

	private String getAlgorithmClass(String algorithm, String serviceType, Provider provider) {
		/*
		 * Looking for the property name that matches
		 * "<service type>.<algorithm>". The value of the property is the class
		 * name
		 */
		String match = serviceType + "." + algorithm;

		for (Enumeration<?> names = provider.propertyNames(); names.hasMoreElements();) {
			String key = (String) names.nextElement();

			if (key.equals(match)) {
				return provider.getProperty(key);
			}
		}

		return null;
	}

	private String[] getAlgorithmAttributes(String algorithm, String serviceType, Provider provider) {
		/*
		 * Looking for property names matching "<service type>.<algorithm> ".
		 * The attribute name if the text following the ' ' while the attribute
		 * value is the value of the property. Return in alpha order by name.
		 * Returned value is 'name=value'
		 */
		String matchAttr = serviceType + "." + algorithm + " ";

		TreeMap<String, String> attributeMap = new TreeMap<String, String>();

		for (Enumeration<?> names = provider.propertyNames(); names.hasMoreElements();) {
			String key = (String) names.nextElement();

			if (key.startsWith(matchAttr)) {
				String attrName = key.substring(key.indexOf(" ") + 1);
				String attributeDisplay = MessageFormat.format(res.getString("DProviderInfo.AttributeNode.text"),
						attrName, provider.getProperty(key));
				attributeMap.put(attrName, attributeDisplay);
			}
		}

		ArrayList<String> attributes = new ArrayList<String>();

		for (String key : attributeMap.keySet()) {
			attributes.add(attributeMap.get(key));
		}

		return attributes.toArray(new String[attributes.size()]);
	}

	private String[] getAlgorithmAliases(String algorithm, String serviceType, Provider provider) {
		/*
		 * Looking to match property names with key "Alg.Alias.<service type>."
		 * and value of algorithm. The alias is the text following the '.' in
		 * the property name. Return in alpha order
		 */
		String matchAlias = "Alg.Alias." + serviceType + ".";

		ArrayList<String> aliasList = new ArrayList<String>();

		for (Enumeration<?> names = provider.propertyNames(); names.hasMoreElements();) {
			String key = (String) names.nextElement();

			if (provider.getProperty(key).equals(algorithm)) {
				if (key.startsWith(matchAlias)) {
					String alias = key.substring(matchAlias.length());
					aliasList.add(alias);
				}
			}
		}

		String[] aliases = aliasList.toArray(new String[aliasList.size()]);
		Arrays.sort(aliases);

		return aliases;
	}

	private void copyPressed() {
		String info = getNodeContents((TreeNode) jtrProviders.getModel().getRoot(), 0);

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(info);
		clipboard.setContents(copy, copy);
	}

	private String getNodeContents(TreeNode node, int level) {
		StringBuffer strBuff = new StringBuffer();

		for (int i = 0; i < level; i++) {
			strBuff.append('\t');
		}

		strBuff.append(node.toString());
		strBuff.append('\n');

		for (int i = 0; i < node.getChildCount(); i++) {
			strBuff.append(getNodeContents(node.getChildAt(i), level + 1));
		}

		return strBuff.toString();
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
