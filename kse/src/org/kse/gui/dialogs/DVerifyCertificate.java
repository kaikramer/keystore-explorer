package org.kse.gui.dialogs;

import java.awt.Dialog;
import java.awt.GridBagConstraints;
import java.awt.Insets;

import javax.swing.JFrame;

import org.kse.gui.JEscDialog;

public class DVerifyCertificate extends JEscDialog{

	private static final long serialVersionUID = 1L;
	private String certificateAlias;

	public DVerifyCertificate(JFrame parent, String certificateAlias) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.certificateAlias = certificateAlias;
		initComponents();
	}

	private void initComponents() 
	{
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 3;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcEdCtrl = new GridBagConstraints();
		gbcEdCtrl.gridx = 3;
		gbcEdCtrl.gridwidth = 3;
		gbcEdCtrl.gridheight = 1;
		gbcEdCtrl.insets = new Insets(5, 5, 5, 5);
		gbcEdCtrl.anchor = GridBagConstraints.WEST;		

		setResizable(false);

		pack();		
	}
	
}
