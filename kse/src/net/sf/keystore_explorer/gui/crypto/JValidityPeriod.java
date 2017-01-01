/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
package net.sf.keystore_explorer.gui.crypto;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Calendar;
import java.util.ResourceBundle;
import java.util.TimeZone;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;

/**
 * Component that allows a user to choose a validity period. User can choose an
 * integral value and a period type (year, month, week, day). Choice is
 * converted into msecs. Useful for the likes of X.509 certificate creation.
 *
 */
public class JValidityPeriod extends JPanel {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/crypto/resources");

	private JSpinner jsValue;
	private JComboBox jcbType;

	/** Years period type */
	public static final int YEARS = 0;

	/** Months period type */
	public static final int MONTHS = 1;

	/** Weeks period type */
	public static final int WEEKS = 2;

	/** Days period type */
	public static final int DAYS = 3;

	/**
	 * Construct a JValidityPeriod with the period type defaulting to that
	 * supplied.
	 *
	 * @param periodType
	 *            Period type
	 */
	public JValidityPeriod(int periodType) {
		initComponents(periodType);
	}

	private void initComponents(int periodType) {
		jsValue = new JSpinner();
		GridBagConstraints gbc_jsValue = new GridBagConstraints();
		gbc_jsValue.gridheight = 1;
		gbc_jsValue.gridwidth = 1;
		gbc_jsValue.gridx = 0;
		gbc_jsValue.gridy = 0;
		gbc_jsValue.insets = new Insets(0, 0, 0, 5);

		jcbType = new JComboBox(new String[] { res.getString("JValidityPeriod.jcbType.years.text"),
				res.getString("JValidityPeriod.jcbType.months.text"),
				res.getString("JValidityPeriod.jcbType.weeks.text"),
				res.getString("JValidityPeriod.jcbType.days.text"), });

		GridBagConstraints gbc_jcbType = new GridBagConstraints();
		gbc_jcbType.gridheight = 1;
		gbc_jcbType.gridwidth = 1;
		gbc_jcbType.gridx = 1;
		gbc_jcbType.gridy = 0;
		gbc_jcbType.insets = new Insets(0, 0, 0, 0);

		switch (periodType) {
		case YEARS: {
			jcbType.setSelectedIndex(YEARS);
			typeChanged(YEARS);
			break;
		}
		case MONTHS: {
			jcbType.setSelectedIndex(MONTHS);
			typeChanged(MONTHS);
			break;
		}
		case WEEKS: {
			jcbType.setSelectedIndex(WEEKS);
			typeChanged(WEEKS);
			break;
		}
		default: {
			jcbType.setSelectedIndex(DAYS);
			typeChanged(DAYS);
			break;
		}
		}

		jcbType.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				typeChanged(((JComboBox) evt.getSource()).getSelectedIndex());
			}
		});

		setLayout(new GridBagLayout());
		add(jsValue, gbc_jsValue);
		add(jcbType, gbc_jcbType);
	}

	/**
	 * Set component's tooltip text.
	 *
	 * @param toolTipText
	 *            Tooltip text
	 */
	@Override
	public void setToolTipText(String toolTipText) {
		super.setToolTipText(toolTipText);
		jsValue.setToolTipText(toolTipText);
		jcbType.setToolTipText(toolTipText);
	}

	@SuppressWarnings("unchecked")
	private void typeChanged(int periodType) {
		Number value = ((SpinnerNumberModel) jsValue.getModel()).getNumber();

		SpinnerNumberModel model;

		switch (periodType) {
		case YEARS: {
			model = new SpinnerNumberModel(1, 1, 999, 1);
			break;
		}
		case MONTHS: {
			model = new SpinnerNumberModel(1, 1, 12, 1);
			break;
		}
		case WEEKS: {
			model = new SpinnerNumberModel(1, 1, 52, 1);
			break;
		}
		default: {
			model = new SpinnerNumberModel(1, 1, 365, 1);
			break;
		}
		}

		if ((model.getMaximum().compareTo(value) >= 0) && (model.getMinimum().compareTo(value) <= 0)) {
			model.setValue(value);
		}

		jsValue.setModel(model);
	}

	/**
	 * Get chosen validity period in msecs.
	 *
	 * @return Validity period
	 */
	public long getValidityPeriodMs() {
		/*
		 * Use a non-shifting timezone to calculate validity date otherwise, if
		 * we cross a DST-shift, we'll be an hour out
		 */
		Calendar now = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		Calendar validityDate = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

		int periodType = jcbType.getSelectedIndex();
		int periodValue = ((Number) jsValue.getValue()).intValue();

		switch (periodType) {
		case YEARS: {
			validityDate.add(Calendar.YEAR, periodValue);
			break;
		}
		case MONTHS: {
			validityDate.add(Calendar.MONTH, periodValue);
			break;
		}
		case WEEKS: {
			validityDate.add(Calendar.WEEK_OF_MONTH, periodValue);
			break;
		}
		default: {
			validityDate.add(Calendar.DAY_OF_WEEK, periodValue);
			break;
		}
		}

		return validityDate.getTimeInMillis() - now.getTimeInMillis();
	}
}
