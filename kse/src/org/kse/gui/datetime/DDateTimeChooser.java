/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui.datetime;

import static java.awt.Color.BLUE;
import static java.awt.Color.WHITE;
import static java.util.Calendar.DATE;
import static java.util.Calendar.HOUR_OF_DAY;
import static java.util.Calendar.MINUTE;
import static java.util.Calendar.MONTH;
import static java.util.Calendar.SECOND;
import static java.util.Calendar.YEAR;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.LayoutManager;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.ResourceBundle;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.MatteBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog to choose a date/time value.
 *
 */
public class DDateTimeChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/datetime/resources");

	private static final String[] MONTH_NAMES = new String[] { res.getString("DDateTimeChooser.Month.January"),
			res.getString("DDateTimeChooser.Month.February"), res.getString("DDateTimeChooser.Month.March"),
			res.getString("DDateTimeChooser.Month.April"), res.getString("DDateTimeChooser.Month.May"),
			res.getString("DDateTimeChooser.Month.June"), res.getString("DDateTimeChooser.Month.July"),
			res.getString("DDateTimeChooser.Month.August"), res.getString("DDateTimeChooser.Month.September"),
			res.getString("DDateTimeChooser.Month.October"), res.getString("DDateTimeChooser.Month.November"),
			res.getString("DDateTimeChooser.Month.December") };

	private static final String[] DAY_NAMES = new String[] { res.getString("DDateTimeChooser.Day.Mon"),
			res.getString("DDateTimeChooser.Day.Tue"), res.getString("DDateTimeChooser.Day.Wed"),
			res.getString("DDateTimeChooser.Day.Thu"), res.getString("DDateTimeChooser.Day.Fri"),
			res.getString("DDateTimeChooser.Day.Sat"), res.getString("DDateTimeChooser.Day.Sun") };

	private static final Color LIGHT_BLUE = new Color(51, 119, 204);
	private static final Color WEEK_DAY_BACKGROUND = LIGHT_BLUE;
	private static final Color WEEK_DAY_FOREGROUND = WHITE;
	private static final Color DAY_FOREGROUND = LIGHT_BLUE;
	private static final Color DAY_BACKGROUND = WHITE;
	private static final Color SELECTED_DAY_FOREGROUND = WHITE;
	private static final Color SELECTED_DAY_BACKGROUND = BLUE;
	private static final String EMPTY_DAY = "";
	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpMonthYear;
	private JComboBox<?> jcbMonth;
	private JSpinner jsYear;
	private JPanel jpDaysOfMonth;
	private JLabel[][] jlDaysOfMonth;
	private JLabel jlSelectedDayOfMonth;
	private JPanel jpTime;
	private JSpinner jsHour;
	private JLabel jlTimeSeparator1;
	private JSpinner jsMinute;
	private JLabel jlTimeSeparator2;
	private JSpinner jsSecond;
	private JPanel jpShortcuts;
	private JButton jbStartOfYear;
	private JButton jbNow;
	private JButton jbEndOfYear;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private int indexOfFirstDayOfMonth;
	private int lastDayOfSelectedMonth;
	private Date date;

	/**
	 * Constructs a new DDateTimeChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param date
	 *            Date to display initially
	 */
	public DDateTimeChooser(JFrame parent, String title, Date date) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(date);
	}

	/**
	 * Constructs a new DDateTimeChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param date
	 *            Date to display initially
	 */
	public DDateTimeChooser(JDialog parent, String title, Date date) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents(date);
	}

	private void initComponents(Date date) {
		if (date == null) {
			date = new Date();
		}

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);

		jcbMonth = new JComboBox<>(MONTH_NAMES);
		jcbMonth.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent evt) {
				update();
			}
		});

		jsYear = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.YEAR), 1900, 2100, 1));
		jsYear.setEditor(new JSpinner.NumberEditor(jsYear, "0000"));
		jsYear.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent evt) {
				update();
			}
		});

		jlDaysOfMonth = new JLabel[7][7];
		for (int i = 0; i < 7; i++) {
			jlDaysOfMonth[0][i] = new JLabel(DAY_NAMES[i], SwingConstants.CENTER);
			jlDaysOfMonth[0][i].setOpaque(true);
			jlDaysOfMonth[0][i].setForeground(WEEK_DAY_FOREGROUND);
			jlDaysOfMonth[0][i].setBackground(WEEK_DAY_BACKGROUND);
		}

		for (int i = 1; i < 7; i++) {
			for (int j = 0; j < 7; j++) {
				jlDaysOfMonth[i][j] = new JLabel(EMPTY_DAY, SwingConstants.CENTER);
				jlDaysOfMonth[i][j].setOpaque(true);
				jlDaysOfMonth[i][j].setForeground(DAY_FOREGROUND);
				jlDaysOfMonth[i][j].setBackground(DAY_BACKGROUND);
				jlDaysOfMonth[i][j].addMouseListener(new MouseAdapter() {
					@Override
					public void mouseClicked(MouseEvent evt) {
						selectDay((JLabel) evt.getSource());
					}
				});
				jlDaysOfMonth[i][j].setBorder(new MatteBorder(2, 0, 0, 0, Color.WHITE));
			}
		}

		jpMonthYear = new JPanel();
		jpMonthYear.add(jcbMonth);
		jpMonthYear.add(jsYear);

		jpDaysOfMonth = new JPanel(new DayOfMonthGridLayout(7, 7));
		jpDaysOfMonth.setBackground(DAY_BACKGROUND);
		jpDaysOfMonth.setBorder(new CompoundBorder(BorderFactory.createLoweredBevelBorder(),
				new EmptyBorder(2, 2, 2, 2)));
		jpDaysOfMonth.setFocusable(true);

		jpDaysOfMonth.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent evt) {
				setSelectedDay(jlSelectedDayOfMonth);
			}

			@Override
			public void focusLost(FocusEvent evt) {
				setSelectedDay(jlSelectedDayOfMonth);
			}
		});

		jpDaysOfMonth.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent evt) {
				calendarKeyboardNavigation(evt);
			}
		});

		for (int i = 0; i < 7; i++) {
			for (int j = 0; j < 7; j++) {
				jpDaysOfMonth.add(jlDaysOfMonth[i][j]);
			}
		}

		jsHour = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.HOUR_OF_DAY), 0, 23, 1));
		jsHour.setEditor(new JSpinner.NumberEditor(jsHour, "00"));
		jlTimeSeparator1 = new JLabel(":");
		jsMinute = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.MINUTE), 0, 59, 1));
		jsMinute.setEditor(new JSpinner.NumberEditor(jsMinute, "00"));
		jlTimeSeparator2 = new JLabel(":");
		jsSecond = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.SECOND), 0, 59, 1));
		jsSecond.setEditor(new JSpinner.NumberEditor(jsSecond, "00"));

		jpTime = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpTime.add(jsHour);
		jpTime.add(jlTimeSeparator1);
		jpTime.add(jsMinute);
		jpTime.add(jlTimeSeparator2);
		jpTime.add(jsSecond);

		jbNow = new JButton(res.getString("DDateTimeChooser.jbNow.text"));
		jbNow.setMargin(new Insets(2, 2, 2, 2));
		jbNow.addActionListener(e -> populate(new Date()));

		jbStartOfYear = new JButton(res.getString("DDateTimeChooser.jbStartOfYear.text"));
		jbStartOfYear.setMargin(new Insets(2, 2, 2, 2));
		jbStartOfYear.addActionListener(e -> {
			Calendar cal = Calendar.getInstance();
			cal.set(Calendar.YEAR, (int) jsYear.getValue());
			cal.set(Calendar.MONTH, Calendar.JANUARY);
			cal.set(Calendar.DATE, 1);
			cal.set(Calendar.HOUR_OF_DAY, 0);
			cal.set(Calendar.MINUTE, 0);
			cal.set(Calendar.SECOND, 0);
			cal.set(Calendar.MILLISECOND, 0);
			populate(cal.getTime());
		});

		jbEndOfYear = new JButton(res.getString("DDateTimeChooser.jbEndOfYear.text"));
		jbEndOfYear.setMargin(new Insets(2, 2, 2, 2));
		jbEndOfYear.addActionListener(e -> {
			Calendar cal = Calendar.getInstance();
			cal.set(Calendar.YEAR, (int) jsYear.getValue());
			cal.set(Calendar.MONTH, Calendar.DECEMBER);
			cal.set(Calendar.DATE, 31);
			cal.set(Calendar.HOUR_OF_DAY, 23);
			cal.set(Calendar.MINUTE, 59);
			cal.set(Calendar.SECOND, 59);
			cal.set(Calendar.MILLISECOND, 0);
			populate(cal.getTime());
		});

		jpShortcuts = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpShortcuts.add(jbStartOfYear);
		jpShortcuts.add(jbNow);
		jpShortcuts.add(jbEndOfYear);

		JPanel jpDateTime = new JPanel();
		jpDateTime.setLayout(new BoxLayout(jpDateTime, BoxLayout.Y_AXIS));
		jpDateTime.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
				new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));
		jpDateTime.add(jpMonthYear);
		jpDateTime.add(jpDaysOfMonth);
		jpDateTime.add(jpTime);
		jpDateTime.add(jpShortcuts);

		jbOK = new JButton(res.getString("DDateTimeChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DDateTimeChooser.jbCancel.text"));
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

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(BorderLayout.CENTER, jpDateTime);
		getContentPane().add(BorderLayout.SOUTH, jpButtons);

		populate(date);

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * Get selected date.
	 *
	 * @return Date, or null if none
	 */
	public Date getDate() {
		return date;
	}

	private void populate(Date date) {
		Calendar calendar = new GregorianCalendar();
		calendar.setTime(date);

		jsYear.setValue(calendar.get(YEAR));
		jcbMonth.setSelectedIndex(calendar.get(MONTH));
		setSelectedDay(calendar.get(DATE));
		jsHour.setValue(calendar.get(HOUR_OF_DAY));
		jsMinute.setValue(calendar.get(MINUTE));
		jsSecond.setValue(calendar.get(SECOND));
	}

	private int getSelectedDayOfMonth() {
		if (jlSelectedDayOfMonth == null) {
			return -1;
		}

		try {
			return Integer.parseInt(jlSelectedDayOfMonth.getText());
		} catch (NumberFormatException ex) {
		}

		return -1;

	}

	private void setSelectedDay(JLabel newDay) {
		if (jlSelectedDayOfMonth != null) {
			jlSelectedDayOfMonth.setForeground(DAY_FOREGROUND);
			jlSelectedDayOfMonth.setBackground(DAY_BACKGROUND);
		}

		jlSelectedDayOfMonth = newDay;
		jlSelectedDayOfMonth.setForeground(SELECTED_DAY_FOREGROUND);
		jlSelectedDayOfMonth.setBackground(SELECTED_DAY_BACKGROUND);
	}

	private void setSelectedDay(int newDay) {
		setSelectedDay(jlDaysOfMonth[((newDay + indexOfFirstDayOfMonth - 1) / 7) + 1][(newDay + indexOfFirstDayOfMonth - 1) % 7]);
	}

	private void update() {
		int day = getSelectedDayOfMonth();

		for (int i = 0; i < 7; i++) {
			jlDaysOfMonth[1][i].setText(EMPTY_DAY);
			jlDaysOfMonth[5][i].setText(EMPTY_DAY);
			jlDaysOfMonth[6][i].setText(EMPTY_DAY);
		}

		Calendar calendar = new GregorianCalendar();
		calendar.set(Calendar.DATE, 1);
		calendar.set(Calendar.MONTH, jcbMonth.getSelectedIndex());
		calendar.set(Calendar.YEAR, (int) jsYear.getValue());

		calculateIndexOfFirstDayOfMonth(calendar);

		lastDayOfSelectedMonth = calendar.getActualMaximum(Calendar.DATE);

		for (int i = 0; i < lastDayOfSelectedMonth; i++) {
			jlDaysOfMonth[((i + indexOfFirstDayOfMonth) / 7) + 1][(i + indexOfFirstDayOfMonth) % 7].setText(String
					.valueOf(i + 1));
		}

		if (day != -1) {
			if (day > lastDayOfSelectedMonth) {
				day = lastDayOfSelectedMonth;
			}
			setSelectedDay(day);
		}
	}

	private void calculateIndexOfFirstDayOfMonth(Calendar calendar) {
		int dayOfWeek = calendar.get(Calendar.DAY_OF_WEEK);
		indexOfFirstDayOfMonth = dayOfWeek - 2;

		if (indexOfFirstDayOfMonth < 0) {
			indexOfFirstDayOfMonth = 6;
		}
	}

	private void selectDay(JLabel jlDay) {
		if (!jlDay.getText().equals(EMPTY_DAY)) {
			setSelectedDay(jlDay);
		}

		jpDaysOfMonth.requestFocus();
	}

	private void calendarKeyboardNavigation(KeyEvent evt) {
		int day = getSelectedDayOfMonth();

		switch (evt.getKeyCode()) {
		case KeyEvent.VK_LEFT: {
			if (day > 1) {
				setSelectedDay(day - 1);
			}
			break;
		}
		case KeyEvent.VK_RIGHT: {
			if (day < lastDayOfSelectedMonth) {
				setSelectedDay(day + 1);
			}
			break;
		}
		case KeyEvent.VK_UP: {
			if (day > 7) {
				setSelectedDay(day - 7);
			}
			break;
		}
		case KeyEvent.VK_DOWN: {
			if (day <= (lastDayOfSelectedMonth - 7)) {
				setSelectedDay(day + 7);
			}
			break;
		}
		}
	}

	private void okPressed() {
		Calendar calendar = new GregorianCalendar();

		calendar.set(Calendar.DATE, getSelectedDayOfMonth());
		calendar.set(Calendar.MONTH, jcbMonth.getSelectedIndex());
		calendar.set(Calendar.YEAR, (int) jsYear.getValue());
		calendar.set(Calendar.HOUR_OF_DAY, (int) jsHour.getValue());
		calendar.set(Calendar.MINUTE, (int) jsMinute.getValue());
		calendar.set(Calendar.SECOND, (int) jsSecond.getValue());
		calendar.set(Calendar.MILLISECOND, 0);

		date = calendar.getTime();

		closeDialog();
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	// GridLayout that distributes left over space between components
	private class DayOfMonthGridLayout implements LayoutManager {
		private int rows;
		private int cols;

		public DayOfMonthGridLayout(int rows, int cols) {
			this.rows = rows;
			this.cols = cols;
		}

		@Override
		public void addLayoutComponent(String name, Component child) {
		}

		@Override
		public void removeLayoutComponent(Component child) {
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			synchronized (parent.getTreeLock()) {
				Insets insets = parent.getInsets();

				Component[] children = parent.getComponents();

				int length = children.length;
				int prefWidth = 0;
				int prefHeight = 0;

				for (int i = 0; i < length; i++) {
					Dimension prefSize = children[i].getPreferredSize();

					if (prefSize.width > prefWidth) {
						prefWidth = prefSize.width;
					}

					if (prefSize.height > prefHeight) {
						prefHeight = prefSize.height;
					}
				}

				return new Dimension((cols * prefWidth) + insets.left + insets.right, (rows * prefHeight) + insets.top
						+ insets.bottom);
			}
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			synchronized (parent.getTreeLock()) {
				Insets insets = parent.getInsets();

				Component[] children = parent.getComponents();

				int length = children.length;
				int minWidth = 0;
				int minHeight = 0;

				for (int i = 0; i < length; i++) {
					Dimension minSize = children[i].getMinimumSize();

					if (minSize.width > minWidth) {
						minWidth = minSize.width;
					}

					if (minSize.height > minHeight) {
						minHeight = minSize.height;
					}
				}

				return new Dimension((cols * minWidth) + insets.left + insets.right, (rows * minHeight) + insets.top
						+ insets.bottom);
			}
		}

		@Override
		public void layoutContainer(Container parent) {
			synchronized (parent.getTreeLock()) {
				Insets insets = parent.getInsets();

				int width = (parent.getWidth() - (insets.left + insets.right)) / cols + 1;
				int widthRemainder = (parent.getWidth() - (insets.left + insets.right)) % cols;
				int height = (parent.getHeight() - (insets.top + insets.bottom)) / rows + 1;
				int heightRemainder = (parent.getHeight() - (insets.top + insets.bottom)) % rows;

				Component[] children = parent.getComponents();

				int i = 0;
				int y = 0;

				for (int row = 0; row < heightRemainder; row++) {
					int x = 0;

					for (int col = 0; col < widthRemainder; col++) {
						children[i++].setBounds((x + insets.left), (y + insets.top), width, height);
						x += width;
					}

					width--;

					for (int col = widthRemainder; col < cols; col++) {
						children[i++].setBounds((x + insets.left), (y + insets.top), width, height);
						x += width;
					}

					y += height;
					width++;
				}

				height--;

				for (int row = heightRemainder; row < rows; row++) {
					int x = 0;

					for (int col = 0; col < widthRemainder; col++) {
						children[i++].setBounds((x + insets.left), (y + insets.top), width, height);
						x += width;
					}

					width--;

					for (int col = widthRemainder; col < cols; col++) {
						children[i++].setBounds((x + insets.left), (y + insets.top), width, height);
						x += width;
					}

					y += height;
					width++;
				}
			}
		}
	}
}
