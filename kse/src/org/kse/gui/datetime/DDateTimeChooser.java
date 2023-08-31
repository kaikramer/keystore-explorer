/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
import static java.awt.Color.DARK_GRAY;
import static java.awt.Color.LIGHT_GRAY;
import static java.awt.Color.WHITE;
import static java.util.Calendar.DATE;
import static java.util.Calendar.HOUR_OF_DAY;
import static java.util.Calendar.MINUTE;
import static java.util.Calendar.MONTH;
import static java.util.Calendar.SECOND;
import static java.util.Calendar.YEAR;

import java.awt.Color;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Insets;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.ResourceBundle;

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

import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to choose a date/time value.
 */
public class DDateTimeChooser extends JEscDialog {
    private static final long serialVersionUID = 1L;

    public static int MAX_YEAR = 2200;
    public static int MIN_YEAR = 1900;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/datetime/resources");

    private static final String[] MONTH_NAMES = new String[] { res.getString("DDateTimeChooser.Month.January"),
                                                               res.getString("DDateTimeChooser.Month.February"),
                                                               res.getString("DDateTimeChooser.Month.March"),
                                                               res.getString("DDateTimeChooser.Month.April"),
                                                               res.getString("DDateTimeChooser.Month.May"),
                                                               res.getString("DDateTimeChooser.Month.June"),
                                                               res.getString("DDateTimeChooser.Month.July"),
                                                               res.getString("DDateTimeChooser.Month.August"),
                                                               res.getString("DDateTimeChooser.Month.September"),
                                                               res.getString("DDateTimeChooser.Month.October"),
                                                               res.getString("DDateTimeChooser.Month.November"),
                                                               res.getString("DDateTimeChooser.Month.December") };

    private static final String[] DAY_NAMES = new String[] { res.getString("DDateTimeChooser.Day.Mon"),
                                                             res.getString("DDateTimeChooser.Day.Tue"),
                                                             res.getString("DDateTimeChooser.Day.Wed"),
                                                             res.getString("DDateTimeChooser.Day.Thu"),
                                                             res.getString("DDateTimeChooser.Day.Fri"),
                                                             res.getString("DDateTimeChooser.Day.Sat"),
                                                             res.getString("DDateTimeChooser.Day.Sun") };

    // light scheme colors
    private static final Color LIGHT_BLUE = new Color(51, 119, 204);
    private static final Color WEEK_DAY_FOREGROUND_LIGHT = WHITE;
    private static final Color WEEK_DAY_BACKGROUND_LIGHT = LIGHT_BLUE;
    private static final Color DAY_FOREGROUND_LIGHT = LIGHT_BLUE;
    private static final Color DAY_BACKGROUND_LIGHT = WHITE;
    private static final Color SELECTED_DAY_FOREGROUND_LIGHT = WHITE;
    private static final Color SELECTED_DAY_BACKGROUND_LIGHT = BLUE;

    // dark scheme colors
    private static final Color WEEK_DAY_FOREGROUND_DARK = WHITE;
    private static final Color WEEK_DAY_BACKGROUND_DARK = LIGHT_BLUE;
    private static final Color DAY_FOREGROUND_DARK = LIGHT_GRAY;
    private static final Color DAY_BACKGROUND_DARK = DARK_GRAY;
    private static final Color SELECTED_DAY_FOREGROUND_DARK = WHITE;
    private static final Color SELECTED_DAY_BACKGROUND_DARK = BLUE;

    private static final String EMPTY_DAY = " ";
    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JComboBox<?> jcbMonth;
    private JSpinner jsYear;
    private JPanel jpDaysOfMonth;
    private JLabel[][] jlDaysOfMonth;
    private JLabel jlSelectedDayOfMonth;
    private JSpinner jsHour;
    private JSpinner jsMinute;
    private JSpinner jsSecond;
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
     * @param parent The parent frame
     * @param title  The dialog title
     * @param date   Date to display initially
     */
    public DDateTimeChooser(JFrame parent, String title, Date date) {
        super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
        initComponents(date);
    }

    /**
     * Constructs a new DDateTimeChooser dialog.
     *
     * @param parent The parent dialog
     * @param title  The dialog title
     * @param date   Date to display initially
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
        jcbMonth.addItemListener(evt -> update());

        jsYear = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.YEAR), MIN_YEAR, MAX_YEAR, 1));
        jsYear.setEditor(new JSpinner.NumberEditor(jsYear, "0000"));
        jsYear.addChangeListener(evt -> update());

        jlDaysOfMonth = new JLabel[7][7];
        for (int i = 0; i < 7; i++) {
            jlDaysOfMonth[0][i] = new JLabel(DAY_NAMES[i], SwingConstants.CENTER);
            jlDaysOfMonth[0][i].setOpaque(true);
            jlDaysOfMonth[0][i].setForeground(
                    LnfUtil.isDarkLnf() ? WEEK_DAY_FOREGROUND_DARK : WEEK_DAY_FOREGROUND_LIGHT);
            jlDaysOfMonth[0][i].setBackground(
                    LnfUtil.isDarkLnf() ? WEEK_DAY_BACKGROUND_DARK : WEEK_DAY_BACKGROUND_LIGHT);
        }
        for (int i = 1; i < 7; i++) {
            for (int j = 0; j < 7; j++) {
                jlDaysOfMonth[i][j] = new JLabel(EMPTY_DAY, SwingConstants.CENTER);
                jlDaysOfMonth[i][j].setOpaque(true);
                jlDaysOfMonth[i][j].setForeground(LnfUtil.isDarkLnf() ? DAY_FOREGROUND_DARK : DAY_FOREGROUND_LIGHT);
                jlDaysOfMonth[i][j].setBackground(LnfUtil.isDarkLnf() ? DAY_BACKGROUND_DARK : DAY_BACKGROUND_LIGHT);
                jlDaysOfMonth[i][j].addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent evt) {
                        selectDay((JLabel) evt.getSource());
                    }
                });
                jlDaysOfMonth[i][j].setBorder(new MatteBorder(0, 0, 0, 0, Color.WHITE));
            }
        }

        jpDaysOfMonth = new JPanel(new MigLayout("insets 0, fill", "[fill]0[fill]", ""));
        jpDaysOfMonth.setBackground((LnfUtil.isDarkLnf() ? DAY_BACKGROUND_DARK : DAY_BACKGROUND_LIGHT));
        jpDaysOfMonth.setFocusable(true);
        jpDaysOfMonth.setBorder(
                new CompoundBorder(BorderFactory.createLoweredBevelBorder(), new EmptyBorder(2, 2, 2, 2)));

        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < 7; j++) {
                jpDaysOfMonth.add(jlDaysOfMonth[i][j], j == 6 ? "wrap 2" : "");
            }
        }

        jsHour = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.HOUR_OF_DAY), 0, 23, 1));
        jsHour.setEditor(new JSpinner.NumberEditor(jsHour, "00"));

        jsMinute = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.MINUTE), 0, 59, 1));
        jsMinute.setEditor(new JSpinner.NumberEditor(jsMinute, "00"));

        jsSecond = new JSpinner(new SpinnerNumberModel(calendar.get(Calendar.SECOND), 0, 59, 1));
        jsSecond.setEditor(new JSpinner.NumberEditor(jsSecond, "00"));

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

        jbOK = new JButton(res.getString("DDateTimeChooser.jbOK.text"));

        jbCancel = new JButton(res.getString("DDateTimeChooser.jbCancel.text"));
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);

        jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

        JPanel jpDateTime = new JPanel();
        jpDateTime.setLayout(new BoxLayout(jpDateTime, BoxLayout.Y_AXIS));
        jpDateTime.setBorder(new CompoundBorder(new EmptyBorder(0, 0, 0, 0),
                                                new CompoundBorder(new EtchedBorder(), new EmptyBorder(0, 0, 0, 0))));

        // layout of inner panel
        jpDateTime.setLayout(new MigLayout("insets panel, fill", "", ""));
        jpDateTime.add(jcbMonth, "spanx, split, align 50%");
        jpDateTime.add(jsYear, "wrap");
        jpDateTime.add(jpDaysOfMonth, "spanx, growx, wrap");
        jpDateTime.add(jsHour, "spanx, split, align 50%");
        jpDateTime.add(new JLabel(":"), "");
        jpDateTime.add(jsMinute, "");
        jpDateTime.add(new JLabel(":"), "");
        jpDateTime.add(jsSecond, "wrap unrel");
        jpDateTime.add(jbStartOfYear, "spanx, split, align 50%");
        jpDateTime.add(jbNow, "");
        jpDateTime.add(jbEndOfYear, "");

        // layout of dialog
        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets panel, fill", "", ""));
        pane.add(jpDateTime, "wrap unrel");
        pane.add(jpButtons, "right, spanx");

        jbOK.addActionListener(evt -> okPressed());
        jbCancel.addActionListener(evt -> cancelPressed());

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

        populate(date);
        update();

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
            // always a number
        }

        return -1;
    }

    private void setSelectedDay(JLabel newDay) {
        if (jlSelectedDayOfMonth != null) {
            jlSelectedDayOfMonth.setForeground(LnfUtil.isDarkLnf() ? DAY_FOREGROUND_DARK : DAY_FOREGROUND_LIGHT);
            jlSelectedDayOfMonth.setBackground(LnfUtil.isDarkLnf() ? DAY_BACKGROUND_DARK : DAY_BACKGROUND_LIGHT);
        }

        jlSelectedDayOfMonth = newDay;
        jlSelectedDayOfMonth.setForeground(
                LnfUtil.isDarkLnf() ? SELECTED_DAY_FOREGROUND_DARK : SELECTED_DAY_FOREGROUND_LIGHT);
        jlSelectedDayOfMonth.setBackground(
                LnfUtil.isDarkLnf() ? SELECTED_DAY_BACKGROUND_DARK : SELECTED_DAY_BACKGROUND_LIGHT);
    }

    private void setSelectedDay(int newDay) {
        setSelectedDay(
                jlDaysOfMonth[((newDay + indexOfFirstDayOfMonth - 1) / 7) + 1][(newDay + indexOfFirstDayOfMonth - 1) %
                                                                               7]);
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
            jlDaysOfMonth[((i + indexOfFirstDayOfMonth) / 7) + 1][(i + indexOfFirstDayOfMonth) % 7].setText(
                    String.valueOf(i + 1));
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

    // for quick UI testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        DDateTimeChooser dialog = new DDateTimeChooser(new JFrame(), "Select Date", null);
        DialogViewer.run(dialog);
    }
}
