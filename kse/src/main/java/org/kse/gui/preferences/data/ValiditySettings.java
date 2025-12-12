/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

package org.kse.gui.preferences.data;

/**
 * Config bean for storing settings for certificate validity.
 */
public class ValiditySettings {

    /**
     * The time period for the validity value.
     */
    public enum PeriodType {
        /**
         * Years period type
         */
        YEARS,

        /**
         * Months period type
         */
        MONTHS,

        /**
         * Weeks period type
         */
        WEEKS,

        /**
         * Days period type
         */
        DAYS
    }

    private int periodValue = 1;
    private PeriodType periodType = PeriodType.YEARS;

    /**
     * Constructs a new ValiditySettings instance using default values (1 YEARS)
     */
    public ValiditySettings() {
    }

    /**
     * Constructs a new ValiditySettings instance with period value and type.
     *
     * @param periodValue The period value to use for the default.
     * @param periodType The period type to use for the default.
     */
    public ValiditySettings(int periodValue, PeriodType periodType) {
        this.periodValue = periodValue;
        this.periodType = periodType;
    }

    /**
     * @return the value
     */
    public int getPeriodValue() {
        return periodValue;
    }

    /**
     * @param value 
     *                 value to set
     */
    public void setPeriodValue(int value) {
        this.periodValue = value;
    }

    /**
     * @return the period
     */
    public PeriodType getPeriodType() {
        return periodType;
    }

    /**
     * @param period 
     *                 period to set
     */
    public void setPeriodType(PeriodType period) {
        this.periodType = period;
    }
}
