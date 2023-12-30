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

package org.kse.gui.preferences.data;

import java.time.LocalDate;

/**
 * Config bean for storing settings for automatic update check
 */
public class AutoUpdateCheckSettings {

    private boolean enabled = true;
    private LocalDate lastCheck = LocalDate.now();
    private int checkInterval = 14;


    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public LocalDate getLastCheck() {
        return lastCheck;
    }

    public void setLastCheck(LocalDate lastCheck) {
        this.lastCheck = lastCheck;
    }

    public int getCheckInterval() {
        return checkInterval;
    }

    public void setCheckInterval(int checkInterval) {
        this.checkInterval = checkInterval;
    }
}
