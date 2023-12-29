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
package org.kse.gui.error;

/**
 * Encapsutes a problem and possible causes.
 */
public class Problem {
    private String problem;
    private String[] causes;
    private Throwable error;

    /**
     * Construct ProblemAndCauses.
     *
     * @param problem Problem description
     * @param causes  Possible causes
     * @param error   Cause error
     */
    public Problem(String problem, String[] causes, Throwable error) {
        this.problem = problem;
        this.causes = causes;
        this.error = error;
    }

    /**
     * Get problem description.
     *
     * @return problem description
     */
    public String getProblem() {
        return problem;
    }

    /**
     * Get possible causes.
     *
     * @return Possible causes
     */
    public String[] getCauses() {
        return causes;
    }

    /**
     * Get cause error.
     *
     * @return Cause error
     */
    public Throwable getError() {
        return error;
    }
}
