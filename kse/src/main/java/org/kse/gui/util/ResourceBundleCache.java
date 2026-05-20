/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.gui.util;

import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

/**
 * A Singleton for caching ResourceBundles. This singleton is used by classes
 * that have their static fields initialized before the language preference is
 * loaded from the configuration. Classes referenced by KsePreferences that use
 * ResourceBundles for language specific text should use this class for loading
 * the resource strings.
 */
public enum ResourceBundleCache {

    /**
     * The singleton instance.
     */
    INSTANCE;

    private Map<String, ResourceBundle> resourceBundles = new HashMap<>();

    /**
     * Returns a translated string using the requested resource bundle. The
     * ResourceBundles are cached as they are used so a bundle is only loaded
     * once.
     *
     * @param bundlePath The resource bundle path.
     * @param key The resource bundle key.
     * @return The string associated with the resource bundle key.
     */
    public String getString(String bundlePath, String key) {
        return resourceBundles.computeIfAbsent(bundlePath, this::loadBundle).getString(key);
    }

    private ResourceBundle loadBundle(String bundlePath) {
        return ResourceBundle.getBundle(bundlePath);
    }
}
