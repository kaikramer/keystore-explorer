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

package org.kse.utilities.io;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.swing.SwingUtilities;

import org.kse.gui.KseFrame;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * A Singleton for watching directories containing KeyStore files. File-based KeyStoreTypes
 * register when the backing file exists and unregister when the KeyStore is closed.
 */
public enum AutoReloadWatcher {

    // Singleton pattern
    INSTANCE;

    private KseFrame frame;
    private WatchService ws;
    private Thread watchThread;

    private Set<Path> watchedDirs = new HashSet<>();
    private Map<Path, KeyStoreHistory> keyStoreFiles = new HashMap<>();

    public void start(KseFrame frame) {
        this.frame = frame;
        try {
            ws = FileSystems.getDefault().newWatchService();

            watchThread = new Thread(this::eventHandler, "Watch Service");
            watchThread.setDaemon(true);
            watchThread.start();
        } catch (IOException e) {
            // Silently ignore - There is nothing the user can do if the
            // watch service cannot be started.
        }
    }

    /**
     * Registers a KeyStoreHistory with the automatic KeyStore file watcher for detecting
     * external modifications.
     *
     * @param history The KeyStoryHistory to register.
     */
    public void register(KeyStoreHistory history) {
        if (ws != null) {
            try {
                Path parentPath = history.getFile().getParentFile().toPath();
                if (!watchedDirs.contains(parentPath)) {
                    parentPath.register(ws, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
                    watchedDirs.add(parentPath);
                }
                keyStoreFiles.put(history.getFile().toPath(), history);
            } catch (IOException e) {
                // Silently ignore - There is nothing the user can do if the
                // KeyStore directory cannot be registered with the WatchService.
            }
        }
    }

    /**
     * Unregisters a KeyStoreHistory so that external modifications to the KeyStore file
     * are no longer tracked.
     *
     * @param history The KeyStoreHistory to unregister.
     */
    public void unregister(KeyStoreHistory history) {
        keyStoreFiles.remove(history.getFile().toPath());
    }

    private void eventHandler() {
        // The key represents the directory.
        while (true) {
            try {
                WatchKey key = ws.take();
                Path dir = (Path) key.watchable();

                for (WatchEvent<?> event : key.pollEvents()) {
                    // event.context() contains the relative path (i.e. name of the file that was modified).
                    KeyStoreHistory history = keyStoreFiles.get(dir.resolve((Path) event.context()));
                    if (history != null) {
                        // Don't trigger the update if it's already flagged for update
                        if (!history.isSuppressWatcherEvents() && !history.isExternallyModified()) {
                            history.setExternallyModified(true);

                            SwingUtilities.invokeLater(() -> {
                                frame.handleExternalModification(history);
                            });
                        }
                    }
                }
                key.reset();
            } catch (InterruptedException e) {
                // Ignore -- just keep taking in case the thread is interrupted
            }
        }
    }
}
