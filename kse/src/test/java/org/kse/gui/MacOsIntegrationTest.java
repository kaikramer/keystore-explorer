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
package org.kse.gui;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.awt.desktop.OpenFilesEvent;
import java.awt.desktop.OpenFilesHandler;
import java.io.File;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.kse.gui.dnd.DroppedFileHandler;
import org.mockito.MockedStatic;

class MacOsIntegrationTest {

    @Test
    void openFilesUsesFileTypeAwareHandler() throws Exception {
        KseFrame frame = mock(KseFrame.class);
        List<File> files = List.of(new File("certificate.cer"), new File("private.key"), new File("store.jks"));
        Method method = OpenFilesHandler.class.getMethod("openFiles", OpenFilesEvent.class);

        SwingUtilities.invokeAndWait(() -> {
            try (MockedStatic<DroppedFileHandler> handler = mockStatic(DroppedFileHandler.class)) {
                try {
                    new MacOsIntegration(frame).invoke(null, method, new Object[] { openFilesEvent(files) });
                } catch (Throwable e) {
                    throw new AssertionError(e);
                }
                handler.verify(() -> DroppedFileHandler.openFiles(frame, files));
            }
        });
    }

    @Test
    void openFilesFromAnotherThreadRunsOnEventDispatchThread() throws Throwable {
        KseFrame frame = mock(KseFrame.class);
        List<File> files = List.of(new File("certificate.cer"));
        Method method = OpenFilesHandler.class.getMethod("openFiles", OpenFilesEvent.class);
        AtomicReference<MockedStatic<DroppedFileHandler>> mockRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> mockRef.set(mockStatic(DroppedFileHandler.class)));
        try {
            new MacOsIntegration(frame).invoke(null, method, new Object[] { openFilesEvent(files) });
            SwingUtilities.invokeAndWait(() -> mockRef.get().verify(() -> DroppedFileHandler.openFiles(frame, files)));
        } finally {
            SwingUtilities.invokeAndWait(() -> mockRef.get().close());
        }
    }

    // OpenFilesEvent's constructor needs Desktop.getDesktop(), which fails on headless machines
    private static OpenFilesEvent openFilesEvent(List<File> files) {
        OpenFilesEvent event = mock(OpenFilesEvent.class);
        when(event.getFiles()).thenReturn(files);
        return event;
    }
}
