/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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

import java.awt.Component;
import java.awt.HeadlessException;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.kse.utilities.os.OperatingSystem;

public class JavaFXFileChooser extends JFileChooser {

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

    private static final long serialVersionUID = 706991877631924379L;

    private static Class<?> platformClass;
    private static Class<?> fileChooserClass;
    private static Class<?> directoryChooserClass;
    private static Class<?> extensionFilterClass;
    private static Class<?> windowClass;

    private static boolean fxAvailable = false;

    static {
        // check for availability and initialize javafx thread
        try {
            // disabled for macOS because there are incompatibilities between JavaFX file
            // chooser and some mac tools
            if (!OperatingSystem.isMacOs()) {
                Class.forName("javafx.embed.swing.JFXPanel").getConstructor().newInstance();
                platformClass = Class.forName("javafx.application.Platform");
                fileChooserClass = Class.forName("javafx.stage.FileChooser");
                directoryChooserClass = Class.forName("javafx.stage.DirectoryChooser");
                extensionFilterClass = Class.forName("javafx.stage.FileChooser$ExtensionFilter");
                windowClass = Class.forName("javafx.stage.Window");
                fxAvailable = true;
            }
        } catch (Exception e) {
            fxAvailable = false;
        }
    }

    private List<FileNameExtensionFilter> filters = new ArrayList<>();
    private File selectedFile;
    private File[] selectedFiles;
    private String dialogTitle;
    private File currentDirectory;
    public static final int FILES_ONLY = 0;
    public static final int DIRECTORIES_ONLY = 1;
    public static final int FILES_AND_DIRECTORIES = 2;

    public static boolean isFxAvailable() {
        return fxAvailable;
    }

    @Override
    public void addChoosableFileFilter(FileFilter filter) {
        if (filter instanceof FileNameExtensionFilter) {
            filters.add((FileNameExtensionFilter) filter);
        }
    }

    @Override
    public void setFileFilter(FileFilter filter) {
        addChoosableFileFilter(filter);
    }

    @Override
    public File getSelectedFile() {
        return selectedFile;
    }

    @Override
    public File[] getSelectedFiles() {
        return selectedFiles;
    }

    @Override
    public void setCurrentDirectory(File dir) {
        currentDirectory = dir;
    }

    @Override
    public void setSelectedFile(File file) {
        selectedFile = file;
    }

    @Override
    public void setSelectedFiles(File[] files) {
        selectedFiles = files;
    }

    @Override
    public void setDialogTitle(String dialogTitle) {
        this.dialogTitle = dialogTitle;
    }

    @Override
    public int showDialog(Component parent, String approveButtonText) throws HeadlessException {
        // text of approve button cannot be changed in JavaFX FileChooser
        if (isMultiSelectionEnabled()) {
            return showMultipleFxDialog("showOpenMultipleDialog");
        }
        if (getFileSelectionMode() == DIRECTORIES_ONLY) {
            return showDirectoryFxDialog("showDialog");
        }
        return showFxDialog("showOpenDialog");
    }

    @Override
    public int showOpenDialog(Component parent) throws HeadlessException {
        if (isMultiSelectionEnabled()) {
            return showMultipleFxDialog("showOpenMultipleDialog");
        }
        return showFxDialog("showOpenDialog");
    }

    @Override
    public int showSaveDialog(Component parent) throws HeadlessException {
        return showFxDialog("showSaveDialog");
    }

    /**
     * Creates a method with a callable lambda
     *
     * @param method Accepts String
     * @return Int
     */
    public int showFxDialog(final String method) {

        try {
            final Object fileChooser = fileChooserClass.getConstructor().newInstance();

            // create a callable lambda
            selectedFile = runLater(() -> {

                // set extension filters
                Method getExtensionFiltersMethod = fileChooserClass.getMethod("getExtensionFilters");
                List<Object> observableList = (List<Object>) getExtensionFiltersMethod.invoke(fileChooser);

                // checks whether the AcceptAll FileFilter is used.
                if (isAcceptAllFileFilterUsed()) {
                    observableList.add(extensionFilterClass.getConstructor(String.class, String[].class)
                                                           .newInstance(res.getString("JavaFXFileChooser.AllFiles"),
                                                                        new String[] { "*.*" }));
                }

                for (FileNameExtensionFilter fileFilter : filters) {
                    String[] extensions = fileFilter.getExtensions();
                    for (int i = 0; i < extensions.length; i++) {
                        // check if extension is specified in the *.<extension> format
                        // for the ExtensionFilter class
                        if (!extensions[i].startsWith("*.")) {
                            extensions[i] = "*." + extensions[i].toLowerCase();
                        }
                    }
                    Object extFilter = extensionFilterClass.getConstructor(String.class, String[].class)
                                                           .newInstance(fileFilter.getDescription(), extensions);
                    observableList.add(extFilter);

                }

                // set window title
                Method setTitleMethod = fileChooserClass.getMethod("setTitle", String.class);
                setTitleMethod.invoke(fileChooser, dialogTitle);

                // set current directory
                Method setInitialDirectory = fileChooserClass.getMethod("setInitialDirectory", File.class);
                setInitialDirectory.invoke(fileChooser, currentDirectory);

                Method showDialogMethod = fileChooserClass.getMethod(method, windowClass);
                Object file = showDialogMethod.invoke(fileChooser, (Object) null);

                return (File) file;
            });

        } catch (Exception e) {
            return JFileChooser.ERROR_OPTION;
        }

        if (selectedFile == null) {
            return JFileChooser.CANCEL_OPTION;
        }

        return JFileChooser.APPROVE_OPTION;
    }

    /**
     * Creates a method with a callable lambda
     *
     * @param method Accepts String
     * @return Int
     */
    public int showMultipleFxDialog(final String method) {

        try {
            final Object fileChooser = fileChooserClass.getConstructor().newInstance();

            // create a callable lambda
            selectedFiles = runLaterMultiple(() -> {

                // set extension filters
                Method getExtensionFiltersMethod = fileChooserClass.getMethod("getExtensionFilters");
                List<Object> observableList = (List<Object>) getExtensionFiltersMethod.invoke(fileChooser);

                // checks whether the AcceptAll FileFilter is used.
                if (isAcceptAllFileFilterUsed()) {
                    observableList.add(extensionFilterClass.getConstructor(String.class, String[].class)
                                                           .newInstance(res.getString("JavaFXFileChooser.AllFiles"),
                                                                        new String[] { "*.*" }));
                }

                for (FileNameExtensionFilter fileFilter : filters) {
                    String[] extensions = fileFilter.getExtensions();
                    for (int i = 0; i < extensions.length; i++) {
                        // check if extension is specified in the *.<extension> format
                        // for the ExtensionFilter class
                        if (!extensions[i].startsWith("*.")) {
                            extensions[i] = "*." + extensions[i].toLowerCase();
                        }
                    }
                    Object extFilter = extensionFilterClass.getConstructor(String.class, String[].class)
                                                           .newInstance(fileFilter.getDescription(), extensions);
                    observableList.add(extFilter);

                }

                // set window title
                Method setTitleMethod = fileChooserClass.getMethod("setTitle", String.class);
                setTitleMethod.invoke(fileChooser, dialogTitle);

                // set current directory
                Method setInitialDirectory = fileChooserClass.getMethod("setInitialDirectory", File.class);
                setInitialDirectory.invoke(fileChooser, currentDirectory);

                Method showDialogMethod = fileChooserClass.getMethod(method, windowClass);
                Object file = showDialogMethod.invoke(fileChooser, (Object) null);

                // create a File array
                File[] files = new File[((List<Object>) file).size()];

                // convert an ArrayList to a File array; List<File> to File[]
                for (int i = 0; i < ((List<Object>) file).size(); i++) {
                    files[i] = (File) ((List<Object>) file).get(i);
                }

                return files;
            });

        } catch (Exception e) {
            return JFileChooser.ERROR_OPTION;
        }

        if (selectedFiles == null) {
            return JFileChooser.CANCEL_OPTION;
        }

        return JFileChooser.APPROVE_OPTION;
    }

    /**
     * Creates a method with a callable lambda
     *
     * @param method Accepts String
     * @return Int
     */
    public int showDirectoryFxDialog(final String method) {

        try {
            final Object directoryChooser = directoryChooserClass.getConstructor().newInstance();

            // create a callable lambda
            selectedFile = runLater(() -> {

                // set window title
                Method setTitleMethod = directoryChooserClass.getMethod("setTitle", String.class);
                setTitleMethod.invoke(directoryChooser, dialogTitle);

                // set current directory
                Method setInitialDirectory = directoryChooserClass.getMethod("setInitialDirectory", File.class);
                setInitialDirectory.invoke(directoryChooser, currentDirectory);

                Method showDialogMethod = directoryChooserClass.getMethod(method, windowClass);
                Object file = showDialogMethod.invoke(directoryChooser, (Object) null);

                return (File) file;
            });

        } catch (Exception e) {
            System.out.println(e);
            return JFileChooser.ERROR_OPTION;
        }

        if (selectedFile == null) {
            return JFileChooser.CANCEL_OPTION;
        }

        return JFileChooser.APPROVE_OPTION;
    }

    /**
     * Invokes a Java FX threaded function
     *
     * @param callable Accepts a File
     * @return File
     * @throws Exception
     */
    public File runLater(final Callable<File> callable) throws Exception {

        final FutureTask<File> task = new FutureTask<>(callable);

        Class<?> platformClass = Class.forName("javafx.application.Platform");
        Method runLaterMethod = platformClass.getMethod("runLater", Runnable.class);
        runLaterMethod.invoke(null, task);

        try {
            return task.get();
        } catch (ExecutionException ex) {
            throw new Exception(ex.getCause());
        }
    }

    /**
     * Invokes a Java FX threaded function
     *
     * @param callable Accepts a File[]
     * @return File[]
     * @throws Exception
     */
    public File[] runLaterMultiple(final Callable<File[]> callable) throws Exception {

        final FutureTask<File[]> task = new FutureTask<>(callable);

        Class<?> platformClass = Class.forName("javafx.application.Platform");
        Method runLaterMethod = platformClass.getMethod("runLater", Runnable.class);
        runLaterMethod.invoke(null, task);

        try {
            return task.get();
        } catch (ExecutionException ex) {
            throw new Exception(ex.getCause());
        }
    }

    // for quick UI testing
    public static void main(String[] args)
            throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException,
                   InvocationTargetException {

        if (!fxAvailable) {
            System.out.println("JavaFX not available");
            System.exit(1);
        }

        //JavaFXFileChooser chooser = new JavaFXFileChooser();
        JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();
        chooser.addChoosableFileFilter(new FileNameExtensionFilter("Description1", new String[] { "jks" }));
        //chooser.addChoosableFileFilter(new FileNameExtensionFilter("Description2", new String[] { "p12" }));
        chooser.setDialogTitle("Dialog Title");
        chooser.setCurrentDirectory(new File("."));
        //chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        // chooser.setSelectedFiles(new ArrayList<File>());
        chooser.setMultiSelectionEnabled(true);
        //chooser.setAcceptAllFileFilterUsed(false);
        chooser.showDialog(null, "Button Text");

        //chooser.showSaveDialog(null);
        //File file = chooser.getSelectedFile();

        //System.out.println(file.getAbsolutePath());
        System.out.println(chooser.getSelectedFiles().length);

        Method platformExitMethod = platformClass.getMethod("exit");
        platformExitMethod.invoke(null);
    }
}