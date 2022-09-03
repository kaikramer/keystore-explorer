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
    private FileNameExtensionFilter fileFilter = null;
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
        if (filter instanceof FileNameExtensionFilter) {
            if(!isDuplicateFilter(filters, (FileNameExtensionFilter) filter)) {
                addChoosableFileFilter(filter);
            }
            fileFilter = (FileNameExtensionFilter) filter;
        }
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
                
                // checks if the AcceptAll FileFilter is used.
                if (isAcceptAllFileFilterUsed()) {
                    observableList.add(extensionFilterClass.getConstructor(String.class, String[].class)
                                                           .newInstance(res.getString("JavaFXFileChooser.AllFiles"),
                                                                        new String[] { "*.*" }));
                }
                
                // add extension filters
                observableList.addAll(formatListToJFX(filters));
                
                // set selected file filter
                if (fileFilter != null) {
                    int filterIndex = getExtensionIndex(observableList, fileFilter);
                    Method setSelectedExtensionFilterMethod = fileChooserClass.getMethod("setSelectedExtensionFilter",
                                                              extensionFilterClass);
                    setSelectedExtensionFilterMethod.invoke(fileChooser, observableList.get(filterIndex));
                }
                
                // set window title
                Method setTitleMethod = fileChooserClass.getMethod("setTitle", String.class);
                setTitleMethod.invoke(fileChooser, dialogTitle);

                // set current directory
                Method setInitialDirectory = fileChooserClass.getMethod("setInitialDirectory", File.class);
                setInitialDirectory.invoke(fileChooser, currentDirectory);

                // set show dialog
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
                
                // checks if the AcceptAll FileFilter is used.
                if (isAcceptAllFileFilterUsed()) {
                    observableList.add(extensionFilterClass.getConstructor(String.class, String[].class)
                                                           .newInstance(res.getString("JavaFXFileChooser.AllFiles"),
                                                                        new String[] { "*.*" }));
                }
                
                // add extension filters
                observableList.addAll(formatListToJFX(filters));

                // set selected extension filter
                if (fileFilter != null) {
                int filterIndex = getExtensionIndex(observableList, fileFilter);
                Method setSelectedExtensionFilterMethod = fileChooserClass.getMethod("setSelectedExtensionFilter",
                                                          extensionFilterClass);
                setSelectedExtensionFilterMethod.invoke(fileChooser, observableList.get(filterIndex));
                }
                
                // set window title
                Method setTitleMethod = fileChooserClass.getMethod("setTitle", String.class);
                setTitleMethod.invoke(fileChooser, dialogTitle);

                // set current directory
                Method setInitialDirectory = fileChooserClass.getMethod("setInitialDirectory", File.class);
                setInitialDirectory.invoke(fileChooser, currentDirectory);

                // set show dialog
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

                // set show dialog
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
     * Convert List of FileNameExtensionFilter to List of Java FX ExtensionFilter format
     * @param List<FileNameExtensionFilter> args
     * @return List<Object>
     */
    private List<Object> formatListToJFX(List<FileNameExtensionFilter> args){
        List<Object> extensionList = new ArrayList<Object>();
        
        // parse extension filters to conform to JavaFX
        for (FileFilter fileFilters : args) {
            Object ext = formatToJFXExtensionFilter(fileFilters);
            extensionList.add(ext);
        }
        return extensionList;
    }
    
    /**
     * Helper function to format extension filters
     * from FileNameExtensionFilter to Java FX ExtensionFilter
     * @param FileFilter arg
     * @return Object
     */
    private Object formatToJFXExtensionFilter(FileFilter arg) {
        FileNameExtensionFilter extensions = (FileNameExtensionFilter) arg;
        String[] formatExtensions = extensions.getExtensions();
        Object efc = null; // extension filter conversion
        for (int i = 0; i < formatExtensions.length; i++) {
            // check if extension is specified in the *.<extension> format
            // according to the JavaFX ExtensionFilter class
            if (!formatExtensions[i].startsWith("*.")) {
                formatExtensions[i] = "*." + formatExtensions[i].toLowerCase();
            }
        }
        try {
            efc = extensionFilterClass.getConstructor(String.class, String[].class)
                .newInstance(extensions.getDescription(), formatExtensions);
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return efc;
    }
    
    /**
     * Examine file filter extensions for duplicate entries based on unique extensions.
     * For example (*.jpg, *.gif) and (*.jpg) are unique and can both be valid but not
     * more than one extension signature with (*.jpg) regardless of description.
     * @param List<FileNameExtensionFilter> exts
     * @param FileNameExtensionFilter ext
     * @return boolean
     */
    private boolean isDuplicateFilter(List<FileNameExtensionFilter> exts, FileNameExtensionFilter ext) {
        boolean isDuplicate = false;
        Object oExt = formatToJFXExtensionFilter(ext);
        List<Object> oExts = formatListToJFX(exts);
        String refExt = null;
        String difExt = null;
        for (int i = 0; i < oExts.size(); i++) {
            try {
                Method getFileExt = extensionFilterClass.getMethod("getExtensions");
                refExt = getFileExt.invoke(oExts.get(i)).toString();
                difExt = getFileExt.invoke(oExt).toString();
            }
            catch (Exception e ) {
                System.out.println(e);
            }
            // checks if the extension list matches the set file filter
            if(refExt.equals(difExt)){
                isDuplicate =  true;
            }
        }
        return isDuplicate;
    }
    /**
     * Get the extension filter index from a List of exension filters
     * 
     * @param List<Object> arg
     * @return int
     */
    private int getExtensionIndex(List<Object> arg, FileNameExtensionFilter ext) {
        int index = 0;
        Object oExt = formatToJFXExtensionFilter(ext);
        String refExt = null;
        String difExt = null;
        // loops through each file extension
            for (int i = 0; i < arg.size(); i++) {
                try {
                    Method getFileExt = extensionFilterClass.getMethod("getExtensions");
                    refExt = getFileExt.invoke(arg.get(i)).toString();
                    difExt = getFileExt.invoke(oExt).toString();
                }
                catch (Exception e ) {
                    System.out.println(e);
                }
                // checks if the extension list matches the set file filter
                if(refExt.equals(difExt)){
                    index =  i;
                }
            }
        return index;
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
            throws NoSuchMethodException, SecurityException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException {

            if (!fxAvailable) {
                System.out.println("JavaFX not available");
                System.exit(1);
        }

        //JavaFXFileChooser chooser = new JavaFXFileChooser();
        JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setDialogTitle("Dialog Title");
        chooser.setCurrentDirectory(new File("."));
        chooser.setMultiSelectionEnabled(false);
        // chooser.addChoosableFileFilter(new FileNameExtensionFilter("Description1",
        // new String[] { "jks" }));
        chooser.setFileFilter(new FileNameExtensionFilter("ZIP Filez", new String[] { "zip" }));
        //chooser.setFileFilter(new FileNameExtensionFilter("Description_1", new String[] { "mkv", "jpg" }));
        // chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.showDialog(null, "Button Text");

        // chooser.showSaveDialog(null);
        File file = chooser.getSelectedFile();

        // System.out.println(file.getAbsolutePath());
        // System.out.println(chooser.getSelectedFiles().length);

        Method platformExitMethod = platformClass.getMethod("exit");
        platformExitMethod.invoke(null);
    }
}