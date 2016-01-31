package net.sf.keystore_explorer.gui;

import java.awt.Component;
import java.awt.HeadlessException;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import javax.swing.JFileChooser;

import net.sf.keystore_explorer.gui.FileChooserFactory.KseFileExtFilter;

public class JavaFXFileChooser extends JFileChooser {

    private static final long serialVersionUID = 706991877631924379L;

    static private Class<?> platformClass;
    static private Class<?> fileChooserClass;
    static private Class<?> extensionFilterClass;
    static private Class<?> windowClass;

    private static boolean fxAvailable = false;

    static {
        // check for availability and initialize javafx thread
        try {
            Class.forName("javafx.embed.swing.JFXPanel").getConstructor().newInstance();
            platformClass = Class.forName("javafx.application.Platform");
            fileChooserClass = Class.forName("javafx.stage.FileChooser");
            extensionFilterClass = Class.forName("javafx.stage.FileChooser$ExtensionFilter");
            windowClass = Class.forName("javafx.stage.Window");
            fxAvailable = true;
        } catch (Exception e) {
            fxAvailable = false;
        }
    }

    private List<KseFileExtFilter> filters = new ArrayList<KseFileExtFilter>();
    private File selectedFile;
    private String dialogTitle;

    public static boolean isFxAvailable() {
        return fxAvailable;
    }

    public void addChoosableFileFilter(KseFileExtFilter filter) {
        filters.add(filter);
    }

    @Override
    public File getSelectedFile() {
        return selectedFile;
    }

    @Override
    public void setMultiSelectionEnabled(boolean b) {
        // ignore for now
    }

    @Override
    public void setCurrentDirectory(File dir) {
        // ignore because native file dialog already has a memory
    }

    @Override
    public void setSelectedFile(File file) {
        selectedFile = file;
    }

    @Override
    public void setDialogTitle(String dialogTitle) {
        this.dialogTitle = dialogTitle;
    }

    @Override
    public int showDialog(Component parent, String approveButtonText) throws HeadlessException {

        try {
			final Object fileChooser = fileChooserClass.getConstructor().newInstance();

			SynchronousJFXCaller<File> caller = new SynchronousJFXCaller<File>(new Callable<File>() {

				@Override
				public File call() throws Exception {
					try {

						// set extension filters
						Method getExtensionFiltersMethod = fileChooserClass.getMethod("getExtensionFilters");
						List observableList = (List) getExtensionFiltersMethod.invoke(fileChooser);
						for (KseFileExtFilter fileFilter : filters) {
							Object extFilter = extensionFilterClass.getConstructor(String.class, String[].class)
									.newInstance(fileFilter.getDescription(), fileFilter.getExtensions());
							observableList.add(extFilter);
						}

						// set window title
						Method setTitleMethod = fileChooserClass.getMethod("setTitle", String.class);
						setTitleMethod.invoke(fileChooser, dialogTitle);

						Method showOpenDialogMethod = fileChooserClass.getMethod("showOpenDialog", windowClass);
						Object file = showOpenDialogMethod.invoke(fileChooser, (Object) null);

						if (file != null) {
							selectedFile = (File) file;
						}
					} catch (Exception e) {
						// TODO
						e.printStackTrace();
					}

					if (selectedFile == null) {
						selectedFile = new File("");
					}

					return selectedFile;
				}
			});

			caller.call();

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}

        // TODO
        return 0;
    }

    public static void main(String[] args) throws NoSuchMethodException, SecurityException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException {

        JavaFXFileChooser chooser = new JavaFXFileChooser();
        chooser.addChoosableFileFilter(new KseFileExtFilter(new String[] { ".jks" }, "Description1"));
        chooser.addChoosableFileFilter(new KseFileExtFilter(new String[] { ".p12" }, "Description2"));
        chooser.setDialogTitle("Dialog Titel");
        chooser.setCurrentDirectory(new File("F:\tmp"));
        chooser.setSelectedFile(new File(""));
        chooser.setMultiSelectionEnabled(false);
        chooser.showDialog(null, "Button Text");

        System.out.println(chooser.getSelectedFile().getAbsolutePath());

        Method platformExitMethod = platformClass.getMethod("exit");
        platformExitMethod.invoke(null);
    }

}
