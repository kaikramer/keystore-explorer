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

import org.kse.utilities.os.OperatingSystem;

public class JavaFXFileChooser extends JFileChooser {

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/resources");

	private static final long serialVersionUID = 706991877631924379L;

	static private Class<?> platformClass;
	static private Class<?> fileChooserClass;
	static private Class<?> extensionFilterClass;
	static private Class<?> windowClass;

	private static boolean fxAvailable = false;

	static {
		// check for availability and initialize javafx thread
		try {
			// disabled for Mac OS because there are incompatibilities between JavaFX file chooser and some mac tools
			if (!OperatingSystem.isMacOs()) {
				Class.forName("javafx.embed.swing.JFXPanel").getConstructor().newInstance();
				platformClass = Class.forName("javafx.application.Platform");
				fileChooserClass = Class.forName("javafx.stage.FileChooser");
				extensionFilterClass = Class.forName("javafx.stage.FileChooser$ExtensionFilter");
				windowClass = Class.forName("javafx.stage.Window");
				fxAvailable = true;
			}
		} catch (Exception e) {
			fxAvailable = false;
		}
	}

	private List<FileExtFilter> filters = new ArrayList<FileExtFilter>();
	private File selectedFile;
	private String dialogTitle;
	private File currentDirectory;

	public static boolean isFxAvailable() {
		return fxAvailable;
	}

	@Override
	public void addChoosableFileFilter(FileFilter filter) {
		if (filter instanceof FileExtFilter) {
			filters.add((FileExtFilter) filter);
		}
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
		currentDirectory = dir;
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
		// text of approve button cannot be changed in JavaFX FileChooser
		return showFxDialog(parent, "showOpenDialog");
	}

	@Override
	public int showOpenDialog(Component parent) throws HeadlessException {
		return showFxDialog(parent, "showOpenDialog");
	}

	@Override
	public int showSaveDialog(Component parent) throws HeadlessException {
		return showFxDialog(parent, "showSaveDialog");
	}

	public int showFxDialog(Component parent, final String method) throws HeadlessException {

		try {
			final Object fileChooser = fileChooserClass.getConstructor().newInstance();

			selectedFile = runLater(new Callable<File>() {

				@Override
				public File call() throws Exception {

					// set extension filters
					Method getExtensionFiltersMethod = fileChooserClass.getMethod("getExtensionFilters");
					List<Object> observableList = (List<Object>) getExtensionFiltersMethod.invoke(fileChooser);
					observableList.add(extensionFilterClass.getConstructor(String.class, String[].class)
							.newInstance(res.getString("JavaFXFileChooser.AllFiles"), new String[] { "*.*" }));

					for (FileExtFilter fileFilter : filters) {
						// convert format for extensions
						String[] extensions = fileFilter.getExtensions();
						for (int i = 0; i < extensions.length; i++) {
							if (!extensions[i].startsWith("*.")) {
								extensions[i] = "*." + extensions[i];
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
				}
			});
		} catch (Exception e) {
			return JFileChooser.ERROR_OPTION;
		}

		if (selectedFile == null) {
			return JFileChooser.CANCEL_OPTION;
		}

		return JFileChooser.APPROVE_OPTION;
	}


	public File runLater(final Callable<File> callable) throws Exception {

		final FutureTask<File> task = new FutureTask<File>(callable);

		Class<?> platformClass = Class.forName("javafx.application.Platform");
		Method runLaterMethod = platformClass.getMethod("runLater", Runnable.class);
		runLaterMethod.invoke(null, task);

		try {
			return task.get();
		} catch (ExecutionException ex) {
			throw new Exception(ex.getCause());
		}
	}

	public static void main(String[] args) throws NoSuchMethodException, SecurityException, IllegalAccessException,
	IllegalArgumentException, InvocationTargetException {

		if (!fxAvailable) {
			System.out.println("JavaFX not available");
			System.exit(1);
		}

		JavaFXFileChooser chooser = new JavaFXFileChooser();
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { ".jks" }, "Description1"));
		chooser.addChoosableFileFilter(new FileExtFilter(new String[] { ".p12" }, "Description2"));
		chooser.setDialogTitle("Dialog Titel");
		chooser.setCurrentDirectory(new File("."));
		chooser.setSelectedFile(new File(""));
		chooser.setMultiSelectionEnabled(false);
		chooser.showDialog(null, "Button Text");

		System.out.println(chooser.getSelectedFile().getAbsolutePath());

		Method platformExitMethod = platformClass.getMethod("exit");
		platformExitMethod.invoke(null);
	}

}
