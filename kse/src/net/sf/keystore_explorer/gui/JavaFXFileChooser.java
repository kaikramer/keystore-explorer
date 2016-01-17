package net.sf.keystore_explorer.gui;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import javax.swing.JFileChooser;

public class JavaFXFileChooser extends JFileChooser {

    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {

        // used for initializing javafx thread (ideally called once)
        Class.forName("javafx.embed.swing.JFXPanel").getConstructor().newInstance();

        Class<?> platformClass = Class.forName("javafx.application.Platform");
        Method runLaterMethod = platformClass.getMethod("runLater", Runnable.class);
        runLaterMethod.invoke(null, new Runnable() {
            @Override
            public void run() {
                try {
                    Class<?> extensionFilterClass = Class.forName("javafx.stage.FileChooser$ExtensionFilter");
                    Object extFilterJPG = extensionFilterClass.getConstructor(String.class, String[].class)
                            .newInstance("KeyStore files (*.jks,*.jceks)", new String[] { "*.jks", "*.jceks" });
                    Object extFilterPNG = extensionFilterClass.getConstructor(String.class, String[].class)
                            .newInstance("PKCS#12 files (*.p12, *.pfx)", new String[] { "*.p12", "*.pfx" });

                    // set extension filters
                    Class<?> fileChooserClass = Class.forName("javafx.stage.FileChooser");
                    Object fileChooser = fileChooserClass.getConstructor().newInstance();
                    Method getExtensionFiltersMethod = fileChooserClass.getMethod("getExtensionFilters");
                    List observableList = (List) getExtensionFiltersMethod.invoke(fileChooser);
                    observableList.add(extFilterPNG);
                    observableList.add(extFilterJPG);

                    // set window title
                    Method setTitleMethod = fileChooserClass.getMethod("setTitle", String.class);
                    setTitleMethod.invoke(fileChooser, "Open KeyStore File");

                    Class<?> windowClass = Class.forName("javafx.stage.Window");
                    Method showOpenDialogMethod = fileChooserClass.getMethod("showOpenDialog", windowClass);
                    Object file = showOpenDialogMethod.invoke(fileChooser, (Object) null);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

    }

}
