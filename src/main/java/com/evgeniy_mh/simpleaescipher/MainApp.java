package main.java.com.evgeniy_mh.simpleaescipher;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class MainApp extends Application {

  @Override
  public void start(Stage stage) throws Exception {
    FXMLLoader loader = new FXMLLoader();
    loader.setLocation(getClass().getResource("/fxml/mainOverview.fxml"));
    AnchorPane rootOverview = (AnchorPane) loader.load();

    Scene scene = new Scene(rootOverview);
    stage.setTitle("AES Cipher");
    stage.setScene(scene);
    stage.show();

    MainController mc = loader.getController();
    mc.setMainApp(this);
  }

  public static void main(String[] args) {
    launch(args);
  }

}
