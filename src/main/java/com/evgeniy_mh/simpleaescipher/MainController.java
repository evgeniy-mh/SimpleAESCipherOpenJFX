package main.java.com.evgeniy_mh.simpleaescipher;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.Region;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.AES_CBCEncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.AES_CTREncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.CCM.Encrypt_and_MAC;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.CCM.Encrypt_then_MAC;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.CCM.MAC_then_Encrypt;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.ECBCEncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.HMACEncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.Nonce;

public class MainController {

  private Stage stage;
  private FileChooser fileChooser = new FileChooser();
  private MainApp mainApp;

  //AES-CTR tab
  private File originalFileAES;
  private File resultFileAES;
  private File keyFileAES;
  private File key2FileECBC;
  boolean usingCCM = false;

  @FXML
  TextField originalFilePathAES;
  @FXML
  TextArea originalFileTextAreaAES;
  @FXML
  Button createOriginalFileAES;
  @FXML
  Button openOriginalFileAES;
  @FXML
  Button saveOriginalFileAES;
  @FXML
  Button saveAsOriginalFileAES;
  @FXML
  TextField resultFilePathAES;
  @FXML
  TextArea resultFileTextAreaAES;
  @FXML
  Button createResultFileAES;
  @FXML
  Button openResultFileAES;
  @FXML
  Button saveAsResultFileAES;
  @FXML
  TextField keyTextFieldAES;
  @FXML
  Button openKeyFileAES;
  @FXML
  Button encryptButtonAES;
  @FXML
  Button decryptButtonAES;
  @FXML
  ChoiceBox<ChoiceBoxItem> CipherModeChioceBox;
  @FXML
  CheckBox CreateHMACCheckBox;
  @FXML
  CheckBox CreateECBCCheckBox;
  @FXML
  TextField key2TextFieldECBC;
  @FXML
  Button openKey2FileECBC;
  @FXML
  ProgressIndicator CipherProgressIndicator;

  @FXML
  ChoiceBox<ChoiceBoxItem> CCMChioceBox;
  @FXML
  ChoiceBox<ChoiceBoxItem> CCM_MACChioceBox;

  //HMAC tab
  File originalFileAES_HMACTab;
  File originalFileHMAC_HMACTab;
  File keyFileHMAC_HMACTab;

  @FXML
  TextField originalFileAESPath_HMACTab;
  @FXML
  Button openOriginalFileAESPath_HMACTab;
  @FXML
  TextField originalFileHMACPath_HMACTab;
  @FXML
  Button openOriginalFileHMACPath_HMACTab;
  @FXML
  Button openKeyFileHMAC_HMACTab;
  @FXML
  TextField keyTextFieldHMAC_HMACTab;
  @FXML
  Button checkHMACButton_HMACTab;

  //ECBC tab
  File originalFileAES_ECBCTab;
  File originalFileECBC_ECBCTab;
  File keyFileECBC_ECBCTab;
  File key2FileECBC_ECBCTab;

  @FXML
  TextField originalFileAESPath_ECBCTab;
  @FXML
  Button openOriginalFileAESPath_ECBCTab;
  @FXML
  TextField originalFileECBCPath_ECBCTab;
  @FXML
  Button openOriginalFileECBCPath_ECBCTab;
  @FXML
  Button openKeyFileECBC_ECBCTab;
  @FXML
  TextField keyTextFieldECBC_ECBCTab;
  @FXML
  Button openKey2FileECBC_ECBCTab;
  @FXML
  TextField key2TextFieldECBC_ECBCTab;
  @FXML
  Button checkECBCButton_ECBCTab;

  private AES_CTREncryptor mAES_CTREncryptor;
  private AES_CBCEncryptor mAES_CBCEncryptor;

  private MAC_then_Encrypt mMAC_then_Encrypt;
  private Encrypt_then_MAC mEncrypt_then_MAC;
  private Encrypt_and_MAC mEncrypt_and_MAC;

  private boolean canChangeOriginalFile = true;
  private final int MAX_FILE_TO_SHOW_SIZE = 5000;

  private HMACEncryptor mHMACEncryptor;
  private ECBCEncryptor mECBCEncryptor;

  public void setMainApp(MainApp mainApp) {
    this.mainApp = mainApp;
  }

  public void initialize() {
    mAES_CTREncryptor = new AES_CTREncryptor(CipherProgressIndicator);
    mAES_CBCEncryptor = new AES_CBCEncryptor(CipherProgressIndicator);
    mMAC_then_Encrypt = new MAC_then_Encrypt(CipherProgressIndicator);
    mEncrypt_then_MAC = new Encrypt_then_MAC(CipherProgressIndicator);
    mEncrypt_and_MAC = new Encrypt_and_MAC(CipherProgressIndicator);
    mHMACEncryptor = new HMACEncryptor();
    mECBCEncryptor = new ECBCEncryptor();

    fileChooser = new FileChooser();
    try {
      fileChooser.setInitialDirectory(new File(
          MainApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath())
          .getParentFile());
    } catch (URISyntaxException ex) {
      showExceptionToUser(ex, "Exception in initialize(). fileChooser.setInitialDirectory failed.");
      Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
    }

    initAESCTR_Tab();
    initECBC_Tab();
    initHMAC_Tab();
  }

  private void initAESCTR_Tab() {
    createOriginalFileAES.setOnAction((event) -> {
      File f = createNewFile("Сохраните новый исходный файл");
      if (f != null) {
        originalFileAES = f;
        updateFileInfo(originalFilePathAES, originalFileTextAreaAES, f);
      }
    });

    openOriginalFileAES.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        originalFileAES = f;
        updateFileInfo(originalFilePathAES, originalFileTextAreaAES, f);
        clearKey();
      }
    });

    saveOriginalFileAES.setOnAction((event) -> {
      if (canChangeOriginalFile) {
        FileUtils.saveFile(originalFileAES,
            originalFileTextAreaAES.getText().getBytes(StandardCharsets.UTF_8));
        updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
      }
    });

    saveAsOriginalFileAES.setOnAction((event) -> {
      if (canChangeOriginalFile) {
        byte[] bytesToSave;
        if (!originalFileTextAreaAES.getText().isEmpty()) {
          bytesToSave = originalFileTextAreaAES.getText().getBytes(StandardCharsets.UTF_8);
        } else {
          bytesToSave = "".getBytes(StandardCharsets.UTF_8);
        }
        saveAsFile(bytesToSave, "Сохраните новый исходный файл");
      } else {
        saveAsFile(originalFileAES, "Сохраните новый исходный файл");
      }
      updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
    });

    createResultFileAES.setOnAction((event) -> {
      File f = createNewFile("Сохраните новый файл результата");
      if (f != null) {
        resultFileAES = f;
        updateFileInfo(resultFilePathAES, resultFileTextAreaAES, f);
      }
    });

    openResultFileAES.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        resultFileAES = f;
        updateFileInfo(resultFilePathAES, resultFileTextAreaAES, f);

        clearKey();
      }
    });

    saveAsResultFileAES.setOnAction((event) -> {
      saveAsFile(resultFileAES, "Сохраните новый файл результата");
    });

    openKeyFileAES.setOnAction((event) -> {
      keyFileAES = openFile();
      if (keyFileAES != null) {
        keyTextFieldAES.setText(keyFileAES.getAbsolutePath());
        keyTextFieldAES.setEditable(false);
      }
    });

    keyTextFieldAES.setOnMouseClicked((event) -> {
      if (!keyTextFieldAES.isEditable()) {
        Alert alert = new Alert(AlertType.CONFIRMATION);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        alert.setTitle("Использовать поле ввода ключа?");
        alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

        System.out.println(alert.getTitle());

        Optional<ButtonType> result = alert.showAndWait();
        if (result.get() == ButtonType.OK) {
          clearKey();
        }
      }
    });

    encryptButtonAES.setOnAction((event) -> {
      encryptAES();
      Nonce.getInstance().IncNonce();
    });

    decryptButtonAES.setOnAction((event) -> {
      decryptAES();
    });

    CreateECBCCheckBox.setOnAction((event) -> {
      key2TextFieldECBC.setDisable(!CreateECBCCheckBox.isSelected());
      openKey2FileECBC.setDisable(!CreateECBCCheckBox.isSelected());
    });

    openKey2FileECBC.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        key2FileECBC = f;
        key2TextFieldECBC.setText(f.getPath());
      }
    });

    CipherModeChioceBox.setItems(FXCollections.observableArrayList(
        new ChoiceBoxItem(0, "CTR (Counter mode)"),
        new ChoiceBoxItem(1, "CBC (Cipher Block Chaining)")
    ));
    CipherModeChioceBox.getSelectionModel().selectFirst();

    CCMChioceBox.setItems(FXCollections.observableArrayList(
        new ChoiceBoxItem(0, "Не использовать AEAD"),
        new ChoiceBoxItem(1, "MAC-then-Encrypt"),
        new ChoiceBoxItem(2, "Encrypt-then-MAC"),
        new ChoiceBoxItem(3, "Encrypt-and-MAC")
    ));
    CCMChioceBox.getSelectionModel().selectFirst();
    usingCCM = false;

    CCMChioceBox.getSelectionModel().selectedItemProperty()
        .addListener(new ChangeListener<ChoiceBoxItem>() {
          @Override
          public void changed(ObservableValue<? extends ChoiceBoxItem> observable,
              ChoiceBoxItem oldValue, ChoiceBoxItem newValue) {
            setUsingCCM(newValue.id != 0);
          }
        });

    CCM_MACChioceBox.setItems(FXCollections.observableArrayList(
        new ChoiceBoxItem(0, "HMAC"),
        new ChoiceBoxItem(1, "ECBC")
    ));
    CCM_MACChioceBox.getSelectionModel().selectedItemProperty()
        .addListener(new ChangeListener<ChoiceBoxItem>() {
          @Override
          public void changed(ObservableValue<? extends ChoiceBoxItem> observable,
              ChoiceBoxItem oldValue, ChoiceBoxItem newValue) {
            key2TextFieldECBC.setDisable(newValue.id != 1);
          }
        });
    CCM_MACChioceBox.getSelectionModel().selectFirst();
    CCM_MACChioceBox.setDisable(true);
  }

  private void initECBC_Tab() {
    openOriginalFileAESPath_ECBCTab.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        originalFileAES_ECBCTab = f;
        originalFileAESPath_ECBCTab.setText(f.getPath());
      }
    });

    openOriginalFileECBCPath_ECBCTab.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        originalFileECBC_ECBCTab = f;
        originalFileECBCPath_ECBCTab.setText(f.getPath());
      }
    });

    openKeyFileECBC_ECBCTab.setOnAction((event) -> {
      keyFileECBC_ECBCTab = openFile();
      if (keyFileECBC_ECBCTab != null) {
        keyTextFieldECBC_ECBCTab.setText(keyFileECBC_ECBCTab.getAbsolutePath());
        keyTextFieldECBC_ECBCTab.setEditable(false);
      }
    });

    keyTextFieldECBC_ECBCTab.setOnMouseClicked((event) -> {
      if (!keyTextFieldECBC_ECBCTab.isEditable()) {
        Alert alert = new Alert(AlertType.CONFIRMATION);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        alert.setTitle("Использовать поле ввода ключа?");
        alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

        System.out.println(alert.getTitle());

        Optional<ButtonType> result = alert.showAndWait();
        if (result.get() == ButtonType.OK) {
          keyTextFieldECBC_ECBCTab.clear();
          keyTextFieldECBC_ECBCTab.setEditable(true);
          keyFileECBC_ECBCTab = null;
        }
      }
    });

    openKey2FileECBC_ECBCTab.setOnAction((event) -> {
      key2FileECBC_ECBCTab = openFile();
      if (key2FileECBC_ECBCTab != null) {
        key2TextFieldECBC_ECBCTab.setText(key2FileECBC_ECBCTab.getAbsolutePath());
        key2TextFieldECBC_ECBCTab.setEditable(false);
      }
    });

    key2TextFieldECBC_ECBCTab.setOnMouseClicked((event) -> {
      if (!key2TextFieldECBC_ECBCTab.isEditable()) {
        Alert alert = new Alert(AlertType.CONFIRMATION);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        alert.setTitle("Использовать поле ввода ключа?");
        alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

        System.out.println(alert.getTitle());

        Optional<ButtonType> result = alert.showAndWait();
        if (result.get() == ButtonType.OK) {
          key2TextFieldECBC_ECBCTab.clear();
          key2TextFieldECBC_ECBCTab.setEditable(true);
          key2FileECBC_ECBCTab = null;
        }
      }
    });

    checkECBCButton_ECBCTab.setOnAction((event) -> {
      checkECBC();
    });
  }

  private void initHMAC_Tab() {
    openOriginalFileAESPath_HMACTab.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        originalFileAES_HMACTab = f;
        originalFileAESPath_HMACTab.setText(f.getPath());
      }
    });

    openOriginalFileHMACPath_HMACTab.setOnAction((event) -> {
      File f = openFile();
      if (f != null) {
        originalFileHMAC_HMACTab = f;
        originalFileHMACPath_HMACTab.setText(f.getPath());
      }
    });

    openKeyFileHMAC_HMACTab.setOnAction((event) -> {
      keyFileHMAC_HMACTab = openFile();
      if (keyFileHMAC_HMACTab != null) {
        keyTextFieldHMAC_HMACTab.setText(keyFileHMAC_HMACTab.getAbsolutePath());
        keyTextFieldHMAC_HMACTab.setEditable(false);
      }
    });

    keyTextFieldHMAC_HMACTab.setOnMouseClicked((event) -> {
      if (!keyTextFieldHMAC_HMACTab.isEditable()) {
        Alert alert = new Alert(AlertType.CONFIRMATION);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        alert.setTitle("Использовать поле ввода ключа?");
        alert.setHeaderText("Вы желаете ввести ключ самостоятельно?");

        System.out.println(alert.getTitle());
        Optional<ButtonType> result = alert.showAndWait();
        if (result.get() == ButtonType.OK) {
          keyTextFieldHMAC_HMACTab.clear();
          keyTextFieldHMAC_HMACTab.setEditable(true);
          keyFileHMAC_HMACTab = null;
        }
      }
    });

    checkHMACButton_HMACTab.setOnAction((event) -> {
      checkHMAC();
    });
  }

  private void encryptAES() {
    Alert alert = new Alert(AlertType.WARNING);
    alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    if (originalFileAES == null) {
      alert.setTitle("Вы не выбрали исходный файл");
      alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл(1).");
      alert.showAndWait();
      return;
    } else if (resultFileAES == null) {
      alert.setTitle("Вы не выбрали файл результата ");
      alert.setHeaderText("Пожалуйста, создайте или выберите файл результата шифрования(2).");
      alert.showAndWait();
      return;
    } else if (getKey(keyTextFieldAES, keyFileAES) == null) {
      alert.setTitle("Ошибка ключа шифрования AES");
      alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
      alert.showAndWait();
      return;
    }
    System.out.println(alert.getTitle());

    Alert alertConfirm = new Alert(AlertType.CONFIRMATION);
    alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    alertConfirm.setTitle("Результирующий файл будет перезаписан!");
    alertConfirm
        .setHeaderText("Внимание, это перезапишет результирующий файл " + resultFileAES.getPath());

    System.out.println(alertConfirm.getTitle());
    Optional<ButtonType> result = alertConfirm.showAndWait();
    if (result.get() == ButtonType.OK) {

      Task AESTask = null;
      if (usingCCM) {
        MACOptions options = null;

        MACOptions.CipherMode mode = null;
        switch (CipherModeChioceBox.getValue().id) {
          case 0: //CTR
            mode = MACOptions.CipherMode.CTR;
            break;
          case 1: //CBC
            mode = MACOptions.CipherMode.CBC;
            break;
        }

        switch (CCM_MACChioceBox.getValue().id) {
          case 0: //HMAC
            options = new MACOptions(MACOptions.MACType.HMAC, mode,
                getKey(keyTextFieldAES, keyFileAES), null);
            break;
          case 1: //ECBC
            if (getKey(key2TextFieldECBC, key2FileECBC) == null) {
              alert.setTitle("Ошибка ключа шифрования ECBC");
              alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
              alert.showAndWait();
              return;
            }
            options = new MACOptions(MACOptions.MACType.ECBC, mode,
                getKey(keyTextFieldAES, keyFileAES), getKey(key2TextFieldECBC, key2FileECBC));
            break;
        }

        switch (CCMChioceBox.getValue().id) {
          case 1: //MAC-then-Encrypt
            AESTask = mMAC_then_Encrypt.encrypt(originalFileAES, resultFileAES, options);
            break;
          case 2: //Encrypt-then-MAC
            AESTask = mEncrypt_then_MAC.encrypt(originalFileAES, resultFileAES, options);
            break;
          case 3: //Encrypt-and-MAC
            AESTask = mEncrypt_and_MAC.encrypt(originalFileAES, resultFileAES, options);
            break;
        }

        AESTask.setOnSucceeded(value -> {
          updateFileInfo(resultFilePathAES, resultFileTextAreaAES, resultFileAES);
        });

      } else {

        switch (CipherModeChioceBox.getValue().id) {
          case 0: //CTR
            AESTask = mAES_CTREncryptor
                .encrypt(originalFileAES, resultFileAES, getKey(keyTextFieldAES, keyFileAES));
            break;
          case 1: //CBC
            AESTask = mAES_CBCEncryptor
                .encrypt(originalFileAES, resultFileAES, getKey(keyTextFieldAES, keyFileAES));
            break;
        }

        AESTask.setOnSucceeded(value -> {
          updateFileInfo(resultFilePathAES, resultFileTextAreaAES, resultFileAES);

          if (CreateHMACCheckBox.isSelected()) {
            File hmacFile = createNewFile("Создайте или выберите файл для сохранения HMAC");
            Task HMACTask = mHMACEncryptor
                .getHMAC(resultFileAES, hmacFile, getKey(keyTextFieldAES, keyFileAES));
            HMACTask.setOnSucceeded(event -> {
              Alert alertHMACDone = new Alert(AlertType.INFORMATION);
              alertHMACDone.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
              alertHMACDone.setTitle("HMAC файл создан");
              alertHMACDone.setHeaderText("HMAC файл создан, путь файла: " + hmacFile.getPath());
              alertHMACDone.show();
              System.out.println(alertHMACDone.getTitle());
            });
            HMACTask.run();
          }

          if (CreateECBCCheckBox.isSelected()) {
            if (getKey(key2TextFieldECBC, key2FileECBC) == null) {
              alert.setTitle("Ошибка ключа шифрования ECBC");
              alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
              alert.showAndWait();
              return;
            }
            File ecbcFile = createNewFile("Создайте или выберите файл для сохранения ECBC");
            Task ECBCTasc = mECBCEncryptor
                .getECBC(resultFileAES, ecbcFile, getKey(keyTextFieldAES, keyFileAES),
                    getKey(key2TextFieldECBC, key2FileECBC));
            ECBCTasc.setOnSucceeded(event -> {
              Alert alertECBCDone = new Alert(AlertType.INFORMATION);
              alertECBCDone.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
              alertECBCDone.setTitle("ECBC файл создан");
              alertECBCDone.setHeaderText("ECBC файл создан, путь файла: " + ecbcFile.getPath());
              alertECBCDone.show();
              System.out.println(alertECBCDone.getTitle());
            });
            ECBCTasc.run();
          }
        });
      }
      Thread AESThread = new Thread(AESTask);
      AESThread.start();
    }
  }

  private void decryptAES() {
    Alert alert = new Alert(AlertType.WARNING);
    alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    if (originalFileAES == null) {
      alert.setTitle("Вы не выбрали исходный файл");
      alert.setHeaderText("Пожалуйста, создайте или выберите исходный файл.");
      alert.showAndWait();
      return;
    } else if (resultFileAES == null) {
      alert.setTitle("Вы не выбрали зашифрованный файл");
      alert.setHeaderText("Пожалуйста, создайте или выберите зашифрованный файл.");
      alert.showAndWait();
      return;
    } else if (getKey(keyTextFieldAES, keyFileAES) == null) {
      alert.setTitle("Ошибка ключа шифрования AES");
      alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
      alert.showAndWait();
      return;
    }
    System.out.println(alert.getTitle());

    Alert alertConfirm = new Alert(AlertType.CONFIRMATION);
    alertConfirm.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    alertConfirm.setTitle("Оригинальный файл будет перезаписан!");
    alertConfirm
        .setHeaderText("Внимание, это перезапишет исходный файл " + originalFileAES.getPath());

    System.out.println(alertConfirm.getTitle());
    Optional<ButtonType> result = alertConfirm.showAndWait();
    if (result.get() == ButtonType.OK) {
      Task<Boolean> AESTask;
      if (usingCCM) {
        MACOptions options = null;

        MACOptions.CipherMode mode = null;
        switch (CipherModeChioceBox.getValue().id) {
          case 0: //CTR
            mode = MACOptions.CipherMode.CTR;
            break;
          case 1: //CBC
            mode = MACOptions.CipherMode.CBC;
            break;
        }

        switch (CCM_MACChioceBox.getValue().id) {
          case 0: //HMAC
            options = new MACOptions(MACOptions.MACType.HMAC, mode,
                getKey(keyTextFieldAES, keyFileAES), null);
            break;
          case 1: //ECBC
            if (getKey(key2TextFieldECBC, key2FileECBC) == null) {
              alert.setTitle("Ошибка ключа шифрования ECBC");
              alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
              alert.showAndWait();
              return;
            }
            options = new MACOptions(MACOptions.MACType.ECBC, mode,
                getKey(keyTextFieldAES, keyFileAES), getKey(key2TextFieldECBC, key2FileECBC));
            break;
        }

        switch (CCMChioceBox.getValue().id) {
          case 1: //MAC-then-Encrypt
            AESTask = mMAC_then_Encrypt.decrypt(resultFileAES, originalFileAES, options);
            break;
          case 2: //Encrypt-then-MAC
            AESTask = mEncrypt_then_MAC.decrypt(resultFileAES, originalFileAES, options);
            break;
          case 3: //Encrypt-and-MAC
            AESTask = mEncrypt_and_MAC.decrypt(resultFileAES, originalFileAES, options);
            ;
            break;
          default:
            AESTask = null;
            CommonUtils.reportExceptionToMainThread(new Exception(), "CCMChioceBox.getValue().id");
            break;
        }

        AESTask.setOnSucceeded(value -> {
          Alert MACAlert = new Alert(AlertType.INFORMATION);
          MACAlert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
          if (AESTask.getValue()) {
            MACAlert.setTitle("Проверка AEAD успешно пройдена");
            MACAlert.setHeaderText("Проверка AEAD успешно пройдена.");
          } else {
            MACAlert.setAlertType(AlertType.WARNING);
            MACAlert.setTitle("Внимание!");
            MACAlert.setHeaderText(
                "Проверка AEAD не пройдена. Возможно исходный файл или MAC были скомпрометированны!");
          }
          System.out.println(MACAlert.getTitle());
          MACAlert.showAndWait();

          updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
        });

      } else {

        switch (CipherModeChioceBox.getValue().id) {
          case 0: //CTR
            AESTask = mAES_CTREncryptor
                .decrypt(resultFileAES, originalFileAES, getKey(keyTextFieldAES, keyFileAES));
            break;
          case 1: //CBC
            AESTask = mAES_CBCEncryptor
                .decrypt(resultFileAES, originalFileAES, getKey(keyTextFieldAES, keyFileAES));
            break;
          default:
            AESTask = null;
            break;
        }

        AESTask.setOnSucceeded(value -> {
          updateFileInfo(originalFilePathAES, originalFileTextAreaAES, originalFileAES);
        });
      }
      Thread AESThread = new Thread(AESTask);
      AESThread.start();
    }
  }

  private void checkHMAC() {
    Alert alert = new Alert(AlertType.WARNING);
    alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    if (originalFileAES_HMACTab == null) {
      alert.setTitle("Вы не выбрали исходный зашифрованный AES файл");
      alert.setHeaderText("Пожалуйста, выберите исходный зашифрованный AES файл.");
      alert.showAndWait();
      return;
    } else if (originalFileHMAC_HMACTab == null) {
      alert.setTitle("Вы не выбрали файл HMAC");
      alert.setHeaderText("Пожалуйста, выберите файл HMAC.");
      alert.showAndWait();
      return;
    } else if (getKey(keyTextFieldHMAC_HMACTab, keyFileHMAC_HMACTab) == null) {
      alert.setTitle("Вы не выбрали или не ввели ключ HMAC");
      alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
      alert.showAndWait();
      return;
    }
    System.out.println(alert.getTitle());

    try {
      File tempHMAC = new File(originalFileHMAC_HMACTab.getAbsolutePath() + "_temp");
      tempHMAC.createNewFile();

      Task HMACTask = mHMACEncryptor.getHMAC(originalFileAES_HMACTab, tempHMAC,
          getKey(keyTextFieldHMAC_HMACTab, keyFileHMAC_HMACTab));
      HMACTask.setOnSucceeded(value -> {
        boolean eq = FileUtils.compareFiles(originalFileHMAC_HMACTab, tempHMAC);
        Alert alertConfirm = new Alert(AlertType.INFORMATION);
        alertConfirm.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        if (eq) {
          alertConfirm.setTitle("Проверка HMAC пройдена");
          alertConfirm.setHeaderText("Проверка HMAC пройдена");
        } else {
          alertConfirm.setAlertType(AlertType.WARNING);
          alertConfirm.setTitle("Проверка HMAC НЕ пройдена!");
          alertConfirm.setHeaderText("Проверка HMAC НЕ пройдена!");
        }
        System.out.println(alertConfirm.getTitle());
        alertConfirm.showAndWait();
        tempHMAC.delete();
      });
      Thread HMACThread = new Thread(HMACTask);
      HMACThread.start();

    } catch (IOException ex) {
      showExceptionToUser(ex, "checkHMAC()");
    }
  }

  private void checkECBC() {
    Alert alert = new Alert(AlertType.WARNING);
    alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    if (originalFileAES_ECBCTab == null) {
      alert.setTitle("Вы не выбрали исходный зашифрованный AES файл");
      alert.setHeaderText("Пожалуйста, выберите исходный зашифрованный AES файл.");
      alert.showAndWait();
      return;
    } else if (originalFileECBC_ECBCTab == null) {
      alert.setTitle("Вы не выбрали файл ECBC");
      alert.setHeaderText("Пожалуйста, выберите файл ECBC.");
      alert.showAndWait();
      return;
    } else if (getKey(keyTextFieldECBC_ECBCTab, keyFileECBC_ECBCTab) == null) {
      alert.setTitle("Вы не выбрали или не ввели ключ ECBC");
      alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
      alert.showAndWait();
    } else if (getKey(key2TextFieldECBC_ECBCTab, key2FileECBC_ECBCTab) == null) {
      alert.setTitle("Вы не выбрали или не ввели дополнительный ключ ECBC");
      alert.setHeaderText("Вы не ввели ключ или ввели ключ длина которого больше 128 бит.");
      alert.showAndWait();
      return;
    }
    System.out.println(alert.getTitle());

    try {
      File tempECBC = new File(originalFileECBC_ECBCTab.getAbsolutePath() + "_temp");
      tempECBC.createNewFile();

      Task ECBCTask = mECBCEncryptor.getECBC(originalFileAES_ECBCTab, tempECBC,
          getKey(keyTextFieldECBC_ECBCTab, keyFileECBC_ECBCTab),
          getKey(key2TextFieldECBC_ECBCTab, key2FileECBC_ECBCTab));

      ECBCTask.setOnSucceeded(value -> {
        boolean eq = FileUtils.compareFiles(originalFileECBC_ECBCTab, tempECBC);
        Alert alert2 = new Alert(AlertType.INFORMATION);
        alert2.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        if (eq) {
          alert2.setTitle("Проверка ECBC пройдена");
          alert2.setHeaderText("Проверка ECBC пройдена");
        } else {
          alert2.setAlertType(AlertType.WARNING);
          alert2.setTitle("Проверка ECBC НЕ пройдена!");
          alert2.setHeaderText("Проверка ECBC НЕ пройдена!");
        }
        System.out.println(alert2.getTitle());
        alert2.showAndWait();
        tempECBC.delete();
      });
      Thread ECBCThread = new Thread(ECBCTask);
      ECBCThread.start();

    } catch (IOException ex) {
      showExceptionToUser(ex, "checkECBC()");
    }
  }

  private File createNewFile(String dialogTitle) {
    fileChooser.setTitle(dialogTitle);
    File file = fileChooser.showSaveDialog(stage);
    if (file != null) {
      try {
        file.createNewFile();
      } catch (IOException ex) {
        showExceptionToUser(ex, "Exception in createNewFile");
        Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    return file;
  }

  private File openFile() {
    File file = fileChooser.showOpenDialog(stage);
    return file;
  }

  private File saveAsFile(byte[] fileBytes, String dialogTitle) {
    fileChooser.setTitle(dialogTitle);
    File file = fileChooser.showSaveDialog(stage);
    if (file != null) {
      FileUtils.saveFile(file, fileBytes);
    }
    return file;
  }

  private File saveAsFile(File fileToSave, String dialogTitle) {
    fileChooser.setTitle(dialogTitle);
    File newFile = fileChooser.showSaveDialog(stage);
    if (newFile != null) {
      try {
        Files.copy(fileToSave.toPath(), newFile.toPath());
      } catch (IOException ex) {
        showExceptionToUser(ex, "Exception in saveAsFile");
        Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    return newFile;
  }

  private void updateFileInfo(TextField pathTextField, TextArea contentTextArea, File file) {
    if (file != null) {
      try {
        pathTextField.setText(file.getCanonicalPath());

        if (file.length() < MAX_FILE_TO_SHOW_SIZE) {
          canChangeOriginalFile = true;
          saveOriginalFileAES.setDisable(false);
          originalFileTextAreaAES.setEditable(true);
          try {
            Thread.sleep(1000);
          } catch (InterruptedException ex) {
            showExceptionToUser(ex, "Exception in updateFileInfo");
          }
          String content = new String(Files.readAllBytes(file.toPath()));
          contentTextArea.setText(content);
        } else {
          canChangeOriginalFile = false;
          saveOriginalFileAES.setDisable(true);
          originalFileTextAreaAES.setEditable(false);
          contentTextArea.setText("Файл слишком большой для отображения.");
        }

      } catch (IOException ex) {
        showExceptionToUser(ex, "Exception in updateFileInfo");
        Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
      }
    } else {
      contentTextArea.setText("");
    }
  }

  private void clearKey() {
    keyTextFieldAES.clear();
    keyTextFieldAES.setEditable(true);
    keyFileAES = null;
  }

  private byte[] getKey(TextField keyTextField, File keyFile) {
    if (keyTextField.isEditable()) {
      byte[] key = keyTextField.getText().getBytes(StandardCharsets.UTF_8);
      if (key.length == 0 || key.length > 128) {
        return null;
      } else {
        return key;
      }
    } else {
      return FileUtils.readBytesFromFile(keyFile, 128);
    }
  }

  private void setUsingCCM(boolean isUsingCCM) {
    usingCCM = isUsingCCM;
    CCM_MACChioceBox.setDisable(!isUsingCCM);

    CreateHMACCheckBox.setDisable(usingCCM);
    CreateECBCCheckBox.setDisable(usingCCM);
  }

  public static void showExceptionToUser(Throwable e, String message) {
    Alert errorAlert = new Alert(AlertType.ERROR);
    errorAlert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
    errorAlert.setTitle("Exception!");
    StringWriter sw = new StringWriter();
    e.printStackTrace(new PrintWriter(sw));
    errorAlert.setContentText(message + "\n" + sw.toString());
    errorAlert.showAndWait();
  }
}
