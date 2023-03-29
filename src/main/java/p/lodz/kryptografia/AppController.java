package p.lodz.kryptografia;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.ResourceBundle;

public class AppController implements Initializable {

    private final AES aes = new AES();

    byte[] text, cipherText;

    FileChooser fileChooser = new FileChooser();

    @FXML
    private TextField fileNameToSaveCipherText;

    @FXML
    private TextField fileNameToSaveText;

    @FXML
    private TextField fileNameKeyRead;

    @FXML
    private TextField fileNameKeySave;

    @FXML
    private Button saveCipherTextToFIleButton;

    @FXML
    private Button saveTextToFIleButton;

    @FXML
    private Button decryptButton;

    @FXML
    private Button encryptButton;

    @FXML
    private TextField fileNameCipherText;

    @FXML
    private TextField fileNameText;

    @FXML
    private Button generateKeyButton;

    @FXML
    private TextField keyText;

    @FXML
    private RadioButton radioButton128;

    @FXML
    private RadioButton radioButton192;

    @FXML
    private RadioButton radioButton256;

    @FXML
    private Button readCipherTextFileButton;

    @FXML
    private Button readTextFileButton;

    @FXML
    private TextArea textToDecrypt;

    @FXML
    private TextArea textToEncrypt;

    @FXML
    private Button readKeyFromFileButton;

    @FXML
    private Button saveKeyToFileButton;

    @FXML
    private RadioButton textRadioBox;

    @FXML
    private RadioButton fileRadioBox;

    @FXML
    void handleRadio128(ActionEvent event) {
        if(radioButton128.isSelected()){
            radioButton192.selectedProperty().set(false);
            radioButton256.selectedProperty().set(false);
        }
    }

    @FXML
    void handleRadio192(ActionEvent event) {
        if(radioButton192.isSelected()){
            radioButton128.selectedProperty().set(false);
            radioButton256.selectedProperty().set(false);
        }
    }

    @FXML
    void handleRadio256(ActionEvent event) {
        if(radioButton256.isSelected()){
            radioButton192.selectedProperty().set(false);
            radioButton128.selectedProperty().set(false);
        }
    }

    @FXML
    void handleRadioBoxFile(ActionEvent event) {
        if(fileRadioBox.isSelected()){
            textRadioBox.selectedProperty().set(false);
        }
    }

    @FXML
    void handleRadioBoxText(ActionEvent event) {
        if(textRadioBox.isSelected()){
            fileRadioBox.selectedProperty().set(false);
        }
    }

    @FXML
    void onActionReadCipherTextFileButton(ActionEvent event) {


        fileChooser.getExtensionFilters().setAll(
                new FileChooser.ExtensionFilter("ALL FILES", "*.*"));
        File file = fileChooser.showOpenDialog(null);
        if(file != null) {
            fileNameCipherText.setText(file.getAbsolutePath());
            try {
                cipherText = Helper.readFile(file.getAbsolutePath());
                textToDecrypt.setText(Helper.bytesToHex( cipherText));
            } catch (FileException e) {
                AlertWindow.messageWindow("Błąd pliku", "Błąd podczas wczytywania pliku", Alert.AlertType.WARNING);
            }
        }

    }

    @FXML
    void onActionReadTextFileButton(ActionEvent event) {

        fileChooser.getExtensionFilters().setAll(
                new FileChooser.ExtensionFilter("ALL FILES", "*.*"));
        File file = fileChooser.showOpenDialog(null);
        if(file != null) {
            fileNameText.setText(file.getAbsolutePath());
            try {
                text = Helper.readFile(file.getAbsolutePath());
                textToEncrypt.setText(new String(text));
            } catch (FileException e) {
                AlertWindow.messageWindow("Błąd pliku", "Błąd podczas wczytywania pliku", Alert.AlertType.WARNING);
            }
        }
    }

    @FXML
    void onActionReadKeyFromFile(ActionEvent event) {

        fileChooser.getExtensionFilters().setAll(
                new FileChooser.ExtensionFilter("AES KEY", "*.aes"));
        File file = fileChooser.showOpenDialog(null);
        if(file != null){
            fileNameKeyRead.setText(file.getAbsolutePath());
            try {
                byte[] key = Helper.readFile(file.getAbsolutePath());
                keyText.setText(Helper.bytesToHex(key));
            } catch (FileException e) {
                AlertWindow.messageWindow("Błąd pliku", "Błąd podczas zapisywania pliku", Alert.AlertType.WARNING);
            }
        }
    }

    @FXML
    void onActionSaveKeyToFile(ActionEvent event) {

        fileChooser.getExtensionFilters().setAll(
                new FileChooser.ExtensionFilter("AES KEY", "*.aes"));
        File file = fileChooser.showOpenDialog(null);
        if(file != null){
            fileNameKeySave.setText(file.getAbsolutePath());
            try {
                if(!keyText.getText().isEmpty() && checkKeySize()) {
                    Helper.saveFile(Helper.hexToBytes(keyText.getText()), file.getAbsolutePath());
                } else {
                    AlertWindow.messageWindow("Błąd zapisu", "Brak danych do zapisania w pliku", Alert.AlertType.WARNING);
                }
            } catch (FileException e) {
                AlertWindow.messageWindow("Błąd pliku", "Błąd podczas zapisywania pliku", Alert.AlertType.WARNING);
            }
        }
    }

    @FXML
    void onActionSaveCipherText(ActionEvent event) {

        fileChooser.getExtensionFilters().setAll(
                new FileChooser.ExtensionFilter("ALL FILES", "*.*"));
        File file = fileChooser.showOpenDialog(null);
        if(file != null){
            fileNameToSaveCipherText.setText(file.getAbsolutePath());
            try {
                if(fileRadioBox.isSelected()){
                    if (cipherText != null){
                        Helper.saveFile(cipherText,file.getAbsolutePath());
                    } else if(!textToDecrypt.getText().isEmpty()) {
                        Helper.saveFile(Helper.hexToBytes(textToDecrypt.getText()),file.getAbsolutePath());
                    } else {
                        AlertWindow.messageWindow("Błąd zapisu", "Brak danych do zapisania w pliku", Alert.AlertType.WARNING);
                    }

                } else {
                    if(!textToDecrypt.getText().isEmpty()){
                        Helper.saveFile(Helper.hexToBytes(textToDecrypt.getText()),file.getAbsolutePath());
                    } else {
                        AlertWindow.messageWindow("Błąd zapisu", "Brak danych do zapisania w pliku", Alert.AlertType.WARNING);
                    }

                }
            } catch (FileException e) {
                AlertWindow.messageWindow("Błąd pliku", "Błąd podczas zapisywania pliku", Alert.AlertType.WARNING);
            }
        }

    }

    @FXML
    void onActionSaveTextFile(ActionEvent event) {

        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("ALL FILES", "*.*"));
        File file = fileChooser.showOpenDialog(null);
        if(file != null){
            fileNameToSaveText.setText(file.getAbsolutePath());
            try {
                if(fileRadioBox.isSelected()){
                    if (text != null){
                        Helper.saveFile(text,file.getAbsolutePath());
                    } else if(!textToEncrypt.getText().isEmpty()) {
                        Helper.saveFile(textToEncrypt.getText().getBytes(),file.getAbsolutePath());
                    } else {
                        AlertWindow.messageWindow("Błąd zapisu", "Brak danych do zapisania w pliku", Alert.AlertType.WARNING);
                    }

                } else {
                    if(!textToEncrypt.getText().isEmpty()){
                        Helper.saveFile(textToEncrypt.getText().getBytes(),file.getAbsolutePath());
                    } else {
                        AlertWindow.messageWindow("Błąd zapisu", "Brak danych do zapisania w pliku", Alert.AlertType.WARNING);
                    }
                }

            } catch (FileException e) {
                AlertWindow.messageWindow("Błąd pliku", "Błąd podczas zapisywania pliku", Alert.AlertType.WARNING);
            }
        }

    }

    @FXML
    void onActionEncryptButton(ActionEvent event) {
        if(checkKeySize()) {
            if(fileRadioBox.isSelected()){
                byte[] keyBytes = Helper.hexToBytes(keyText.getText());
                cipherText = aes.encrypt(text, keyBytes);
                textToDecrypt.setText(Helper.bytesToHex(cipherText));
            } else {
                if(!textToEncrypt.getText().isEmpty()){
                    byte[] keyBytes = Helper.hexToBytes(keyText.getText());
                    cipherText = aes.encrypt(textToEncrypt.getText().getBytes(), keyBytes);
                    textToDecrypt.setText(Helper.bytesToHex(cipherText));
                } else {
                    AlertWindow.messageWindow("Błąd", "Pole z wiadomością do odszyfrowania jest puste", Alert.AlertType.ERROR);
                }
            }


        }

    }

    @FXML
    void onActionDecryptButton(ActionEvent event) {
        if(checkKeySize()) {
            if(fileRadioBox.isSelected()){
                byte[] keyBytes = Helper.hexToBytes(keyText.getText());
                text = aes.decrypt(cipherText, keyBytes);
                textToEncrypt.setText(new String(text));
            } else {
                if (!textToDecrypt.getText().isEmpty()) {
                    byte[] keyBytes = Helper.hexToBytes(keyText.getText());
                    text = aes.decrypt(Helper.hexToBytes(textToDecrypt.getText()), keyBytes);
                    textToEncrypt.setText(new String(text));
                } else {
                    AlertWindow.messageWindow("Błąd", "Pole z wiadomością do odszyfrowania jest puste", Alert.AlertType.ERROR);
                }
            }


        }

    }


    @FXML
    void onactionGenerateKey(ActionEvent event) {
        int keysize;
        if(radioButton128.isSelected()){
            keysize = 32;
        } else if(radioButton192.isSelected()){
            keysize = 48;
        } else {
            keysize = 64;
        }
        keyText.setText(getRandomHexString(keysize));
    }

    boolean checkKeySize() {
        int len = keyText.getText().length();

        if(len != 32 & len != 48 & len != 64){
            AlertWindow.messageWindow("Błąd", "Zład długość klucza", Alert.AlertType.ERROR);
            return false;
        }
        return true;
    }

    private String getRandomHexString(int numchars){
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, numchars);
    }


    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

        keyText.textProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                if(!(newValue.matches("^[A-Fa-f0-9]+$") || newValue.equals(""))){
                    keyText.setText(oldValue);
                }
            }
        });

    }
}