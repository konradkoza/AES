package p.lodz.kryptografia;

import javafx.scene.control.Alert;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;

public class Helper {


    static public String getRandomHexString(int numchars){
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, numchars);
    }

    static public byte[] readFile(String fileName) throws FileException {
        byte[] result;

        try(FileInputStream fis = new FileInputStream(fileName)) {
            result = fis.readAllBytes();
        } catch (IOException e) {

            throw new FileException(e);
        }
        return result;
    }

    static public void saveFile(byte[] dane, String fileName) throws FileException {

        try(FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(dane);
        } catch (IOException e) {
            AlertWindow.messageWindow("Błąd pliku", "Błąd podczas zapisywania pliku", Alert.AlertType.WARNING);
            throw new FileException(e);
        }
    }

    static public byte[] hexToBytes(String text) {
        int len = text.length()/2;
        byte[] bytes = new byte[len];
        for (int i = 0; i < text.length(); i++) {
            int first = Character.digit(text.charAt(i++), 16);
            int second = Character.digit(text.charAt(i), 16);
            bytes[i/2] = (byte) ((first << 4) + second);
        }
        return bytes;
    }


    static public String bytesToHex(byte[] bytes) {
        StringBuilder hexText = new StringBuilder();
        String initial = null;
        char[] hexDigits = new char[2];
        for (int i = 0; i < bytes.length; i++) {
            byte next = bytes[i];

            hexDigits[0] = Character.forDigit((next >> 4) & 0xF, 16);
            hexDigits[1] = Character.forDigit((next & 0xF), 16);
            hexText.append(hexDigits);
        }
        initial = hexText.toString();

        return initial;
    }


}

