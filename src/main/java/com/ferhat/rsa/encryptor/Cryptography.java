package com.ferhat.rsa.encryptor;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

public class Cryptography {

    private Cipher cipher;
    private static final String SEPERATOR = "-";

    public Cryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance("RSA");
    }

    public PublicKey getPublic(String publicKeyXmlFilePath) throws Exception {
        File file = new File(publicKeyXmlFilePath);
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(file);
        String modulus = document.getElementsByTagName("Modulus").item(0).getTextContent();
        String exponent = document.getElementsByTagName("Exponent").item(0).getTextContent();

        byte[] modulusBytes = modulus.getBytes();
        byte[] expBytes = exponent.getBytes();
        KeyFactory rsaFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaKeyspec = new RSAPublicKeySpec(new BigInteger(modulusBytes), new BigInteger(expBytes));

        return rsaFactory.generatePublic(rsaKeyspec);
    }

    public void encryptString(File input, File output, PublicKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        List<String> lines = Files.readAllLines(input.toPath());

        List<String> encryptedLines = new ArrayList<>();

        for (String line : lines) {
            if (line.contains(SEPERATOR) && line.split(SEPERATOR).length == 2) {
                String[] lineArr = line.split(SEPERATOR);
                String id = lineArr[0];
                String inputStr = lineArr[1];
                String encryptedStr = Base64.encodeBase64String(cipher.doFinal(inputStr.getBytes()));
                encryptedLines.add(id + SEPERATOR + encryptedStr);
            }
        }

        writeToFile(output, encryptedLines);

    }

    private void writeToFile(File output, List<String> encryptedLines) throws IOException {
        PrintWriter printWriter = new PrintWriter(output);

        encryptedLines.forEach(encryptedLine -> {
            printWriter.write(encryptedLine);
            printWriter.write("\n");
        });
        printWriter.close();
    }

}
