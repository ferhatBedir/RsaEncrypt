import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

public class Cryptography {

    private Cipher cipher;

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

    public void encryptFile(byte[] input, File output, PublicKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    private void writeToFile(File output, byte[] toWrite) throws IOException {
        byte[] encryptFileBytes = Base64.encodeBase64(toWrite);
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(encryptFileBytes);
        fos.flush();
        fos.close();
    }

    public byte[] getFileInBytes(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }

}
