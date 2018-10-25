package com.ferhat.rsa.encryptor;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;

public class Main {
    public static void main(String[] args) throws Exception {
        Cryptography cryptography = new Cryptography();
        PublicKey publicKey = cryptography.getPublic(args[0]);

        if (new File(args[0]).exists()) {
            cryptography.encryptFile(cryptography.getFileInBytes(new File(args[1])), new File(args[2]), publicKey);
        } else {
            throw new IOException("FILE_NOT_FOUND");
        }
    }
}

