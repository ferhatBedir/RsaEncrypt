package com.ferhat.rsa.encryptor;

import java.io.File;
import java.security.PublicKey;

public class Main {

    public static void main(String[] args) throws Exception {
        Cryptography cryptography = new Cryptography();
        PublicKey publicKey = cryptography.getPublic(args[1]);
        cryptography.encryptString(new File(args[0]), new File(args[2]), publicKey);

    }
}

