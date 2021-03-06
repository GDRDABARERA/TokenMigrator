/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.wso2.tokenmigrator;

import com.google.gson.Gson;
import org.apache.axiom.om.util.Base64;
import org.wso2.carbon.core.util.CipherHolder;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * Class related to Encrypt and Decrypt.
 */
public class EncryptDecryptUtils {

    /**
     * holds keystore.
     */
    private KeyStore decryptKeyStore = null;
    private KeyStore encryptKeyStore = null;
    private String decryptKeyStoreAlias = null;
    private String encryptKeyStoreAlias = null;
    private String decryptKeystorePassword = null;
    private Gson gson = new Gson();
    private static final char[] HEX_CHARACTERS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
            'C', 'D', 'E', 'F'};


    /**
     * Constructor initialize the keystore.
     * @param configFileLoader
     * @throws IOException input output file exception
     */
    public EncryptDecryptUtils(ConfigFileLoader configFileLoader)
            throws IOException {
        try {
            decryptKeyStore = KeyStore.getInstance("JKS");
            encryptKeyStore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        FileInputStream in = null;
        try {
            in = new FileInputStream(configFileLoader.getDecryptKeystoreLocation());
            decryptKeyStoreAlias = configFileLoader.getDecryptKeyStoreAlias();
            decryptKeystorePassword = configFileLoader.getDecryptKeyStorePassword();
            decryptKeyStore.load(in, decryptKeystorePassword.toCharArray());


            in = new FileInputStream(configFileLoader.getEncryptKeystoreLocation());
            encryptKeyStore.load(in, configFileLoader.getEncryptKeyStorePassword().toCharArray());
            encryptKeyStoreAlias = configFileLoader.getEncryptKeyStoreAlias();

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /**
     * encrypt the keys.
     * @param plaintext plain text key/token
     * @param encryptAlgorithm algorithm use for encryption
     * @return encrypted byte array
     * @throws Exception when encryption fails
     */
    public byte[] encrypt(String plaintext, String encryptAlgorithm) throws Exception {
        Certificate[] certs = encryptKeyStore.getCertificateChain(encryptKeyStoreAlias);
        Cipher cipher;
        byte[] encryptedText;

        if (encryptAlgorithm.isEmpty() || encryptAlgorithm.equals("RSA/ECB/OAEPwithSHA1andMGF1Padding")) {
            System.out.println("Encoding : " + plaintext + " using Algo : RSA/ECB/OAEPwithSHA1andMGF1Padding ");
            cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding", "BC");
            byte [] convertedByteToken = plaintext.getBytes(Charset.defaultCharset());

            cipher.init(Cipher.ENCRYPT_MODE, certs[0].getPublicKey());
            encryptedText = cipher.doFinal(plaintext.getBytes());
            encryptedText = createSelfContainedCiphertext(encryptedText,
                    "RSA/ECB/OAEPwithSHA1andMGF1Padding",
                    certs[0]);
//            System.out.println("Encoded : " + encryptedText);



        } else {
            cipher = Cipher.getInstance(encryptAlgorithm, "BC");
            System.out.println("Encoding : " + plaintext + " using Algo : " + encryptAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, certs[0].getPublicKey());
            encryptedText = cipher.doFinal(plaintext.getBytes());

        }


        System.out.println("LOG: Encryption is successful");
        return encryptedText;
    }

  /**
     * Decrypt the byte array.
     * @param CIP byte array contains encrypted text
     * @param decryptAlgorithm algorithm to decrypt
     * @return decrypted key
     * @throws Exception when unable to decrypt
     */
    public String decrypt(byte[] CIP, String decryptAlgorithm) throws Exception {

       PrivateKey privateKey = (PrivateKey) decryptKeyStore.getKey(decryptKeyStoreAlias, decryptKeystorePassword
           .toCharArray());

        Cipher cipher;
        byte[] cipherText;

        if (decryptAlgorithm.isEmpty() || decryptAlgorithm.equals("RSA/ECB/OAEPwithSHA1andMGF1Padding")) {
            cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding","BC");
            String cipherStr = new String(CIP, Charset.defaultCharset());
            System.out.println(cipherStr);
            CipherHolder cipherholder = gson.fromJson(cipherStr, CipherHolder.class);
            String text = cipherholder.getCipherText();
            System.out.println("The cipher text: " + text);
            cipherText =cipherholder.getCipherBase64Decoded();
        } else {
            cipher = Cipher.getInstance(decryptAlgorithm, "BC");
            cipherText = CIP;
        }

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherByte = null;
        if (cipherText.length == 0) {
            cipherByte = "".getBytes();
            System.out.println("Empty value for plainTextBytes null will persist to DB");
        } else {
            cipherByte = cipher.doFinal(cipherText);
        }

        System.out.println("LOG: decryption process successful");
        return new String(cipherByte);
    }

    /**
     * This function will create self-contained ciphertext with metadata
     *
     * @param originalCipher ciphertext need to wrap with metadata
     * @param transformation transformation used to encrypt ciphertext
     * @param certificate certificate that holds relevant keys used to encrypt
     * @return setf-contained ciphertext
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    public byte[] createSelfContainedCiphertext(byte[] originalCipher, String transformation, Certificate certificate)
            throws CertificateEncodingException, NoSuchAlgorithmException {

        CipherHolder cipherHolder = new CipherHolder();
        cipherHolder.setCipherText(Base64.encode(originalCipher));
        cipherHolder.setTransformation(transformation);
        cipherHolder.setThumbPrint(calculateThumbprint(certificate, "SHA-1"), "SHA-1");
        String cipherWithMetadataStr = gson.toJson(cipherHolder);

        System.out.println("Cipher with meta data : " + cipherWithMetadataStr);

        return cipherWithMetadataStr.getBytes(Charset.defaultCharset());
    }

    private String calculateThumbprint(Certificate certificate, String digest)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        MessageDigest messageDigest = MessageDigest.getInstance(digest);
        messageDigest.update(certificate.getEncoded());
        byte[] digestByteArray = messageDigest.digest();

        //convert digest in form of byte array to hex format
        StringBuffer strBuffer = new StringBuffer();

        for (int i = 0; i < digestByteArray.length; i++) {
            int leftNibble = (digestByteArray[i] & 0xF0) >> 4;
            int rightNibble = (digestByteArray[i] & 0x0F);
            strBuffer.append(HEX_CHARACTERS[leftNibble]).append(HEX_CHARACTERS[rightNibble]);
        }

        return strBuffer.toString();
    }

}
