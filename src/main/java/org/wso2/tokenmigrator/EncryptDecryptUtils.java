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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
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
    private static final Log log = LogFactory.getLog(EncryptDecryptUtils.class);

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
        if (encryptAlgorithm.isEmpty()) {
            cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding", "BC");
        } else {
            cipher = Cipher.getInstance(encryptAlgorithm, "BC");
        }
        cipher.init(Cipher.ENCRYPT_MODE, certs[0].getPublicKey());

        log.info("encryption successful");
        return cipher.doFinal(plaintext.getBytes());
    }

  /**
     * Decrypt the byte array.
     * @param ciphertext byte array contains encrypted text
     * @param decryptAlgorithm algorithm to decrypt
     * @return decrypted key
     * @throws Exception when unable to decrypt
     */
    public String decrypt(byte[] ciphertext, String decryptAlgorithm) throws Exception {
       PrivateKey privateKey = (PrivateKey) decryptKeyStore.getKey(decryptKeyStoreAlias, decryptKeystorePassword
           .toCharArray());
        Cipher cipher;
        if (decryptAlgorithm.isEmpty()) {
            cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding", "BC");
        } else {
            cipher = Cipher.getInstance(decryptAlgorithm, "BC");
        }
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherbyte = cipher.doFinal(ciphertext);
        log.info("decryption successful");
        return new String(cipherbyte);
    }

}
