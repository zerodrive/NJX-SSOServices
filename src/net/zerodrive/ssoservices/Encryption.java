/*
 * Encryption.java
 * Version: 1.0
 * Copyright 2018 Thomas Schwade
 * http://www.zerodrive.net
 * Licensed under the EUPL V.1.1
 * https://github.com/zerodrive/NJX-SSOServices/blob/master/LICENSE.pdf
 */

package net.zerodrive.ssoservices;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Encryption {

	private final String CATALINA_BASE = "catalina.base";
	private final String CONFIG_DIR = "conf";
	private final String KEYSTORE = "keystore.jks";
	private final String KEYSTOREPASSFILE = "keystorepass";
	private final String KEYALIAS = "mykey";

	/*
	 * Use the public key of a given key pair to encrypt a string. Then
	 * convert the result to base64 representation.
	 */
	public String encrypt(String aString) throws EncryptionException {
		String strKeystore = getKeystorePath();
		try (FileInputStream is = new FileInputStream(strKeystore)) {
			try {
				KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
				keystore.load(is, null);
				try {
					Certificate cert = keystore.getCertificate(KEYALIAS);
					PublicKey publicKey = cert.getPublicKey();
					try {
						Cipher cipher = Cipher.getInstance("RSA");
						cipher.init(Cipher.PUBLIC_KEY, publicKey);
						byte[] encryptedBytes = cipher.doFinal(aString.getBytes());
						return Base64.getUrlEncoder().encodeToString(encryptedBytes);
					} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
							| IllegalBlockSizeException | BadPaddingException e) {
						throw (new EncryptionException("Encryption failed", e));
					}
				} catch (KeyStoreException e) {
					throw (new EncryptionException(
							"Public key for " + KEYALIAS + " not found in keystore " + strKeystore + ".", e));
				}
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
				throw (new EncryptionException("Keystore  " + strKeystore + " could not be loaded.", e));
			}
		} catch (FileNotFoundException e) {
			throw (new EncryptionException("Keystore file " + strKeystore + " could not be loaded.", e));
		} catch (IOException e) {
			throw (new EncryptionException("Keystore file " + strKeystore + " could not be closed.", e));
		}
	}

	/*
	 * Convert a string back from base64 representation. Then use the private key
	 * to decrypt the string.
	 */
	public String decrypt(String aString) throws EncryptionException {
		String strKeystore = getKeystorePath();
		byte[] decVal = java.util.Base64.getUrlDecoder().decode(aString);
		try (FileInputStream is = new FileInputStream(strKeystore);) {
			try {
				KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
				keystore.load(is, null);
				try {
					Key privateKey = keystore.getKey(KEYALIAS, getKeystorePass());
					if (privateKey instanceof PrivateKey) {
						try {
							Cipher cipher = Cipher.getInstance("RSA");
							cipher.init(Cipher.PRIVATE_KEY, privateKey);
							byte[] decryptedBytes = cipher.doFinal(decVal);
							return new String(decryptedBytes);
						} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
								| IllegalBlockSizeException | BadPaddingException e) {
							throw (new EncryptionException("Decryption failed", e));
						}
					} else {
						throw (new EncryptionException(
								"Private key for " + KEYALIAS + " not found in keystore " + strKeystore + "."));
					}
				} catch (UnrecoverableKeyException e) {
					throw (new EncryptionException(
							"Private key for " + KEYALIAS + " not found in keystore " + strKeystore + ".", e));
				}
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
				throw (new EncryptionException("Keystore  " + strKeystore + " could not be loaded.", e));
			}
		} catch (FileNotFoundException e) {
			throw (new EncryptionException("Keystore file " + strKeystore + " could not be loaded.", e));
		} catch (IOException e) {
			throw (new EncryptionException("Keystore file " + strKeystore + " could not be closed.", e));
		}
	}

	private String getKeystorePath() {
		File configDir = new File(System.getProperty(CATALINA_BASE), CONFIG_DIR);
		String path = configDir.getAbsolutePath() + File.separator + KEYSTORE;
		return path;
	}

	private char[] getKeystorePass() throws EncryptionException {
		File configDir = new File(System.getProperty(CATALINA_BASE), CONFIG_DIR);
		File configFile = new File(configDir, KEYSTOREPASSFILE);
		try (BufferedReader reader = new BufferedReader(new FileReader(configFile));) {
			String line;
			try {
				line = reader.readLine();
				char[] pass = line.toCharArray();
				line = null;
				return pass;
			} catch (IOException e) {
				throw (new EncryptionException("Password file could not be read.", e));
			}
		} catch (FileNotFoundException e) {
			throw (new EncryptionException("Password file could not be loaded.", e));
		} catch (IOException e) {
			throw (new EncryptionException("Password file could not be closed.", e));
		}
	}

}
