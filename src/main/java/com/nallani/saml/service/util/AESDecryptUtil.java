package com.nallani.saml.service.util;

import com.nallani.saml.service.helper.GetPrivateKeyHelper;
import lombok.extern.java.Log;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.net.URLCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.Nonnull;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.nallani.saml.service.constants.Constants.AES_ALGORITHM;
import static com.nallani.saml.service.constants.Constants.RSA_ALGORITHM;

@Log
@Service
public class AESDecryptUtil {
    public static final Logger logger = LoggerFactory.getLogger(AESDecryptUtil.class);

    @Autowired
    private GetPrivateKeyHelper privateKeyHelper;

    @Value("${saml.aes.private.key}")
    private String aesPrivateKey;

    public String decrypt(@Nonnull final String encryptedData) {
        String result = null;
        try {
            // Decode tokens and split them
            final String[] tokens = new URLCodec().decode(encryptedData).split("\\|");
            // Decrypt key using RSA and then decrypt the data using decrypted key
            final byte[] decryptedData =
                    decrypt(
                            Base64.decodeBase64(tokens[1]),
                            decryptWithPrivateKey(Base64.decodeBase64(tokens[0])));
            result = new String(decryptedData);
        } catch (DecoderException
                | InvalidAlgorithmParameterException
                | NoSuchPaddingException
                | IllegalBlockSizeException
                | NoSuchAlgorithmException
                | BadPaddingException
                | InvalidKeyException e) {
        }
        return result;
    }

    private byte[] decryptWithPrivateKey(@Nonnull final byte[] encData)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher rsa = Cipher.getInstance(RSA_ALGORITHM);
        rsa.init(Cipher.DECRYPT_MODE, privateKeyHelper.getPrivateKey(aesPrivateKey));
        return rsa.doFinal(encData);
    }

    private byte[] decrypt(byte[] data, byte[] keyBytes)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        SecretKey key = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(keyBytes);
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // NOSONAR
        encryptCipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return encryptCipher.doFinal(data);
    }
}
