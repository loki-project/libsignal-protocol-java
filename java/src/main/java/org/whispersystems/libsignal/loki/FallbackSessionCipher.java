package org.whispersystems.libsignal.loki;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.libsignal.util.Hex;

/**
 * A session cipher that uses the current user's private key along with a contact's public key to encrypt data.
 */
public final class FallbackSessionCipher {

    public static final int SESSION_VERSION = 3;

    private byte[] symmetricKey;

    public FallbackSessionCipher(byte[] userPrivateKey, String hexEncodedContactPublicKey) {
        try {
            String stringPublicKey = hexEncodedContactPublicKey;
            if (stringPublicKey.length() > 64 && stringPublicKey.startsWith("05")) {
                stringPublicKey = stringPublicKey.substring(2);
            }
            byte[] contactPublicKey = Hex.fromStringCondensed(stringPublicKey);
            Curve25519 curve25519 = Curve25519.getInstance(Curve25519.BEST);
            symmetricKey = curve25519.calculateAgreement(contactPublicKey, userPrivateKey);
        } catch (Exception e) {
            symmetricKey = null;
        }
    }

    public byte[] encrypt(byte[] paddedMessageBody) {
        if (symmetricKey == null) { return null; }
        try {
            return DiffieHellman.encrypt(paddedMessageBody, symmetricKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decrypt(byte[] bytes) {
        if (symmetricKey == null) { return null; }
        try {
            return DiffieHellman.decrypt(bytes, symmetricKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
