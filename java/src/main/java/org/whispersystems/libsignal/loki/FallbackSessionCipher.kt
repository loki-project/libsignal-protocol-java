package org.whispersystems.libsignal.loki

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.util.Hex

/**
 * A session cipher that uses the current user's private key along with a contact's public key to encrypt data.
 */
class FallbackSessionCipher(private val userPrivateKey: ByteArray, private val hexEncodedContactPublicKey: String) {

  // region Convenience
  private val contactPublicKey by lazy {
    val hexEncodedContactPublicKey = if (hexEncodedContactPublicKey.length > 64) hexEncodedContactPublicKey.removePrefix("05") else hexEncodedContactPublicKey
    Hex.fromStringCondensed(hexEncodedContactPublicKey)
  }

  private val symmetricKey: ByteArray?
    get() {
      return try {
        val curve = Curve25519.getInstance(Curve25519.BEST)
        curve.calculateAgreement(contactPublicKey, userPrivateKey)
      } catch (e: Exception) {
        e.printStackTrace()
        null
      }
    }
  // endregion

  // region Settings
  companion object {
    val sessionVersion = 3
  }
  // endregion

  // region Encryption
  fun encrypt(paddedMessageBody: ByteArray): ByteArray? {
    val symmetricKey = symmetricKey ?: return null
    return try {
       DiffieHellman.encrypt(paddedMessageBody, symmetricKey)
    } catch (e: Exception) {
      e.printStackTrace()
      null
    }
  }
  // endregion

  // region Decryption
  fun decrypt(bytes: ByteArray): ByteArray? {
    val symmetricKey = symmetricKey ?: return null
    return try {
      DiffieHellman.decrypt(bytes, symmetricKey)
    } catch (e: Exception) {
      e.printStackTrace()
      null
    }
  }
  // endregion
}