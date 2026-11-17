package com.sentinelai.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac

/**
 * Keeps the sensitive-findings gate verifier keyed by Android Keystore.
 * The PIN itself is never persisted in preferences or source control.
 */
object LocalSensitiveGate {
    private const val PREFS = "sentinel_sensitive_access"
    private const val VERIFIER = "pin_verifier"
    private const val KEY_ALIAS = "sentinel_sensitive_gate_hmac_v1"

    fun isConfigured(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(VERIFIER)

    fun setPin(context: Context, pin: String): Boolean {
        if (!validFormat(pin)) return false
        val key = getOrCreateKey()
        val verifier = hmac(key, pin)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(VERIFIER, verifier).apply()
        return true
    }

    fun verify(context: Context, pin: String): Boolean {
        if (!validFormat(pin)) return false
        val expected = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(VERIFIER, null) ?: return false
        val actual = runCatching { hmac(getOrCreateKey(), pin) }.getOrNull() ?: return false
        return constantTimeEquals(expected, actual)
    }

    private fun validFormat(pin: String) = pin.length in 6..64 && pin.all { it.isDigit() || it.isLetter() }

    private fun getOrCreateKey(): java.security.Key {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        store.getKey(KEY_ALIAS, null)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        return generator.generateKey()
    }

    private fun hmac(key: java.security.Key, value: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        return mac.doFinal(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}
