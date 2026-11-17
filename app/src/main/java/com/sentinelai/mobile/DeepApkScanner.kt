package com.sentinelai.mobile

import java.io.File
import java.util.zip.ZipFile

/** Local defensive APK inspection. Never emits secret values. */
object DeepApkScanner {
    private val textExtensions = setOf("xml", "json", "txt", "properties", "yml", "yaml", "js", "html", "htm", "cfg", "conf", "ini", "gradle", "kt", "java", "smali")
    private val secretRules = listOf(
        "Private key" to Regex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "AWS access key" to Regex("\\bAKIA[0-9A-Z]{16}\\b"),
        "Google API key" to Regex("\\bAIza[0-9A-Za-z_-]{30,}\\b"),
        "JWT token" to Regex("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"),
        "Credential assignment" to Regex("(?i)(?:password|passwd|client_secret|api_secret|access_token)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]"),
        "Bearer token" to Regex("(?i)authorization\\s*[:=]\\s*['\"]?bearer\\s+[A-Za-z0-9._~+/-]{16,}")
    )

    fun scan(apk: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries()
                var inspected = 0
                while (entries.hasMoreElements() && inspected < 5000) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory || entry.size > 30_000_000L) continue
                    val ext = entry.name.substringAfterLast('.', "").lowercase()
                    if (ext !in textExtensions && ext != "dex") continue
                    inspected++
                    val raw = runCatching { zip.getInputStream(entry).use { it.readBytes() } }.getOrNull() ?: continue
                    val text = if (ext == "dex") {
                        // DEX string data is commonly UTF-8/ASCII; extract printable runs without executing bytecode.
                        Regex("[ -~]{6,}").findAll(raw.toString(Charsets.ISO_8859_1)).joinToString("\\n") { it.value }
                    } else raw.toString(Charsets.UTF_8)
                    inspectText(entry.name, text, findings, ext == "dex")
                }
            }
        } catch (e: Exception) {
            findings += Finding("REVISAR", "No se pudo completar el análisis", e.message ?: "Error leyendo el APK.", "Verificar que el archivo APK sea íntegro.")
        }
        return findings.distinctBy { "${it.title}|${it.detail}" }
    }

    private fun inspectText(path: String, text: String, findings: MutableList<Finding>, dex: Boolean) {
        for ((label, regex) in secretRules) {
            val matches = regex.findAll(text).take(10).count()
            if (matches > 0) findings += Finding("ALTO", "Posible $label en ${if (dex) "código DEX" else "recurso"}",
                "Se detectaron $matches patrones en $path. El valor secreto no se muestra.",
                "Validar si es un secreto real, revocarlo si procede y trasladar credenciales al backend.")
        }
        if (Regex("(?i)http://[A-Za-z0-9._:/?&=%#-]+").containsMatchIn(text)) findings += Finding(
            "MEDIO", "Referencia HTTP sin cifrado", "Se encontró una URL http:// en $path.",
            "Verificar si transmite datos sensibles y migrar a HTTPS.")
        val urls = Regex("https?://[A-Za-z0-9._-]+(?::[0-9]{2,5})?").findAll(text).map { it.value }.distinct().take(30).toList()
        if (urls.isNotEmpty()) findings += Finding("INFORMATIVO", "Hosts/endpoints encontrados",
            "${urls.size} referencia(s) en $path: ${urls.joinToString()}",
            "Confirmar titularidad y alcance antes de realizar pruebas de red.")
    }
}
