package com.sentinelai.mobile

import java.io.File
import java.util.zip.ZipFile

/**
 * Defensive static inspection of an APK's packaged text resources.
 * Secret values are never copied into findings; only the resource path and rule are reported.
 */
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
                while (entries.hasMoreElements() && inspected < 2500) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory || entry.size > 2_000_000L) continue
                    val ext = entry.name.substringAfterLast('.', "").lowercase()
                    if (ext !in textExtensions) continue
                    inspected++
                    val text = runCatching { zip.getInputStream(entry).bufferedReader(Charsets.UTF_8).use { it.readText() } }.getOrNull() ?: continue
                    for ((label, regex) in secretRules) {
                        val matches = regex.findAll(text).take(5).count()
                        if (matches > 0) findings += Finding(
                            "ALTO", "Posible $label en recurso empaquetado",
                            "Se detectó un patrón compatible en ${entry.name} ($matches coincidencia(s)). El valor no se muestra ni se extrae.",
                            "Revocar/rotar el secreto si es real, moverlo a un servicio backend y evitar incluir credenciales en el APK."
                        )
                    }
                    if (Regex("(?i)http://[A-Za-z0-9._:/?&=%#-]+").containsMatchIn(text)) {
                        findings += Finding(
                            "MEDIO", "URL HTTP sin cifrado",
                            "Se encontró una referencia http:// en ${entry.name}. Verifica si transmite datos sensibles.",
                            "Usar HTTPS y configurar Network Security Config para bloquear tráfico en claro."
                        )
                    }
                    val urls = Regex("https?://[A-Za-z0-9._-]+(?::[0-9]{2,5})?").findAll(text).map { it.value }.distinct().take(20).toList()
                    if (urls.isNotEmpty()) findings += Finding(
                        "INFORMATIVO", "Hosts y servicios referenciados",
                        "${urls.size} host(s) encontrados en ${entry.name}: ${urls.joinToString()}",
                        "Confirmar que cada host pertenezca al proveedor y esté dentro del alcance autorizado de auditoría."
                    )
                }
            }
        } catch (e: Exception) {
            findings += Finding("REVISAR", "No se pudo completar el análisis profundo", e.message ?: "Error leyendo el contenedor APK.", "Verificar que el archivo APK sea íntegro y legible.")
        }
        return findings.distinctBy { "${it.title}|${it.detail}" }
    }
}
