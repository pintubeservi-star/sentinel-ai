package com.sentinelai.mobile

import java.net.InetAddress
import java.net.URI
import javax.net.ssl.HttpsURLConnection

data class WebAuditReport(val host: String, val status: String, val findings: List<Finding>)

/**
 * Non-invasive, single-request HTTPS configuration review for an explicitly authorized host.
 * No crawling, brute force, payload injection, authentication bypass, or state-changing requests.
 */
object SafeWebAudit {
    fun audit(input: String): WebAuditReport {
        val uri = runCatching { URI(input.trim()) }.getOrElse { error("Introduce una URL válida, por ejemplo https://tu-dominio.com") }
        require(uri.scheme.equals("https", true)) { "Solo se permiten objetivos HTTPS." }
        require(uri.userInfo == null && uri.query == null && uri.fragment == null) { "Introduce solo el dominio HTTPS, sin credenciales, parámetros ni fragmentos." }
        val host = uri.host ?: error("No se reconoce el dominio.")
        require(!host.equals("localhost", true) && !host.endsWith(".local", true)) { "No se permiten destinos locales." }
        val addresses = InetAddress.getAllByName(host)
        require(addresses.isNotEmpty() && addresses.all { it.isAnyLocalAddress || it.isLoopbackAddress || it.isLinkLocalAddress || it.isSiteLocalAddress || it.isMulticastAddress }.not()) {
            "El dominio resuelve a una dirección privada o local; auditoría bloqueada."
        }
        val connection = (uri.toURL().openConnection() as HttpsURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 7000
            readTimeout = 7000
            instanceFollowRedirects = false
            setRequestProperty("User-Agent", "SentinelAI-Authorized-Security-Review/1.0")
            setRequestProperty("Range", "bytes=0-0")
        }
        try {
            val status = connection.responseCode
            val findings = mutableListOf<Finding>()
            val certs = connection.serverCertificates
            val cert = certs.firstOrNull() as? java.security.cert.X509Certificate
            if (cert != null) {
                val now = System.currentTimeMillis()
                if (now < cert.notBefore.time || now > cert.notAfter.time) findings += Finding("ALTO", "Certificado TLS fuera de vigencia",
                    "El certificado presentado por $host no está dentro de su periodo de validez.",
                    "Renovar y desplegar un certificado válido.")
                else findings += Finding("INFORMATIVO", "Certificado TLS válido en la conexión",
                    "Emisor: ${cert.issuerX500Principal.name}; vence: ${cert.notAfter}.",
                    "Mantener renovación automática y monitorización de expiración.")
            }
            val headers = mapOf(
                "Strict-Transport-Security" to "HSTS",
                "Content-Security-Policy" to "CSP",
                "X-Content-Type-Options" to "X-Content-Type-Options",
                "Referrer-Policy" to "Referrer-Policy",
                "Permissions-Policy" to "Permissions-Policy"
            )
            for ((header, label) in headers) {
                if (connection.getHeaderField(header).isNullOrBlank()) findings += Finding("MEDIO", "Falta cabecera $label",
                    "La respuesta inicial de $host no incluyó $header.",
                    "Evaluar y configurar la cabecera según el tipo de aplicación y sus compatibilidades.")
            }
            val server = connection.getHeaderField("Server")
            if (!server.isNullOrBlank()) findings += Finding("INFORMATIVO", "Cabecera Server expuesta",
                "El servidor revela el identificador: ${server.take(100)}.",
                "Considerar reducir la divulgación de versión/tecnología si no es necesaria.")
            val powered = connection.getHeaderField("X-Powered-By")
            if (!powered.isNullOrBlank()) findings += Finding("BAJO", "Tecnología declarada en cabecera",
                "X-Powered-By está presente.",
                "Eliminar cabeceras de tecnología que no sean necesarias.")
            if (findings.isEmpty()) findings += Finding("INFORMATIVO", "Revisión inicial sin alertas de cabeceras",
                "La respuesta HTTPS inicial no mostró los problemas configuracionales comprobados.",
                "Esto no equivale a una prueba de penetración ni certifica seguridad.")
            return WebAuditReport(host, "HTTP $status", findings)
        } finally {
            connection.disconnect()
        }
    }
}
