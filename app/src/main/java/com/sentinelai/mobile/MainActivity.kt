package com.sentinelai.mobile

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.io.File
import java.io.FileOutputStream

data class Finding(val severity: String, val title: String, val detail: String, val recommendation: String)
data class ApkReport(val appName: String, val packageName: String, val version: String, val permissions: List<String>, val findings: List<Finding>)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { SentinelScreen(onAnalyze = { uri -> analyzeApk(uri) }) }
    }

    private fun analyzeApk(uri: Uri): ApkReport {
        val apk = File(cacheDir, "audit-${System.currentTimeMillis()}.apk")
        contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "No se pudo leer el archivo seleccionado." }
            FileOutputStream(apk).use { output -> input.copyTo(output) }
        }
        try {
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
            val info: PackageInfo = if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getPackageArchiveInfo(apk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageArchiveInfo(apk.absolutePath, flags)
            } ?: error("Android no pudo leer el APK. Comprueba que sea válido.")

            val appInfo = info.applicationInfo
            val permissions = info.requestedPermissions?.toList().orEmpty()
            val findings = mutableListOf<Finding>()
            val sensitive = permissions.filter {
                it.contains("CAMERA") || it.contains("RECORD_AUDIO") || it.contains("READ_CONTACTS") ||
                it.contains("READ_SMS") || it.contains("ACCESS_FINE_LOCATION") || it.contains("READ_EXTERNAL_STORAGE") ||
                it.contains("READ_MEDIA")
            }
            if (sensitive.isNotEmpty()) findings += Finding(
                "REVISAR", "Permisos sensibles declarados",
                "El APK solicita: ${sensitive.joinToString { it.substringAfterLast('.') }}. Declararlos no demuestra abuso.",
                "Confirmar que cada permiso sea imprescindible y solicitarlo solo cuando haga falta."
            )
            if (appInfo != null && (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                findings += Finding("ALTO", "APK depurable", "La aplicación permite depuración.", "Desactivar android:debuggable en compilaciones de producción.")
            }
            val exported = info.activities?.count { it.exported }.orZero() +
                info.services?.count { it.exported }.orZero() +
                info.receivers?.count { it.exported }.orZero() +
                info.providers?.count { it.exported }.orZero()
            if (exported > 0) findings += Finding(
                "REVISAR", "Componentes Android exportados",
                "Se detectaron $exported componentes exportados. Esto no es automáticamente una vulnerabilidad.",
                "Revisar permisos, validación de llamadas y exposición necesaria de cada componente."
            )
            if (findings.isEmpty()) findings += Finding(
                "INFORMATIVO", "Sin señales básicas detectadas",
                "Las reglas iniciales no encontraron señales. Esto no certifica que el APK sea seguro.",
                "Continuar con revisión de código, configuración, dependencias y pruebas autorizadas."
            )
            val label = appInfo?.loadLabel(packageManager)?.toString()?.takeIf { it.isNotBlank() } ?: info.packageName.orEmpty()
            val version = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode.toString() else {
                @Suppress("DEPRECATION") info.versionCode.toString()
            }
            return ApkReport(label, info.packageName.orEmpty(), version, permissions, findings)
        } finally {
            apk.delete()
        }
    }

    private fun Int?.orZero(): Int = this ?: 0
}

@Composable
private fun SentinelScreen(onAnalyze: (Uri) -> ApkReport) {
    var report by remember { mutableStateOf<ApkReport?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            busy = true
            error = null
            try { report = onAnalyze(uri) } catch (e: Exception) { error = e.message ?: "No se pudo analizar el APK." }
            busy = false
        }
    }
    MaterialTheme(colorScheme = darkColorScheme(
        primary = androidx.compose.ui.graphics.Color(0xFF58D6C7),
        background = androidx.compose.ui.graphics.Color(0xFF0B1220),
        surface = androidx.compose.ui.graphics.Color(0xFF142033)
    )) {
        Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                item {
                    Text("SENTINEL AI", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    Text("Mobile Security Lab", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                    Text("Auditoría inicial de aplicaciones Android", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                item {
                    Card {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Análisis de APK", style = MaterialTheme.typography.titleLarge)
                            Text("Selecciona un APK para revisar metadatos, permisos y señales básicas. El análisis se procesa localmente.")
                            Button(onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                                Text(if (busy) "Analizando…" else "Seleccionar APK")
                            }
                        }
                    }
                }
                if (error != null) item { Text(error!!, color = MaterialTheme.colorScheme.error) }
                report?.let { result ->
                    item {
                        Card {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("Resultado del análisis", style = MaterialTheme.typography.titleLarge)
                                Text(result.appName, fontWeight = FontWeight.Bold)
                                Text(result.packageName)
                                Text("Versión: ${result.version}")
                                Text("Permisos declarados: ${result.permissions.size}")
                            }
                        }
                    }
                    items(result.findings) { finding ->
                        Card {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(finding.severity, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
                                Text(finding.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                                Text(finding.detail)
                                Text("Recomendación: ${finding.recommendation}", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                    item {
                        Text("Permisos declarados", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        result.permissions.forEach { Text("• ${it.substringAfterLast('.')}", style = MaterialTheme.typography.bodySmall) }
                    }
                }
                item {
                    Text("Alcance: análisis estático inicial. No explota vulnerabilidades ni prueba servidores. Las auditorías dinámicas requieren autorización escrita y entorno controlado.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
