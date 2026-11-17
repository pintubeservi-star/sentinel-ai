package com.sentinelai.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

private data class AgentMessage(val role: String, val content: String)

@Composable
fun AgentChatPanel() {
    var baseUrl by remember { mutableStateOf("https://api.openai.com/v1") }
    var model by remember { mutableStateOf("gpt-4o-mini") }
    var apiKey by remember { mutableStateOf("") }
    var draft by remember { mutableStateOf("") }
    var messages by remember { mutableStateOf(listOf(
        AgentMessage("assistant", "Soy Sentinel, tu agente de IA. Puedo ayudarte a investigar, programar, analizar documentos y planificar tareas. Para responder con un modelo avanzado, configura un proveedor compatible con la API de chat.")
    )) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()

    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("SENTINEL · AGENTE IA", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text("Chat con contexto de conversación. La clave API se mantiene solo en memoria durante esta sesión y no se guarda en el APK ni en preferencias.")
            OutlinedTextField(baseUrl, { baseUrl = it }, label = { Text("URL base compatible (HTTPS)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(model, { model = it }, label = { Text("Modelo") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(apiKey, { apiKey = it }, label = { Text("Clave API del proveedor") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { apiKey = "" }) { Text("Borrar clave") }
                TextButton(onClick = { messages = messages.take(1); error = null }) { Text("Limpiar chat") }
            }
            HorizontalDivider()
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxWidth().heightIn(min = 180.dp, max = 380.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(messages) { message ->
                    Surface(
                        color = if (message.role == "user") MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                        shape = MaterialTheme.shapes.medium
                    ) {
                        Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text(if (message.role == "user") "TÚ" else "SENTINEL", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                            Text(message.content)
                        }
                    }
                }
            }
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                label = { Text("Escribe tu instrucción") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2
            )
            Button(
                onClick = {
                    val prompt = draft.trim()
                    if (prompt.isEmpty() || busy) return@Button
                    if (apiKey.isBlank()) { error = "Introduce la clave API de tu proveedor para activar el modelo."; return@Button }
                    val normalized = baseUrl.trim().trimEnd('/')
                    if (!normalized.startsWith("https://")) { error = "Por seguridad, el proveedor debe usar HTTPS."; return@Button }
                    val updated = messages + AgentMessage("user", prompt)
                    messages = updated
                    draft = ""
                    error = null
                    busy = true
                    scope.launch {
                        try {
                            val answer = withContext(Dispatchers.IO) {
                                requestChat(normalized, model.trim(), apiKey.trim(), updated.takeLast(20))
                            }
                            messages = messages + AgentMessage("assistant", answer)
                        } catch (e: Exception) {
                            error = e.message ?: "No se pudo completar la solicitud."
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && draft.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (busy) "Pensando…" else "Enviar instrucción") }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Text(
                "Aviso: esta primera versión es conversacional; todavía no ejecuta acciones autónomas en el dispositivo ni tiene acceso automático a GitHub, archivos o aplicaciones. Esas herramientas se añadirán con permisos y confirmaciones por acción.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun requestChat(baseUrl: String, model: String, apiKey: String, history: List<AgentMessage>): String {
    require(model.isNotBlank()) { "Indica el nombre del modelo." }
    val endpoint = URL("$baseUrl/chat/completions")
    val connection = (endpoint.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 20000
        readTimeout = 60000
        doOutput = true
        setRequestProperty("Authorization", "Bearer $apiKey")
        setRequestProperty("Content-Type", "application/json")
        setRequestProperty("Accept", "application/json")
    }
    try {
        val payload = JSONObject().apply {
            put("model", model)
            put("messages", JSONArray().apply {
                history.forEach { put(JSONObject().put("role", it.role).put("content", it.content)) }
            })
            put("temperature", 0.4)
        }
        connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (code !in 200..299) {
            val detail = runCatching { JSONObject(body).optJSONObject("error")?.optString("message") }.getOrNull()
            throw IllegalStateException(detail?.takeIf { it.isNotBlank() } ?: "El proveedor respondió HTTP $code.")
        }
        val root = JSONObject(body)
        return root.getJSONArray("choices").getJSONObject(0).getJSONObject("message").optString("content")
            .takeIf { it.isNotBlank() } ?: "El proveedor no devolvió texto."
    } finally {
        connection.disconnect()
    }
}
