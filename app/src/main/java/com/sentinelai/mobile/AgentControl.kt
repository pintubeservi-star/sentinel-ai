package com.sentinelai.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

private enum class TaskState { DRAFT, PLANNED, RUNNING, AWAITING_APPROVAL, COMPLETED, STOPPED, FAILED }
private enum class StepState { PENDING, RUNNING, AWAITING_APPROVAL, DONE, BLOCKED }

private data class AgentOrder(
    val id: String = UUID.randomUUID().toString(),
    val controller: String,
    val objective: String,
    val scope: String,
    val successMetric: String,
    val state: TaskState = TaskState.DRAFT,
    val steps: List<AgentStep>,
    val log: List<String> = emptyList()
)
private data class AgentStep(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val rationale: String,
    val requiresApproval: Boolean = false,
    val state: StepState = StepState.PENDING
)

private object AgentTaskEngine {
    fun create(controller: String, objective: String, scope: String, metric: String): AgentOrder {
        require(controller.isNotBlank()) { "Indica el identificador del controlador." }
        require(objective.isNotBlank()) { "Describe el objetivo." }
        require(scope.isNotBlank()) { "Define las tareas permitidas." }
        val normalized = scope.split(",", ";", "\n").map { it.trim() }.filter { it.isNotBlank() }
        require(normalized.isNotEmpty()) { "Añade al menos una tarea autorizada." }
        val steps = listOf(
            AgentStep(title = "Validar orden y alcance", rationale = "Comprobar que el objetivo y las tareas estén definidos."),
            AgentStep(title = "Preparar plan operativo", rationale = "Ordenar las tareas autorizadas y sus dependencias."),
            AgentStep(title = "Identificar riesgos y aprobaciones", rationale = "Marcar acciones ambiguas, sensibles o irreversibles.", requiresApproval = true),
            AgentStep(title = "Ejecutar tareas autorizadas", rationale = "Ejecutar únicamente mediante herramientas registradas y dentro del alcance."),
            AgentStep(title = "Verificar criterio de éxito", rationale = "Contrastar evidencias con la métrica indicada."),
            AgentStep(title = "Entregar informe", rationale = "Documentar resultados, supuestos, riesgos y decisiones.")
        )
        return AgentOrder(
            controller = controller.trim(), objective = objective.trim(),
            scope = normalized.joinToString("\n") { "• $it" },
            successMetric = metric.trim().ifBlank { "Resultado verificable documentado" },
            steps = steps,
            log = listOf("Orden recibida; pendiente de validación de identidad del controlador.")
        )
    }

    fun start(order: AgentOrder): AgentOrder {
        require(order.state == TaskState.DRAFT || order.state == TaskState.PLANNED) { "La orden no está disponible para iniciar." }
        return order.copy(state = TaskState.RUNNING, log = order.log + "Plan preparado. No se han ejecutado acciones externas.")
    }

    fun advance(order: AgentOrder): AgentOrder {
        require(order.state == TaskState.RUNNING) { "La tarea no está en ejecución." }
        val index = order.steps.indexOfFirst { it.state != StepState.DONE }
        if (index < 0) return order.copy(state = TaskState.COMPLETED)
        val step = order.steps[index]
        if (step.requiresApproval) {
            val updated = order.steps.toMutableList()
            updated[index] = step.copy(state = StepState.AWAITING_APPROVAL)
            return order.copy(state = TaskState.AWAITING_APPROVAL, steps = updated,
                log = order.log + "Escalado: aprobación humana requerida antes de continuar.")
        }
        val updated = order.steps.toMutableList()
        updated[index] = step.copy(state = StepState.DONE)
        val finished = updated.all { it.state == StepState.DONE }
        return order.copy(state = if (finished) TaskState.COMPLETED else TaskState.RUNNING,
            steps = updated, log = order.log + "Paso de planificación completado: ${step.title}.")
    }

    fun approve(order: AgentOrder): AgentOrder {
        require(order.state == TaskState.AWAITING_APPROVAL) { "No hay una aprobación pendiente." }
        val updated = order.steps.map { if (it.state == StepState.AWAITING_APPROVAL) it.copy(state = StepState.DONE) else it }
        return order.copy(state = TaskState.RUNNING, steps = updated,
            log = order.log + "Aprobación registrada localmente. La ejecución real sigue limitada a herramientas integradas.")
    }

    fun stop(order: AgentOrder, reason: String): AgentOrder =
        order.copy(state = TaskState.STOPPED, log = order.log + "Detención solicitada: ${reason.ifBlank { "sin motivo indicado" }}.")
}

@Composable
fun AgentControlPanel() {
    var controller by remember { mutableStateOf("controlador-autorizado") }
    var objective by remember { mutableStateOf("") }
    var scopeText by remember { mutableStateOf("Analizar APK seleccionado, generar hallazgos y recomendaciones") }
    var metric by remember { mutableStateOf("Informe con hallazgos verificables y SHA-256") }
    var order by remember { mutableStateOf<AgentOrder?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("CENTRO DE CONTROL · SENTINEL", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text("El controlador define el objetivo y el alcance. El agente organiza el trabajo, registra decisiones y escala los puntos críticos.")
            OutlinedTextField(controller, { controller = it }, label = { Text("Identificador del controlador") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(objective, { objective = it }, label = { Text("Objetivo concreto y medible") }, minLines = 2, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(scopeText, { scopeText = it }, label = { Text("Autonomía permitida (separa tareas con coma)") }, minLines = 3, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(metric, { metric = it }, label = { Text("Criterio de éxito") }, minLines = 2, modifier = Modifier.fillMaxWidth())
            Button(onClick = {
                error = null
                order = runCatching { AgentTaskEngine.create(controller, objective, scopeText, metric) }.getOrElse {
                    error = it.message ?: "No se pudo crear la orden."
                    null
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Recibir orden del controlador") }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

            order?.let { current ->
                HorizontalDivider()
                Text("ORDEN ${current.id.take(8)}", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                Text(current.objective, fontWeight = FontWeight.Bold)
                Text("Controlador: ${current.controller}")
                Text("Estado: ${current.state}")
                Text("Alcance autorizado:\n${current.scope}")
                Text("Éxito: ${current.successMetric}")
                Text("Plan del agente", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                current.steps.forEachIndexed { index, step ->
                    ListItem(
                        headlineContent = { Text("${index + 1}. ${step.title}") },
                        supportingContent = { Text("${step.rationale}\nEstado: ${step.state}") },
                        trailingContent = { if (step.requiresApproval) Text("REVISIÓN", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall) }
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { order = runCatching { AgentTaskEngine.start(current) }.getOrElse { error = it.message; current } },
                        enabled = current.state == TaskState.DRAFT || current.state == TaskState.PLANNED,
                        modifier = Modifier.weight(1f)) { Text("Iniciar plan") }
                    OutlinedButton(onClick = { order = runCatching { AgentTaskEngine.advance(current) }.getOrElse { error = it.message; current } },
                        enabled = current.state == TaskState.RUNNING, modifier = Modifier.weight(1f)) { Text("Siguiente paso") }
                }
                if (current.state == TaskState.AWAITING_APPROVAL) {
                    Text("Este punto requiere revisión humana antes de continuar.", color = MaterialTheme.colorScheme.error)
                    Button(onClick = { order = AgentTaskEngine.approve(current) }, modifier = Modifier.fillMaxWidth()) { Text("Registrar aprobación y continuar") }
                }
                OutlinedButton(onClick = { order = AgentTaskEngine.stop(current, "Detención del controlador") },
                    enabled = current.state != TaskState.COMPLETED && current.state != TaskState.STOPPED,
                    modifier = Modifier.fillMaxWidth()) { Text("Detener tarea") }
                Text("Registro de auditoría", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                current.log.reversed().forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
            Text(
                "Límite de esta versión: el motor implementa recepción de órdenes, planificación, estados, escalado y registro local. Todavía no autentica criptográficamente al controlador ni ejecuta herramientas externas de forma autónoma; los botones avanzan el flujo de planificación, no realizan operaciones sobre sistemas.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
