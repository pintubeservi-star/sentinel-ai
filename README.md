# Sentinel AI

Aplicación Android para auditoría inicial de seguridad de aplicaciones móviles, con enfoque defensivo y pruebas autorizadas.

## Estado
Primera base Android (MVP): selección local de un APK, lectura de metadatos y revisión estática de señales de riesgo. No realiza explotación, no se conecta a servidores de terceros y no demuestra por sí sola que una vulnerabilidad sea explotable.

## Funciones iniciales
- Importar un APK mediante el selector del sistema.
- Leer nombre, paquete, versión y permisos declarados.
- Identificar señales que requieren revisión: permisos sensibles, componentes exportados, aplicación depurable.
- Mostrar hallazgos y recomendaciones.
- Procesar el APK localmente y eliminar la copia temporal al terminar.

## Compilar
GitHub Actions compila automáticamente al hacer push a main o manualmente. Descarga el artefacto sentinel-ai-debug-apk desde la ejecución del workflow.
Requiere JDK 17 y Gradle 8.9. Salida: app/build/outputs/apk/debug/app-debug.apk.

## Uso responsable
Analiza únicamente APK que tengas derecho a examinar. El análisis estático puede producir falsos positivos y no sustituye una auditoría profesional. Las pruebas dinámicas, de API o infraestructura requieren autorización escrita, alcance definido y entorno de pruebas.

## Próximas fases
Análisis profundo en entorno aislado, inventario de activos autorizados, pruebas controladas y generación de informes PDF.
