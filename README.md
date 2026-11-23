# CyberShield MVP

Aplicación web académica para registrar activos, comprobar puertos TCP, generar alertas y consultar métricas, basada en los cinco casos de uso del documento del MVP.

## Requisitos
- Python 3.10 o superior
- Windows, Linux o macOS
- Conexión a Internet solo para cargar las fuentes visuales externas (Google Fonts y Chart.js no son necesarias para las funciones principales).

## Instalación en Windows
1. Extrae el ZIP en una carpeta, por ejemplo `C:\CyberShield`.
2. Abre CMD o PowerShell dentro de esa carpeta.
3. Crea un entorno virtual:
   ```bash
   py -m venv venv
   ```
4. Actívalo:
   ```bash
   venv\Scripts\activate
   ```
5. Instala dependencias:
   ```bash
   pip install -r requirements.txt
   ```
6. Ejecuta:
   ```bash
   python app.py
   ```
7. Abre en el navegador: http://127.0.0.1:5000

## Credenciales iniciales
- Usuario: `admin`
- Contraseña: `Admin123!`

Cambia la contraseña inicial antes de cualquier uso fuera de una demostración local. Para el MVP académico, la contraseña se almacena con hash seguro; la interfaz de cambio de contraseña y recuperación no están incluidas en el alcance entregado.

## Cómo probarlo
1. Inicia sesión.
2. En **Equipos protegidos**, registra un nombre y una IP privada autorizada. Para una prueba local puedes usar `127.0.0.1`.
3. Abre **Escáner de puertos** y selecciona el equipo.
4. Revisa los puertos abiertos y las alertas generadas.
5. En **Alertas de seguridad**, marca una alerta como atendida.
6. Vuelve al panel general para consultar las métricas.

## Alcance funcional implementado
- CU-01: inicio de sesión de un único administrador.
- CU-03: registrar, listar y eliminar activos (nombre e IP).
- CU-04: escaneo de una lista fija de puertos TCP y almacenamiento del resultado con fecha y hora.
- CU-09: alertas en pantalla para puertos riesgosos abiertos, nivel alto/bajo y opción de marcar atendida.
- CU-11: panel con puertos abiertos, alertas pendientes y tiempo promedio entre detección y emisión de alertas.

## Puertos del MVP
21 FTP, 22 SSH, 23 Telnet, 80 HTTP, 443 HTTPS, 445 SMB, 3306 MySQL, 3389 RDP, 5432 PostgreSQL y 8080 HTTP alternativo.

## Restricciones y seguridad
- El escáner solo acepta direcciones IPv4 privadas o loopback. No permite objetivos públicos.
- Escanea únicamente equipos registrados y autorizados por el responsable de la red.
- La comprobación es TCP connect; un puerto que no responde se reporta como no abierto, aunque un firewall podría estar filtrando el tráfico.
- La lista de puertos y los niveles de riesgo son fijos, como establece el alcance del MVP.
- La aplicación escucha en `127.0.0.1` para uso local. No la expongas a Internet ni a redes compartidas sin una revisión de seguridad adicional.
- Cambia `SECRET_KEY` mediante variable de entorno para un despliegue real.
- Este MVP es una herramienta académica de inventario y comprobación básica; no sustituye un análisis profesional de vulnerabilidades.

## Base de datos
SQLite se crea automáticamente en `cybershield.db` la primera vez que se ejecuta la aplicación. Para reiniciar los datos de prueba, detén la aplicación y elimina ese archivo.

## Limitaciones conocidas
No incluye gestión de usuarios/roles, análisis profundo de vulnerabilidades, monitoreo continuo, detección/bloqueo de accesos sospechosos, configuración dinámica de reglas, historial avanzado ni generación de reportes; estas funciones están fuera del MVP definido en el documento.
