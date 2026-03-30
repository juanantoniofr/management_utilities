# DHCP Observer Monitor

Monitor web en tiempo real para eventos DHCP ISC con autenticación HTTP Basic + SSL/TLS.

**Descripción:** Herramienta para visualizar y monitorear eventos DHCP (DISCOVER, OFFER, REQUEST, ACK, NAK) desde el servidor ISC DHCP. Interfaz web intuitiva con clasificación de severidad, seguimiento en vivo y análisis de histórico de hasta 30 días.

## Características

- ✅ **Monitoreo en tiempo real** — Seguimiento en vivo con refetch cada 5 segundos
- ✅ **Análisis histórico** — Rango temporal flexible (6h, 12h, 24h, 48h, hasta 30 días)
- ✅ **Clasificación de severidad** — Automática basada en eventos DHCP
- ✅ **Autenticación segura** — HTTP Basic Auth con contraseña hasheada
- ✅ **API REST JSON** — Fácil integración con sistemas externos
- ✅ **Parsing robusto** — Regex compiladas, validación de datos
- ✅ **Caché de rendimiento** — LRU cache para evitar reprocesamiento
- ✅ **Manejo de errores** — Alertas visuales, logs estructurados
- ✅ **XSS Prevention** — Escape HTML automático
- ✅ **Soporte SSL/TLS** — Con fallback HTTP

## 🔒 Seguridad & GitHub

### Archivos a EXCLUIR (nunca subir a GitHub)

El archivo `.gitignore` ya está configurado. **NO subir:**

- ✋ `.env` — Contiene contraseñas y credenciales
- ✋ `__pycache__/` — Bytecode compilado (se regenera)
- ✋ `*.pyc` — Archivos compilados Python
- ✋ `*.csv` — Datos sensibles (dhcp_observer.csv)
- ✋ `*.key` — Claves privadas SSL
- ✋ `*.pem` — Certificados SSL privados
- ✋ Scripts legacy — `cazador_naks.sh`, `dhcp_nak_hunter.sh`, etc.
- ✋ `venv/`, `env/` — Virtual environments

**Verificar antes de subir:**

```bash
git status  # Confirmar que no aparecen archivos sensibles
```

### Mejores prácticas

1. **Contraseñas:** Siempre en `.env`, nunca en código
2. **Secrets:** Usar variables de entorno
3. **Certificados:** Generar localmente, no versionar
4. **Logs:** Ignorar en `.gitignore`
5. **.env.example:** Sí incluir (como plantilla)

---

### 1. Requisitos

- Linux (Debian/Ubuntu)
- Python 3.8+
- ISC DHCP Server (`isc-dhcp-server`)
- pip3

```bash
sudo apt-get install -y isc-dhcp-server python3 python3-pip
```

### 2. Clonar el repositorio

```bash
git clone https://github.com/yourusername/dhcp-observer.git
cd dhcp-observer
```

### 3. Instalar dependencias Python

```bash
pip3 install -r requirements.txt
```

### 4. Configurar variables de entorno

```bash
cp .env.example .env
nano .env  # Editar credenciales
```

**Variables obligatorias:**

- `DHCP_ADMIN_USER=admin` — Usuario acceso web
- `DHCP_ADMIN_PASS=changeme` → **⚠️ CAMBIAR EN PRODUCCIÓN**

### 5. Ejecutar

**Desarrollo (HTTP):**

```bash
export FLASK_ENV=development
python3 ogDHCP-Observer.py
# Acceder: http://localhost:5000
```

**Producción (HTTPS):**

```bash
export FLASK_ENV=production
python3 ogDHCP-Observer.py
# Requiere certificados SSL en /etc/ssl/certs/
```

**Con Gunicorn:**

```bash
pip3 install gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 ogDHCP-Observer:app
```

---

## API Endpoints

### GET `/api/status?hours=24`

Retorna lista JSON de dispositivos DHCP en las últimas N horas.

**Parámetros:**

- `hours` (int): 1-730 (default: 24)

**Response:**

```json
[
  {
    "mac": "00:11:22:33:44:55",
    "ip": "192.168.1.100",
    "last_event": "DHCPACK",
    "time": "Mar 30 10:45:32",
    "count": 0,
    "sev": "INFO",
    "msg": "Conexión establecida correctamente"
  }
]
```

**Códigos de Error:**

- `400`: Parámetro inválido
- `503`: Error en journalctl
- `500`: Error interno

---

## Testing

### Backend

- [x] Validación `hours` (-1, 0, 1, 24, 730, 731)
- [x] Parseador regex robusto
- [x] Try/except en rutas
- [x] Env vars vs hardcoded
- [x] Caché funcionando

### Frontend

- [x] CSS sin errores
- [x] Spinner aparece/desaparece
- [x] Botón activo actualiza
- [x] Error handling muestra alerts
- [x] HTML escape previene XSS

### Operaciones

- [x] Sintaxis Python válida
- [x] Logging configurable
- [x] Fallback HTTP si SSL falta
- [x] Rutas 404/500 maneja

---

## Estructura de Archivos

```
network_analyzers/
├── ogDHCP-Observer.py          # Backend Flask (refactorizado)
├── requirements.txt            # Dependencias Python
├── .env.example                # Plantilla de configuración
├── README.md                   # Este archivo
└── templates/
    └── index.html              # Frontend (mejorado)
```

---

## Logs

Usar `journalctl` para ver logs de la aplicación:

```bash
journalctl -u isc-dhcp-server --since "1 hour ago"
```

O ejecutar en modo debug:

```bash
export FLASK_DEBUG=True
python3 ogDHCP-Observer.py
```

---

## Mantenimiento

### Limpiar caché

El caché se limpia automáticamente (maxsize=16). Para resetear:

```python
parse_dhcp_logs.cache_clear()
```

### Renovar certificados SSL

Si los certificados snakeoil expiraron:

```bash
sudo apt-get install ssl-cert
sudo make-ssl-cert generate-default-snakeoil
```

---

## Problemas Comunes

| Problema                          | Solución                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------- |
| `Certificados SSL no encontrados` | Ejecuta en HTTP (puerto 5000) o instala `ssl-cert`                                |
| `Permission denied: journalctl`   | Ejecuta con `sudo` o añade user a grupo `systemd-journal`                         |
| `ModuleNotFoundError: flask`      | Ejecuta `pip3 install -r requirements.txt`                                        |
| `API retorna 503`                 | Verifica que `isc-dhcp-server` esté corriendo: `systemctl status isc-dhcp-server` |

---

## Cambios Vs Original

```diff
- users = {"admin": "scrypt:..."}  # Hardcoded
+ users = load_users()             # Env vars

- def parse_dhcp_logs(hours):
-     parts[7], parts[9]          # Índices frágiles
-
+ @functools.lru_cache(maxsize=16)
+ def parse_dhcp_logs(hours):
+     pattern.search()             # Regex robusto
+     validate hours: 1-730
+     try/except en todo

- .sev-INFO { table-success; }     # CSS error
+ .sev-INFO { background-color: #d4edda !important; }

- fetch(...).then(res => res.json())  # Sin error handling
+ fetch(...).catch(error => showAlert(...))
```

---

## Licencia

MIT License - Ver archivo LICENSE para detalles

## Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Soporte

Para reportar bugs o sugerir mejoras, abre un [Issue](https://github.com/yourusername/dhcp-observer/issues)
