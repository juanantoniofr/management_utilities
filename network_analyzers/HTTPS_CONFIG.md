# DHCP Monitor - Actualización a HTTPS

## Cambios Realizados

### ✅ HTTPS Habilitado
- **Puerto**: 5443 (no requiere permisos de root)
- **Certificados**: `cert.pem` y `key.pem` (autofirmados; válidos por 4 años)
- **Protocolo**: TLS Seguro

### ✅ Contraseña Actualizada
- **Contraseña anterior**: `changeme` (insegura)
- **Contraseña nueva**: `/VvAGqOo26p1LgQj` (segura, 16 caracteres)
- **Usuario por defecto**: `admin`

## Cómo Ejecutar

### Opción 1: Con Virtual Environment (Recomendado)
```bash
cd /home/tecnico/management_utilities/network_analyzers
source venv/bin/activate
python3 ogDHCP-Observer.py
```

### Opción 2: Acceso Rápido
```bash
cd /home/tecnico/management_utilities/network_analyzers && \
source venv/bin/activate && \
python3 ogDHCP-Observer.py
```

## Generar certificados (si faltan)

Desde el directorio del proyecto:

```bash
cd /home/tecnico/management_utilities/network_analyzers
./generate_certs.sh
```

Para regenerarlos:

```bash
./generate_certs.sh --force
```

Opcional (añadir IP/DNS al SAN):

```bash
./generate_certs.sh --ip 192.168.1.10 --dns dhcp-observer.local
```

## Cómo Acceder

### HTTPS (Recomendado)
```bash
curl -k https://127.0.0.1:5443/ -u admin:/VvAGqOo26p1LgQj
```

### O desde el navegador
1. Ir a: `https://127.0.0.1:5443/`
2. Usuario: `admin`
3. Contraseña: `/VvAGqOo26p1LgQj`

**Nota**: Ignorar advertencia de certificado auto-firmado (es seguro)

### HTTP Fallback (si es necesario)
```bash
curl http://127.0.0.1:5000/ -u admin:/VvAGqOo26p1LgQj
```

## Cambiar la Contraseña

Edita el archivo `.env`:
```bash
nano /home/tecnico/management_utilities/network_analyzers/.env
```

O establece la variable de entorno:
```bash
export DHCP_ADMIN_PASS="tu_nueva_contraseña_aqui"
python3 ogDHCP-Observer.py
```

## Logs de Inicio (Esperado)
```
WARNING:__main__:DHCP_ADMIN_PASS no configurado. Usando contraseña por defecto.
INFO:__main__:Iniciando DHCP Monitor...
✓ SSL configurado correctamente. Escuchando en puerto 5443 (HTTPS)
```

## Puertos en Uso
- **5443**: HTTPS (primario)
- **5000**: HTTP fallback (si SSL falla)

---
**Servidor activo y seguro ✓**
