# Gestión del Servicio DHCP Observer

## Comandos Útiles

### Ver estado del servicio
```bash
sudo systemctl status dhcp-observer
```

### Iniciar el servicio
```bash
sudo systemctl start dhcp-observer
```

### Detener el servicio
```bash
sudo systemctl stop dhcp-observer
```

### Reiniciar el servicio
```bash
sudo systemctl restart dhcp-observer
```

### Ver logs en tiempo real
```bash
sudo journalctl -u dhcp-observer -f
```

### Ver últimos 50 logs
```bash
sudo journalctl -u dhcp-observer -n 50
```

### Habilitar autoarranque (ya está configurado)
```bash
sudo systemctl enable dhcp-observer
```

### Deshabilitar autoarranque
```bash
sudo systemctl disable dhcp-observer
```

### Ver la configuración del servicio
```bash
cat /etc/systemd/system/dhcp-observer.service
```

## Ubicaciones Importantes

- **Archivo de servicio**: `/etc/systemd/system/dhcp-observer.service`
- **App principal**: `/home/tecnico/management_utilities/network_analyzers/ogDHCP-Observer.py`
- **Configuración**: `/home/tecnico/management_utilities/network_analyzers/.env`
- **Certificados SSL**: `/home/tecnico/management_utilities/network_analyzers/cert.pem` y `key.pem`
- **Templates HTML**: `/home/tecnico/management_utilities/network_analyzers/templates/index.html`

## Estado Actual

✅ Servicio **HABILITADO** para autoarranque al boot
✅ Servicio **CORRIENDO** en https://127.0.0.1:5443
✅ Logs disponibles vía `journalctl -u dhcp-observer`
✅ Reinicio automático si falla (RestartSec=10)
