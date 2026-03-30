import subprocess
import re
import os
import logging
import functools
from flask import Flask, render_template, jsonify, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import ssl

app = Flask(__name__)
auth = HTTPBasicAuth()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cargar credenciales desde variables de entorno
def load_users():
    """Carga credenciales desde env vars. Si no existen, genera defaults."""
    admin_user = os.getenv('DHCP_ADMIN_USER', 'admin')
    admin_pass = os.getenv('DHCP_ADMIN_PASS')
    
    if not admin_pass:
        logger.warning("DHCP_ADMIN_PASS no configurado. Usando default inseguro.")
        admin_pass = "changeme"
    
    return {admin_user: generate_password_hash(admin_pass)}

users = load_users()

@auth.verify_password
def verify_password(username, password):
    """Verifica credenciales contra los usuarios cargados."""
    if username in users and check_password_hash(users.get(username), password):
        return username
    logger.warning(f"Intento de login fallido: {username}")
    return None

@functools.lru_cache(maxsize=16)
def parse_dhcp_logs(hours):
    """
    Parsea logs de DHCP desde journalctl y extrae eventos de dispositivos.
    
    Args:
        hours (int): Horas atrás a analizar (1-730, máximo 30 días)
    
    Returns:
        list: Lista de dispositivos con su último estado, ordenados por timestamp
    
    Raises:
        ValueError: Si hours está fuera del rango válido
        RuntimeError: Si journalctl falla
    """
    # === VALIDACIÓN ===
    try:
        hours = int(hours)
        if not (1 <= hours <= 730):
            raise ValueError(f"hours debe estar entre 1 y 730. Recibido: {hours}")
    except (TypeError, ValueError) as e:
        logger.error(f"Parámetro hours inválido: {e}")
        raise ValueError(f"Parámetro 'hours' inválido: {str(e)}")
    
    # === EJECUCIÓN ===
    try:
        cmd = ["journalctl", "-u", "isc-dhcp-server", "--since", f"{hours} hours ago", "--no-pager"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            logger.error(f"journalctl falló: {result.stderr}")
            raise RuntimeError(f"journalctl error: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("journalctl timeout (>10s)")
        raise RuntimeError("DHCP logs readout timeout")
    except Exception as e:
        logger.error(f"Error ejecutando journalctl: {e}")
        raise RuntimeError(f"Error reading DHCP logs: {str(e)}")
    
    # === PARSING ===
    devices = {}
    
    # Compilar regex patterns una sola vez
    patterns = {
        'DISCOVER': re.compile(r'DHCPDISCOVER from ([0-9a-fA-F:]{17})'),
        'OFFER': re.compile(r'DHCPOFFER on ([\d.]+) to ([0-9a-fA-F:]{17})'),
        'REQUEST': re.compile(r'DHCPREQUEST.*from ([0-9a-fA-F:]{17})'),
        'ACK': re.compile(r'DHCPACK on ([\d.]+) to ([0-9a-fA-F:]{17})'),
        'NAK': re.compile(r'DHCPNAK on ([\d.]+) to ([0-9a-fA-F:]{17})')
    }
    
    for line in result.stdout.splitlines():
        try:
            parts = line.split()
            if len(parts) < 6:
                continue
            
            timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
            message = ' '.join(parts[5:])
            
            # Determinar tipo de evento
            event = None
            mac = ""
            ip = "-"  # ← INICIALIZAR CORRECTAMENTE
            
            # Intentar cada patrón
            for event_type, pattern in patterns.items():
                match = pattern.search(message)
                if match:
                    event = event_type
                    groups = match.groups()
                    
                    if event_type == 'DISCOVER':
                        mac = groups[0]
                    elif event_type in ['OFFER', 'ACK', 'NAK']:
                        ip = groups[0]
                        mac = groups[1]
                    elif event_type == 'REQUEST':
                        mac = groups[0]
                    break
            
            if not event or not mac:
                continue
            
            # Validar formato MAC (media check, no es regex pesada)
            if len(mac) < 17 or mac.count(':') != 5:
                continue
            
            # === LÓGICA DE SEVERIDAD ===
            if mac not in devices:
                devices[mac] = {
                    'mac': mac,
                    'ip': '-',
                    'last_event': '',
                    'time': '',
                    'count': 0,
                    'sev': 'INFO',
                    'msg': ''
                }
            
            dev = devices[mac]
            dev['last_event'] = event
            dev['time'] = timestamp
            if ip != "-":
                dev['ip'] = ip
            
            # Contar DISCOVERs para detectar flapping
            if event == "DHCPDISCOVER":
                dev['count'] += 1
            
            # Actualizar severidad según evento
            if event == "DHCPDISCOVER":
                dev['sev'] = 'CRIT'
                dev['msg'] = 'Servidor no responde (No Offer)'
            elif event == "DHCPOFFER":
                dev['sev'] = 'WARN'
                dev['msg'] = 'Esperando Request del cliente'
            elif event == "DHCPNAK":
                dev['sev'] = 'ERROR'
                dev['msg'] = '¡Denegado! Posible conflicto o servidor ajeno'
            elif event == "DHCPACK":
                dev['sev'] = 'INFO'
                dev['msg'] = 'Conexión establecida correctamente'
            elif dev['count'] > 5:
                dev['sev'] = 'WARN'
                dev['msg'] = 'Exceso de peticiones (Flapping)'
            else:
                dev['sev'] = 'INFO'
                dev['msg'] = 'Estado desconocido'
        
        except Exception as e:
            logger.debug(f"Error parseando línea: {line} | {e}")
            continue
    
    logger.info(f"Parseados {len(devices)} dispositivos únicos en {hours}h")
    return sorted(devices.values(), key=lambda x: x['time'], reverse=True)

@app.route('/')
@auth.login_required
def index():
    """Renderiza la interfaz web."""
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error renderizando template: {e}")
        return jsonify({'error': 'Template not found'}), 500

@app.route('/api/status')
@auth.login_required
def api_status():
    """API endpoint para obtener estado de DHCP."""
    try:
        hours = request.args.get('hours', default=24, type=int)
        devices = parse_dhcp_logs(hours)
        return jsonify(devices)
    except ValueError as e:
        logger.error(f"Validación fallida: {e}")
        return jsonify({'error': str(e)}), 400
    except RuntimeError as e:
        logger.error(f"Error runtime: {e}")
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logger.error(f"Error inesperado en /api/status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    """Manejador para rutas no encontradas."""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejador para errores 500."""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("Iniciando DHCP Monitor...")
    
    # Verificar variables de entorno críticas
    if not os.getenv('DHCP_ADMIN_PASS'):
        logger.warning("⚠️ DHCP_ADMIN_PASS no configurado. Usando password inseguro (changeme)")
    
    # Configurar SSL
    ssl_cert_path = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
    ssl_key_path = '/etc/ssl/private/ssl-cert-snakeoil.key'
    
    if not os.path.exists(ssl_cert_path) or not os.path.exists(ssl_key_path):
        logger.error(f"❌ Certificados SSL no encontrados en {ssl_cert_path} o {ssl_key_path}")
        logger.info("Ejecutando en modo HTTP sin SSL")
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(ssl_cert_path, ssl_key_path)
            logger.info("✓ SSL configurado correctamente. Escuchando en puerto 443")
            app.run(host='0.0.0.0', port=443, ssl_context=context, debug=False)
        except Exception as e:
            logger.error(f"Error configurando SSL: {e}")
            logger.info("Fallback a HTTP en puerto 5000")
            app.run(host='0.0.0.0', port=5000, debug=False)