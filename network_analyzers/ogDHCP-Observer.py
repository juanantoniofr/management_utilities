import subprocess
import re
import os
import logging
import functools
import time
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import ssl
from dotenv import load_dotenv

app = Flask(__name__)
auth = HTTPBasicAuth()

# Cargar variables desde .env (si existe) antes de leer os.getenv
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(_BASE_DIR, '.env'), override=True)

# Parsear dhcpd.conf para mapear MAC -> hostname
def _load_dhcp_hosts():
    """Parsea dhcpd.conf y devuelve dict MAC -> hostname."""
    hosts = {}
    try:
        with open('/etc/dhcp/dhcpd.conf', 'r') as f:
            # Leer todo el archivo
            content = f.read()
            # Normalizar saltos de línea en una línea lógica
            content = re.sub(r'\n\s+', ' ', content)
            # Buscar: host NOMBRE { ... hardware ethernet MAC; ... }
            pattern = r'host\s+(\S+)\s*\{[^}]*hardware\s+ethernet\s+([0-9a-fA-F:]{17})'
            for match in re.finditer(pattern, content, re.IGNORECASE):
                hostname = match.group(1)
                mac = match.group(2).lower()
                hosts[mac] = hostname
    except Exception as e:
        logger.warning(f"Error parsando dhcpd.conf: {e}")
    return hosts

_DHCP_HOSTS = _load_dhcp_hosts()

def _is_known_range(ip_str):
    """Verifica si IP está en rango conocido (10.1.21.x o 10.1.22.188-255)."""
    if not ip_str or ip_str == '-':
        return False
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        if parts[0:2] != ['10', '1']:
            return False
        third = int(parts[2])
        fourth = int(parts[3])
        # Rango 10.1.21.x
        if third == 21:
            return True
        # Rango 10.1.22.188-255
        if third == 22 and 188 <= fourth <= 255:
            return True
        return False
    except (ValueError, IndexError):
        return False

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

def _validate_hours(hours):
    try:
        hours = int(hours)
        if not (1 <= hours <= 730):
            raise ValueError(f"hours debe estar entre 1 y 730. Recibido: {hours}")
        return hours
    except (TypeError, ValueError) as e:
        logger.error(f"Parámetro hours inválido: {e}")
        raise ValueError(f"Parámetro 'hours' inválido: {str(e)}")


def _get_slow_threshold_s():
    raw = os.getenv('DHCP_SLOW_THRESHOLD_S', '10')
    try:
        value = int(raw)
        if value < 1:
            raise ValueError("DHCP_SLOW_THRESHOLD_S debe ser >= 1")
        return value
    except ValueError:
        logger.warning(f"DHCP_SLOW_THRESHOLD_S inválido ({raw}). Usando 10")
        return 10


def _get_alert_threshold():
    """
    Obtiene umbral de filtrado para DISCOVER sin OFFER.
    Default (10): Filtra ruido ocasional, muestra problemas reales.
    Si se configura en .env: filtra solo MACs con >= N intentos fallidos.
    
    Con exponential backoff, un equipo legítimo con problema acumula ~50-300 en 24h.
    Valores realistas: 5-20.
    """
    raw = os.getenv('DHCP_ALERT_THRESHOLD', '10')
    
    if raw and raw.lower() in ['disabled', 'none']:
        # Sin filtrado (mostrar todos)
        return None
    
    try:
        value = int(raw)
        if value < 1:
            raise ValueError("DHCP_ALERT_THRESHOLD debe ser >= 1 o 'disabled'")
        return value
    except ValueError:
        logger.warning(f"DHCP_ALERT_THRESHOLD inválido ({raw}). Usando default 10")
        return 10


_TS_PREFIX_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})[T\s](?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,6}))?(?:\s*(?P<tz>Z|[+-]\d{2}:\d{2}|[+-]\d{4}))?\s+'
)


def _parse_short_iso_timestamp(line):
    """Parsea el prefijo `journalctl -o short-iso` y devuelve (dt, resto_linea)."""
    m = _TS_PREFIX_RE.match(line)
    if not m:
        return None, line

    date_s = m.group('date')
    time_s = m.group('time')
    frac = m.group('frac')
    tz_s = m.group('tz')

    # Construir ISO format con T y TZ
    dt_s = f"{date_s}T{time_s}"
    if frac:
        dt_s += f".{frac.ljust(6, '0')}"
    if tz_s:
        if tz_s == 'Z':
            dt_s += "+00:00"
        elif ':' in tz_s:
            # Ya está en formato +HH:MM
            dt_s += tz_s
        else:
            # +0200 -> +02:00
            dt_s += tz_s[:3] + ":" + tz_s[3:]

    try:
        dt = datetime.fromisoformat(dt_s)
    except Exception as e:
        logger.debug(f"Error parseando ISO timestamp '{dt_s}': {e}")
        return None, line
    return dt, line[m.end():]


def _read_dhcp_journal(hours):
    """Lee logs del servicio isc-dhcp-server vía journalctl."""
    try:
        cmd = [
            "journalctl",
            "-u",
            "isc-dhcp-server",
            "--since",
            f"{hours} hours ago",
            "--no-pager",
            "-o",
            "short-iso",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            logger.error(f"journalctl falló: {result.stderr}")
            raise RuntimeError(f"journalctl error: {result.stderr}")
        # Normalizar line breaks: unir solo los que estén EN MEDIO de una línea lógica
        # (i.e., newlines que NO van seguidos de un timestamp ISO)
        text = result.stdout
        text = re.sub(r'(\S)\n(?!\d{4}-\d{2}-\d{2}T)', r'\1 ', text)
        return text.splitlines()
    except subprocess.TimeoutExpired:
        logger.error("journalctl timeout (>10s)")
        raise RuntimeError("DHCP logs readout timeout")
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"Error ejecutando journalctl: {e}")
        raise RuntimeError(f"Error reading DHCP logs: {str(e)}")


def _compile_dhcp_patterns():
    # En ISC DHCP, los formatos más comunes son:
    # - DHCPDISCOVER from aa:bb:cc:dd:ee:ff via eth0
    # - DHCPOFFER on 10.0.0.10 to aa:bb:cc:dd:ee:ff via eth0
    # - DHCPREQUEST for 10.0.0.10 from aa:bb:cc:dd:ee:ff via eth0
    # - DHCPACK on 10.0.0.10 to aa:bb:cc:dd:ee:ff via eth0
    # - DHCPNAK on 10.0.0.10 to aa:bb:cc:dd:ee:ff via eth0
    return {
        'DISCOVER': re.compile(r'\bDHCPDISCOVER\b.*?\bfrom\s+([0-9a-fA-F:]{17})\b', re.DOTALL),
        'OFFER': re.compile(r'\bDHCPOFFER\b.*?\bon\s+([\d.]+)\s+to\s+([0-9a-fA-F:]{17})\b', re.DOTALL),
        'REQUEST': re.compile(r'\bDHCPREQUEST\b.*?\bfor\s+([\d.]+)\s+from\s+([0-9a-fA-F:]{17})\b', re.DOTALL),
        'REQUEST_FALLBACK': re.compile(r'\bDHCPREQUEST\b.*?\bfrom\s+([0-9a-fA-F:]{17})\b', re.DOTALL),
        'ACK': re.compile(r'\bDHCPACK\b.*?\bon\s+([\d.]+)\s+to\s+([0-9a-fA-F:]{17})\b', re.DOTALL),
        'NAK': re.compile(r'\bDHCPNAK\b.*?\bon\s+([\d.]+)\s+to\s+([0-9a-fA-F:]{17})\b', re.DOTALL),
    }


def _parse_dhcp_events(lines):
    patterns = _compile_dhcp_patterns()
    events = []

    for line in lines:
        try:
            ts, rest = _parse_short_iso_timestamp(line)
            if ts is None:
                continue

            message = rest
            if 'DHCP' not in message:
                continue

            # DISCOVER
            m = patterns['DISCOVER'].search(message)
            if m:
                mac = m.group(1)
                events.append({
                    'ts': ts,
                    'ts_str': ts.isoformat(sep=' ', timespec='seconds'),
                    'event': 'DISCOVER',
                    'mac': mac.lower(),
                    'ip': None,
                    'raw': message.strip(),
                })
                continue

            # OFFER
            m = patterns['OFFER'].search(message)
            if m:
                ip, mac = m.group(1), m.group(2)
                events.append({
                    'ts': ts,
                    'ts_str': ts.isoformat(sep=' ', timespec='seconds'),
                    'event': 'OFFER',
                    'mac': mac.lower(),
                    'ip': ip,
                    'raw': message.strip(),
                })
                continue

            # REQUEST
            m = patterns['REQUEST'].search(message)
            if m:
                ip, mac = m.group(1), m.group(2)
                events.append({
                    'ts': ts,
                    'ts_str': ts.isoformat(sep=' ', timespec='seconds'),
                    'event': 'REQUEST',
                    'mac': mac.lower(),
                    'ip': ip,
                    'raw': message.strip(),
                })
                continue
            m = patterns['REQUEST_FALLBACK'].search(message)
            if m:
                mac = m.group(1)
                events.append({
                    'ts': ts,
                    'ts_str': ts.isoformat(sep=' ', timespec='seconds'),
                    'event': 'REQUEST',
                    'mac': mac.lower(),
                    'ip': None,
                    'raw': message.strip(),
                })
                continue

            # ACK
            m = patterns['ACK'].search(message)
            if m:
                ip, mac = m.group(1), m.group(2)
                events.append({
                    'ts': ts,
                    'ts_str': ts.isoformat(sep=' ', timespec='seconds'),
                    'event': 'ACK',
                    'mac': mac.lower(),
                    'ip': ip,
                    'raw': message.strip(),
                })
                continue

            # NAK
            m = patterns['NAK'].search(message)
            if m:
                ip, mac = m.group(1), m.group(2)
                events.append({
                    'ts': ts,
                    'ts_str': ts.isoformat(sep=' ', timespec='seconds'),
                    'event': 'NAK',
                    'mac': mac.lower(),
                    'ip': ip,
                    'raw': message.strip(),
                })
                continue

        except Exception as e:
            logger.debug(f"Error parseando línea: {line} | {e}")
            continue

    events.sort(key=lambda e: e['ts'])
    return events


def _new_cycle(mac, start_event):
    return {
        'mac': mac,
        'ip': None,
        'start_ts': start_event['ts'],
        'start_str': start_event['ts_str'],
        'end_ts': None,
        'end_str': None,
        'events': [start_event],
        'first_ts_by_event': {'DISCOVER': start_event['ts']},
        'result': None,  # SUCCESS / NAK / INCOMPLETE
    }


def _close_cycle(cycle, end_ts, result):
    cycle['end_ts'] = end_ts
    cycle['end_str'] = end_ts.isoformat(sep=' ', timespec='seconds')
    cycle['result'] = result
    return cycle


def _cycle_metrics(cycle):
    first = cycle['first_ts_by_event']
    out = {
        't_discover_offer_s': None,
        't_offer_request_s': None,
        't_request_ack_s': None,
        't_discover_ack_s': None,
        'duration_s': None,
    }
    if cycle.get('start_ts') and cycle.get('end_ts'):
        out['duration_s'] = int((cycle['end_ts'] - cycle['start_ts']).total_seconds())

    if 'DISCOVER' in first and 'OFFER' in first:
        out['t_discover_offer_s'] = int((first['OFFER'] - first['DISCOVER']).total_seconds())
    if 'OFFER' in first and 'REQUEST' in first:
        out['t_offer_request_s'] = int((first['REQUEST'] - first['OFFER']).total_seconds())
    if 'REQUEST' in first and 'ACK' in first:
        out['t_request_ack_s'] = int((first['ACK'] - first['REQUEST']).total_seconds())
    if 'DISCOVER' in first and 'ACK' in first:
        out['t_discover_ack_s'] = int((first['ACK'] - first['DISCOVER']).total_seconds())
    return out


def _analyze_dhcp_logs(hours, slow_threshold_s):
    lines = _read_dhcp_journal(hours)
    events = _parse_dhcp_events(lines)

    cycles = []
    active = {}  # mac -> cycle

    for ev in events:
        mac = ev['mac']
        if ev['event'] == 'DISCOVER':
            if mac in active:
                prev = active.pop(mac)
                last_ts = prev['events'][-1]['ts']
                cycles.append(_close_cycle(prev, last_ts, 'INCOMPLETE'))
            active[mac] = _new_cycle(mac, ev)
            continue

        if mac not in active:
            # Si no hay ciclo activo, podría ser:
            # 1. Una renovación (REQUEST sin DISCOVER) - RFC 2131 Renewal state
            # 2. Un evento huérfano (OFFER sin DISCOVER) - ignorar
            if ev['event'] in ['REQUEST', 'ACK', 'NAK']:
                # Iniciar ciclo con este evento (renovación o renegotiation)
                active[mac] = _new_cycle(mac, ev)
            else:
                # OFFER sin DISCOVER previo -> ignorar
                continue

        cycle = active[mac]
        cycle['events'].append(ev)
        cycle['first_ts_by_event'].setdefault(ev['event'], ev['ts'])
        if ev.get('ip'):
            cycle['ip'] = ev['ip']

        if ev['event'] == 'ACK':
            cycles.append(_close_cycle(active.pop(mac), ev['ts'], 'SUCCESS'))
        elif ev['event'] == 'NAK':
            cycles.append(_close_cycle(active.pop(mac), ev['ts'], 'NAK'))

    # Cerrar ciclos abiertos al final de la ventana
    for mac, cycle in list(active.items()):
        last_ts = cycle['events'][-1]['ts']
        cycles.append(_close_cycle(cycle, last_ts, 'INCOMPLETE'))

    # Clasificación en secciones
    sections = [
        {'id': 'slow_dora', 'title': f'Ciclos DORA lentos (>{slow_threshold_s}s)', 'severity': 'WARN', 'items': []},
        {'id': 'discover_no_offer', 'title': 'DISCOVER sin OFFER (nadie ofrece IP)', 'severity': 'CRIT', 'items': []},
        {'id': 'request_no_ack', 'title': 'REQUEST sin ACK (DHCP no confirma)', 'severity': 'ERROR', 'items': []},
        {'id': 'dhcpnak', 'title': 'DHCPNAK (denegaciones/conflictos)', 'severity': 'ERROR', 'items': []},
        {'id': 'success', 'title': 'Ciclos exitosos (ACK)', 'severity': 'INFO', 'items': []},
    ]
    section_by_id = {s['id']: s for s in sections}

    for c in cycles:
        metrics = _cycle_metrics(c)
        first = c['first_ts_by_event']
        has_discover = 'DISCOVER' in first
        has_offer = 'OFFER' in first
        has_request = 'REQUEST' in first
        has_ack = 'ACK' in first
        has_nak = 'NAK' in first

        # Solo marcar como lento si hay DISCOVER (no es renovación)
        is_slow = bool(has_discover and has_ack and metrics['t_discover_ack_s'] is not None and metrics['t_discover_ack_s'] > slow_threshold_s)

        # Buscar hostname en dhcpd.conf
        hostname = _DHCP_HOSTS.get(c['mac'], None)
        is_known = _is_known_range(c['ip'])
        
        base_item = {
            'mac': c['mac'],
            'hostname': hostname,
            'is_known': is_known,
            'ip': c['ip'] or '-',
            'start': c['start_str'],
            'end': c['end_str'],
            'duration_s': metrics['duration_s'],
            't_discover_ack_s': metrics['t_discover_ack_s'],
            'is_slow': is_slow,
        }

        if c['result'] == 'SUCCESS':
            item = {
                **base_item,
                'stage': 'ACK',
                'explanation': 'Ciclo DHCP completado correctamente',
            }
            section_by_id['success']['items'].append(item)
            if is_slow:
                section_by_id['slow_dora']['items'].append({
                    **item,
                    'explanation': f"Ciclo exitoso pero lento: DISCOVER→ACK = {metrics['t_discover_ack_s']}s (umbral {slow_threshold_s}s)",
                })
            continue

        if has_nak:
            section_by_id['dhcpnak']['items'].append({
                **base_item,
                'stage': 'NAK',
                'explanation': 'DHCPNAK: denegación (posible conflicto / servidor ajeno / IP no válida)',
            })
            continue

        # INCOMPLETE - clasificar según los eventos presentes
        if has_discover and not has_offer:
            # DISCOVER sin OFFER (ciclo normal incompleto)
            section_by_id['discover_no_offer']['items'].append({
                **base_item,
                'stage': 'DISCOVER',
                'explanation': 'El cliente emite DISCOVER pero no se observa ningún OFFER',
            })
        elif has_request and not has_ack:
            # REQUEST enviado pero sin ACK
            # Cubre: ciclo normal incompleto O renovación (Renewal) fallida
            section_by_id['request_no_ack']['items'].append({
                **base_item,
                'stage': 'REQUEST',
                'explanation': 'El cliente solicita IP pero no se observa confirmación (ACK)',
            })

    # Agrupar items por MAC en cada sección (para evitar repetición)
    alert_threshold = _get_alert_threshold()
    
    # PASO 1: Contar eventos GLOBALES por MAC SOLO si se aplica filtrado
    mac_discover_counts = {}
    if alert_threshold is not None:
        discover_section = next((s for s in sections if s['id'] == 'discover_no_offer'), None)
        if discover_section:
            for item in discover_section['items']:
                mac = item['mac']
                mac_discover_counts[mac] = mac_discover_counts.get(mac, 0) + 1
    
    # PASO 2: Filtrar y agrupar dentro de cada sección
    for sec in sections:
        grouped = {}
        # Contar eventos reales por MAC (en esta sección)
        for item in sec['items']:
            mac = item['mac']
            if mac not in grouped:
                grouped[mac] = {'items': [], 'first': item, 'count': 0}
            grouped[mac]['items'].append(item)
            grouped[mac]['count'] += 1
        
        # Reconstruir items con contador, aplicar filtro SOLO a discover_no_offer si está habilitado
        grouped_items = []
        filtered_out = 0
        apply_threshold = (sec['id'] == 'discover_no_offer' and alert_threshold is not None)
        
        for mac, data in sorted(grouped.items()):
            event_count = data['count']  # Número de eventos en ESTA sección
            first_item = data['first']
            
            # Aplicar filtro de umbral SOLO si es discover_no_offer Y filtrado está habilitado
            if apply_threshold:
                global_count = mac_discover_counts.get(mac, 0)
                if global_count < alert_threshold:
                    filtered_out += 1
                    continue
            else:
                global_count = None  # No se usa para otras secciones
            
            # Actualizar explicación con contador de eventos
            explanation = first_item.get('explanation', '')
            if event_count > 1:
                # Reemplazar contador anterior si existe
                explanation = re.sub(r'\s*\(\d+\s+veces?\)\.?', '', explanation)
                if explanation.endswith('.'):
                    explanation = explanation[:-1] + f" ({event_count} veces)."
                else:
                    explanation += f" ({event_count} veces)"
            
            # Crear item agrupado: usar primero como base
            grouped_item = {
                **first_item,
                'count': event_count,
                'explanation': explanation,
            }
            if apply_threshold and global_count is not None:
                grouped_item['total_count'] = global_count
            
            grouped_items.append(grouped_item)
        
        sec['items'] = sorted(grouped_items, key=lambda i: i.get('count') or 0, reverse=True)
        sec['count'] = len(sec['items'])
        sec['filtered_out'] = filtered_out

    return {
        'meta': {
            'hours': hours,
            'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'slow_threshold_s': slow_threshold_s,
            'alert_threshold': alert_threshold if alert_threshold is not None else 'disabled',
        },
        'sections': sections,
    }


def _ttl_cache(ttl_seconds=30):
    """
    Decorator que cachea resultados con time-to-live (TTL) en segundos.
    A diferencia de functools.lru_cache, invalida el cache después de TTL.
    """
    def decorator(func):
        cache = {}
        cache_times = {}
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Crear clave de cache basada en args + kwargs
            key = (args, tuple(sorted(kwargs.items())))
            now = time.time()
            
            # Verificar si existe en cache y aún es válido
            if key in cache and key in cache_times:
                if now - cache_times[key] < ttl_seconds:
                    return cache[key]
                else:
                    # Cache expirado, eliminar
                    del cache[key]
                    del cache_times[key]
            
            # Calcular resultado y cachear
            result = func(*args, **kwargs)
            cache[key] = result
            cache_times[key] = now
            return result
        
        return wrapper
    return decorator


@_ttl_cache(ttl_seconds=30)
def _analyze_dhcp_logs_cached(hours, slow_threshold_s, alert_threshold):
    return _analyze_dhcp_logs(hours, slow_threshold_s)


def analyze_dhcp_logs(hours, slow_threshold_s, nocache=False):
    alert_threshold = _get_alert_threshold()
    if nocache:
        return _analyze_dhcp_logs(hours, slow_threshold_s)
    return _analyze_dhcp_logs_cached(hours, slow_threshold_s, alert_threshold)

@app.route('/')
def index():
    """Renderiza la interfaz web (sin autenticación, la API pide credenciales)."""
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
        hours = _validate_hours(request.args.get('hours', default=24, type=int))
        slow_threshold_s = _get_slow_threshold_s()
        # En modo "en vivo" (hours=1) preferimos evitar caché para frescura.
        nocache = bool(request.args.get('nocache', default=0, type=int)) or hours == 1
        analysis = analyze_dhcp_logs(hours, slow_threshold_s, nocache=nocache)
        return jsonify(analysis)
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
    
    # Configurar SSL (por defecto: cert.pem/key.pem en el directorio del proyecto)
    base_dir = os.path.dirname(os.path.abspath(__file__))

    ssl_cert_path = os.getenv('DHCP_SSL_CERT', os.path.join(base_dir, 'cert.pem'))
    ssl_key_path = os.getenv('DHCP_SSL_KEY', os.path.join(base_dir, 'key.pem'))

    bind_host = os.getenv('DHCP_BIND_HOST', '0.0.0.0')
    https_port = int(os.getenv('DHCP_HTTPS_PORT', '5443'))
    http_port = int(os.getenv('DHCP_HTTP_PORT', '5000'))

    if not os.path.exists(ssl_cert_path) or not os.path.exists(ssl_key_path):
        logger.error(f"❌ Certificados SSL no encontrados en {ssl_cert_path} o {ssl_key_path}")
        logger.info(f"Ejecutando en modo HTTP sin SSL (puerto {http_port})")
        app.run(host=bind_host, port=http_port, debug=False)
    else:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(ssl_cert_path, ssl_key_path)
            logger.info(f"✓ SSL configurado correctamente. Escuchando en puerto {https_port} (HTTPS)")
            app.run(host=bind_host, port=https_port, ssl_context=context, debug=False)
        except Exception as e:
            logger.error(f"Error configurando SSL: {e}")
            logger.info(f"Fallback a HTTP en puerto {http_port}")
            app.run(host=bind_host, port=http_port, debug=False)