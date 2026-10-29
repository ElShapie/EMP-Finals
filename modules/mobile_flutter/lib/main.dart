import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:intl/intl.dart';

void main() {
  runApp(const SocMonitoringApp());
}

// ==================== PALETA DE COLORES OFICIAL ====================
const Color kHubBackground = Color(0xFFF7F7F8);
const Color kHubSurface = Color(0xFFFFFFFF);
const Color kHubSidebar = Color(0xFF202124);
const Color kHubBorder = Color(0xFFE3E4E8);
const Color kHubActionBlue = Color(0xFF146EF5);

// Colores de estado:
const Color kStatusSuccess = Color(0xFF23834A); // Éxito
const Color kStatusWarning = Color(0xFFC35B17); // Advertencia
const Color kStatusDanger = Color(0xFFC91C2B);  // Peligro

class SocMonitoringApp extends StatelessWidget {
  const SocMonitoringApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SOC Data Center Monitor - Security Team',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: kHubBackground,
        colorScheme: ColorScheme.light(
          primary: kHubActionBlue,
          surface: kHubSurface,
          error: kStatusDanger,
          outline: kHubBorder,
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: kHubSidebar,
          foregroundColor: Colors.white,
          elevation: 0,
        ),
        cardTheme: CardThemeData(
          color: kHubSurface,
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
            side: const BorderSide(color: kHubBorder, width: 1),
          ),
        ),
      ),
      home: const SocDashboardScreen(),
    );
  }
}

class SocDashboardScreen extends StatefulWidget {
  const SocDashboardScreen({super.key});

  @override
  State<SocDashboardScreen> createState() => _SocDashboardScreenState();
}

class _SocDashboardScreenState extends State<SocDashboardScreen> {
  int _selectedTabIndex = 0;
  int _selectedCameraIndex = 0;
  bool _isStreaming = true;
  Timer? _clockTimer;
  DateTime _currentDateTime = DateTime.now();

  // Servidor del laboratorio. En web se usa el host de la URL actual
  // (por ejemplo http://192.168.100.8:9000) y en móvil la IP del PC.
  static String get _defaultHost {
    if (kIsWeb && Uri.base.host.isNotEmpty) {
      return Uri.base.host;
    }
    return '192.168.100.8';
  }

  // Configuración oficial del servidor Frigate 0.14.1 del equipo
  late String frigateBaseUrl;
  late String flaskDashboardUrl;
  String videoSourceType = 'frigate'; // 'frigate', 'ip_webcam', 'demo'
  late String customStreamUrl;

  // Configuración NVR
  String nvrStatus = 'ONLINE (v0.14.1)';
  String recordingMode = '24/7 (Retención 1 Día)';

  // Galería de evidencias forenses capturadas
  final List<Map<String, dynamic>> forensicSnapshots = [];

  // Cámaras oficiales del Frigate reportadas por el equipo
  late List<Map<String, dynamic>> cameras;

  // Bitácora de accesos físicos con RFID
  final List<Map<String, dynamic>> accessEvents = [
    {
      'uid': '04:A3:2B:9F',
      'user': 'Carlos Mendez (SysAdmin)',
      'role': 'Microsoft 365 Admin / Server Maint.',
      'status': 'GRANTED',
      'time': DateTime.now().subtract(const Duration(minutes: 3)),
      'verifiedBy': 'RFID + 2FA OneLogin',
    },
    {
      'uid': '89:5C:11:E4',
      'user': 'Andrea Gomez (NetEng)',
      'role': 'Network Operations Engineer',
      'status': 'GRANTED',
      'time': DateTime.now().subtract(const Duration(minutes: 18)),
      'verifiedBy': 'RFID Sensor Card',
    },
    {
      'uid': 'FF:33:09:A1',
      'user': 'UNKNOWN PERSONNEL',
      'role': 'Unregistered Card',
      'status': 'DENIED',
      'time': DateTime.now().subtract(const Duration(minutes: 35)),
      'verifiedBy': 'Door Lock - Tamper Warning',
    },
    {
      'uid': '12:88:FE:03',
      'user': 'Mariana Rios (SOC Analyst)',
      'role': 'Security Auditor / CCTV Monitor',
      'status': 'GRANTED',
      'time': DateTime.now().subtract(const Duration(hours: 1, minutes: 12)),
      'verifiedBy': 'RFID Sensor Card',
    },
    {
      'uid': '55:42:AA:77',
      'user': 'David Morales (DBA)',
      'role': 'Database Administrator',
      'status': 'GRANTED',
      'time': DateTime.now().subtract(const Duration(hours: 2, minutes: 5)),
      'verifiedBy': 'RFID + OneLogin Auth',
    },
  ];

  @override
  void initState() {
    super.initState();
    final host = _defaultHost;
    frigateBaseUrl = 'http://$host:9000';
    flaskDashboardUrl = 'http://$host:8000';
    customStreamUrl = 'http://$host:9000/api/cam_entrada/latest.jpg?h=480';
    cameras = [
      {
        'id': 'cam_entrada',
        'name': 'CAM Entrada',
        'location': 'Torniquete Acceso RFID',
        'enabled': true,
        'fps': '15 FPS',
        'rtsp': 'rtsp://$host:8554/cam_entrada',
      },
      {
        'id': 'zocalo_cdmx',
        'name': 'CAM Demo (Zócalo CDMX)',
        'location': 'Flujo en Vivo Continuo',
        'enabled': true,
        'fps': '25 FPS',
        'rtsp': 'rtsp://$host:8554/zocalo_cdmx',
      },
      {
        'id': 'cam_interior',
        'name': 'CAM Interior',
        'location': 'Racks Data Center',
        'enabled': false,
        'fps': '0 FPS (Inactiva)',
        'rtsp': 'rtsp://$host:8554/cam_interior',
      },
    ];
    _clockTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        setState(() {
          _currentDateTime = DateTime.now();
        });
      }
    });
    // Intenta sincronizar cámaras con el servidor real Frigate
    _fetchFrigateConfig();
  }

  @override
  void dispose() {
    _clockTimer?.cancel();
    super.dispose();
  }

  // Consulta la API real /api/config de Frigate
  Future<void> _fetchFrigateConfig() async {
    try {
      final response = await http
          .get(Uri.parse('$frigateBaseUrl/api/config'))
          .timeout(const Duration(seconds: 2));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data != null && data['cameras'] != null) {
          final Map<String, dynamic> camMap = data['cameras'];
          setState(() {
            nvrStatus = 'ONLINE (v0.14.1 - Sync)';
            for (var cam in cameras) {
              final camId = cam['id'];
              if (camMap.containsKey(camId)) {
                cam['enabled'] = camMap[camId]['enabled'] ?? true;
              }
            }
          });
        }
      }
    } catch (_) {
      // Si el servidor no responde, mantiene la configuración local
    }
  }

  void _simulateCardSwipe() {
    final now = DateTime.now();
    final bool grantAccess = (accessEvents.length % 3 != 0);
    setState(() {
      accessEvents.insert(0, {
        'uid': grantAccess ? '04:A3:2B:9F' : 'E9:12:88:00',
        'user': grantAccess ? 'Carlos Mendez (SysAdmin)' : 'CARD NOT AUTHORIZED',
        'role': grantAccess ? 'SysAdmin (M365 Role verified)' : 'Security Violation Alert',
        'status': grantAccess ? 'GRANTED' : 'DENIED',
        'time': now,
        'verifiedBy': grantAccess ? 'Access Control System' : 'LED RED ALERT Triggered',
      });
    });

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: grantAccess ? kStatusSuccess : kStatusDanger,
        content: Row(
          children: [
            Icon(grantAccess ? Icons.check_circle : Icons.warning_rounded, color: Colors.white),
            const SizedBox(width: 8),
            Text(
              grantAccess
                  ? 'LED VERDE - Acceso Concedido (RFID Autenticado)'
                  : 'LED ROJO - Acceso DENEGADO (Alerta de Intrusión)',
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
            ),
          ],
        ),
        duration: const Duration(seconds: 3),
      ),
    );
  }

  void _captureForensicSnapshot() {
    final now = DateTime.now();
    final cam = cameras[_selectedCameraIndex];
    setState(() {
      forensicSnapshots.insert(0, {
        'id': 'EV-${1000 + forensicSnapshots.length}',
        'cam': cam['name'],
        'time': now,
        'source': videoSourceType.toUpperCase(),
      });
    });

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: kHubActionBlue,
        content: Text('📸 Evidencia Forense EV-${1000 + forensicSnapshots.length - 1} registrada en bitácora'),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  void _showStreamConfigDialog() {
    final frigateCtrl = TextEditingController(text: frigateBaseUrl);
    final webcamCtrl = TextEditingController(text: customStreamUrl);

    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          backgroundColor: kHubSurface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: const BorderSide(color: kHubBorder),
          ),
          title: Row(
            children: const [
              Icon(Icons.tune, color: kHubActionBlue),
              SizedBox(width: 8),
              Text(
                'Parámetros de Servidor & Video',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: kHubSidebar),
              ),
            ],
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Servidor Frigate 0.14.1 & Dashboard Flask:',
                  style: TextStyle(fontSize: 12, color: Colors.black54),
                ),
                const SizedBox(height: 12),

                // Modo 1: Frigate NVR
                RadioListTile<String>(
                  activeColor: kHubActionBlue,
                  value: 'frigate',
                  groupValue: videoSourceType,
                  title: Text('Frigate NVR ($frigateBaseUrl)', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                  subtitle: const Text('API REST oficial con go2rtc y snapshots', style: TextStyle(fontSize: 11)),
                  onChanged: (val) {
                    setDialogState(() => videoSourceType = val!);
                    setState(() => videoSourceType = val!);
                  },
                ),

                // Modo 2: IP Webcam
                RadioListTile<String>(
                  activeColor: kHubActionBlue,
                  value: 'ip_webcam',
                  groupValue: videoSourceType,
                  title: const Text('Cámara de Celular (IP Webcam)', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                  subtitle: const Text('Transmisión directa desde teléfono móvil', style: TextStyle(fontSize: 11)),
                  onChanged: (val) {
                    setDialogState(() => videoSourceType = val!);
                    setState(() => videoSourceType = val!);
                  },
                ),

                // Modo 3: Demo
                RadioListTile<String>(
                  activeColor: kHubActionBlue,
                  value: 'demo',
                  groupValue: videoSourceType,
                  title: const Text('Modo Demo (Respaldo Visual)', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                  subtitle: const Text('Simulación para defensa sin servidor local', style: TextStyle(fontSize: 11)),
                  onChanged: (val) {
                    setDialogState(() => videoSourceType = val!);
                    setState(() => videoSourceType = val!);
                  },
                ),

                const Divider(height: 20, color: kHubBorder),

                if (videoSourceType == 'frigate') ...[
                  const Text('URL Base de Frigate (Puerto 5000 HTTP):', style: TextStyle(fontSize: 11, color: Colors.black54)),
                  const SizedBox(height: 6),
                  TextField(
                    controller: frigateCtrl,
                    decoration: const InputDecoration(
                      hintText: 'http://IP_DEL_PC:9000',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    style: const TextStyle(fontSize: 12),
                  ),
                ],

                if (videoSourceType == 'ip_webcam') ...[
                  const Text('URL de IP Webcam (ej. /shot.jpg):', style: TextStyle(fontSize: 11, color: Colors.black54)),
                  const SizedBox(height: 6),
                  TextField(
                    controller: webcamCtrl,
                    decoration: const InputDecoration(
                      hintText: 'http://IP_DEL_PC:9000/api/cam_entrada/latest.jpg?h=480',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    style: const TextStyle(fontSize: 12),
                  ),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cerrar', style: TextStyle(color: Colors.black54)),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: kHubActionBlue,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
              onPressed: () {
                setState(() {
                  frigateBaseUrl = frigateCtrl.text.trim();
                  customStreamUrl = webcamCtrl.text.trim();
                });
                _fetchFrigateConfig();
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    backgroundColor: kStatusSuccess,
                    content: Text('Configuración guardada para: ${videoSourceType.toUpperCase()}'),
                  ),
                );
              },
              child: const Text('Guardar', style: TextStyle(fontWeight: FontWeight.bold)),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isDesktopWidth = screenWidth > 600;

    Widget content = Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                color: kHubActionBlue.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.shield_outlined, color: kHubActionBlue, size: 22),
            ),
            const SizedBox(width: 10),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'SOC MONITORING HUB',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14, letterSpacing: 0.5),
                ),
                Row(
                  children: [
                    Text('FRIGATE v0.14.1 • ', style: TextStyle(fontSize: 10, color: Colors.white70)),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                      decoration: BoxDecoration(
                        color: videoSourceType == 'demo'
                            ? kStatusWarning.withValues(alpha: 0.3)
                            : kStatusSuccess.withValues(alpha: 0.3),
                        borderRadius: BorderRadius.circular(3),
                      ),
                      child: Text(
                        videoSourceType.toUpperCase(),
                        style: TextStyle(
                          fontSize: 9,
                          fontWeight: FontWeight.bold,
                          color: videoSourceType == 'demo' ? const Color(0xFFF09E60) : const Color(0xFF66E096),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Sincronizar Frigate Config',
            icon: const Icon(Icons.refresh),
            onPressed: () {
              _fetchFrigateConfig();
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Consultando /api/config y /api/stats...')),
              );
            },
          ),
          IconButton(
            tooltip: 'Configuración de Servidor',
            icon: const Icon(Icons.settings_outlined),
            onPressed: _showStreamConfigDialog,
          ),
        ],
      ),
      body: _selectedTabIndex == 0 ? _buildCctvLiveTab() : _buildRfidLogsTab(),
      bottomNavigationBar: Container(
        decoration: const BoxDecoration(
          color: kHubSurface,
          border: Border(top: BorderSide(color: kHubBorder, width: 1)),
        ),
        child: BottomNavigationBar(
          currentIndex: _selectedTabIndex,
          backgroundColor: kHubSurface,
          selectedItemColor: kHubActionBlue,
          unselectedItemColor: Colors.black45,
          elevation: 0,
          onTap: (index) => setState(() => _selectedTabIndex = index),
          items: const [
            BottomNavigationBarItem(
              icon: Icon(Icons.videocam_outlined),
              activeIcon: Icon(Icons.videocam),
              label: 'CCTV Live View',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.badge_outlined),
              activeIcon: Icon(Icons.badge),
              label: 'RFID Access Logs',
            ),
          ],
        ),
      ),
    );

    if (isDesktopWidth) {
      return Container(
        color: const Color(0xFF1B1D21),
        child: Center(
          child: Container(
            width: 480,
            decoration: BoxDecoration(
              color: kHubBackground,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.35),
                  blurRadius: 25,
                  spreadRadius: 5,
                ),
              ],
            ),
            child: content,
          ),
        ),
      );
    }

    return content;
  }

  // ==================== PESTAÑA 1: CCTV LIVE MONITORING ====================
  Widget _buildCctvLiveTab() {
    final currentCam = cameras[_selectedCameraIndex];
    final bool isCamEnabled = currentCam['enabled'] ?? true;
    final dateStr = DateFormat('yyyy-MM-dd HH:mm:ss').format(_currentDateTime);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Banner de Estado NVR & Grabación 24/7
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: kHubSurface,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: kHubBorder),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Container(
                      width: 9,
                      height: 9,
                      decoration: BoxDecoration(
                        color: isCamEnabled ? kStatusSuccess : kStatusWarning,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'NVR: $nvrStatus',
                      style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: kHubSidebar),
                    ),
                  ],
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: kStatusDanger.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: kStatusDanger.withValues(alpha: 0.4), width: 0.8),
                  ),
                  child: Row(
                    children: [
                      Container(
                        width: 7,
                        height: 7,
                        decoration: const BoxDecoration(color: kStatusDanger, shape: BoxShape.circle),
                      ),
                      const SizedBox(width: 5),
                      Text(
                        'REC 24/7: $recordingMode',
                        style: const TextStyle(color: kStatusDanger, fontSize: 10, fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),

          // Pantalla del Stream de Video (Marco CCTV Oficial)
          AspectRatio(
            aspectRatio: 16 / 9,
            child: Container(
              decoration: BoxDecoration(
                color: Colors.black,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: isCamEnabled
                      ? (_isStreaming ? kHubActionBlue : Colors.grey)
                      : kStatusWarning,
                  width: 1.5,
                ),
              ),
              clipBehavior: Clip.antiAlias,
              child: Stack(
                children: [
                  // Render de Video en Vivo
                  Positioned.fill(
                    child: _buildVideoFeed(currentCam),
                  ),

                  // Overlay superior: Live watermark + timestamp
                  Positioned(
                    top: 10,
                    left: 10,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.75),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        '● LIVE | $dateStr (America/Merida)',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 10,
                          fontFamily: 'monospace',
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ),

                  // Overlay Cámara actual e indicador enabled
                  Positioned(
                    top: 10,
                    right: 10,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                      decoration: BoxDecoration(
                        color: isCamEnabled
                            ? kHubActionBlue.withValues(alpha: 0.85)
                            : kStatusWarning.withValues(alpha: 0.85),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Row(
                        children: [
                          Icon(isCamEnabled ? Icons.videocam : Icons.videocam_off, size: 12, color: Colors.white),
                          const SizedBox(width: 4),
                          Text(
                            isCamEnabled ? currentCam['id']!.toUpperCase() : 'DESACTIVADA',
                            style: const TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                    ),
                  ),

                  // Overlay inferior derecho: Resolución y Codec
                  Positioned(
                    bottom: 10,
                    right: 10,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.75),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        'go2rtc / H.264 • ${currentCam['fps']}',
                        style: const TextStyle(color: Colors.white70, fontSize: 9, fontFamily: 'monospace'),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),

          // Botones de control del Operador SOC
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _isStreaming ? kStatusDanger : kHubActionBlue,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    elevation: 0,
                  ),
                  icon: Icon(_isStreaming ? Icons.stop : Icons.play_arrow),
                  label: Text(
                    _isStreaming ? 'Pausar Monitoreo' : 'Iniciar Monitoreo',
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                  onPressed: () => setState(() => _isStreaming = !_isStreaming),
                ),
              ),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  backgroundColor: kHubSurface,
                  foregroundColor: kHubSidebar,
                  padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 14),
                  side: const BorderSide(color: kHubBorder),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
                icon: const Icon(Icons.camera_alt_outlined, size: 20, color: kHubActionBlue),
                label: const Text('Evidencia', style: TextStyle(fontWeight: FontWeight.w600)),
                onPressed: _captureForensicSnapshot,
              ),
            ],
          ),
          const SizedBox(height: 18),

          // Selector de Cámaras (cam_entrada, zocalo_cdmx, cam_interior)
          const Text(
            'CÁMARAS REGISTRADAS EN FRIGATE (GET /api/config)',
            style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.black54),
          ),
          const SizedBox(height: 8),
          SizedBox(
            height: 44,
            child: ListView.separated(
              scrollDirection: Axis.horizontal,
              itemCount: cameras.length,
              separatorBuilder: (_, __) => const SizedBox(width: 8),
              itemBuilder: (context, index) {
                final isSelected = _selectedCameraIndex == index;
                final bool enabled = cameras[index]['enabled'] ?? true;
                return ChoiceChip(
                  label: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 7,
                        height: 7,
                        decoration: BoxDecoration(
                          color: enabled ? kStatusSuccess : kStatusWarning,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        cameras[index]['name']!,
                        style: TextStyle(
                          color: isSelected ? Colors.white : kHubSidebar,
                          fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                  selected: isSelected,
                  selectedColor: kHubActionBlue,
                  backgroundColor: kHubSurface,
                  side: BorderSide(color: isSelected ? kHubActionBlue : kHubBorder),
                  onSelected: (val) {
                    setState(() => _selectedCameraIndex = index);
                  },
                );
              },
            ),
          ),
          const SizedBox(height: 18),

          // Evidencias Forenses Guardadas
          if (forensicSnapshots.isNotEmpty) ...[
            Text(
              'REGISTRO DE EVIDENCIAS FORENSES (${forensicSnapshots.length})',
              style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.black54),
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: kHubSurface,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: kHubBorder),
              ),
              child: Column(
                children: forensicSnapshots.take(3).map((e) {
                  final timeStr = DateFormat('HH:mm:ss').format(e['time']);
                  return ListTile(
                    dense: true,
                    leading: const Icon(Icons.image, color: kHubActionBlue, size: 20),
                    title: Text('${e['id']} - ${e['cam']}', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: kHubSidebar)),
                    subtitle: Text('Capturado a las $timeStr | Fuente: ${e['source']}', style: const TextStyle(fontSize: 10, color: Colors.black54)),
                    trailing: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: kStatusSuccess.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: const Text('SECURE HASH', style: TextStyle(fontSize: 9, color: kStatusSuccess, fontWeight: FontWeight.bold)),
                    ),
                  );
                }).toList(),
              ),
            ),
            const SizedBox(height: 18),
          ],

          // Parámetros Técnicos de Infraestructura
          const Text(
            'PARÁMETROS TÉCNICOS DE INFRAESTRUCTURA',
            style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.black54),
          ),
          const SizedBox(height: 8),
          _buildDetailCard(Icons.dns_outlined, 'Frigate Server / API', '$frigateBaseUrl/api/config'),
          _buildDetailCard(Icons.stream_outlined, 'RTSP go2rtc Restream', currentCam['rtsp'] ?? 'N/A'),
          _buildDetailCard(Icons.storage_outlined, 'Almacenamiento Continuo', 'Modo: ALL (Retención 1 Día 24/7)'),
          _buildDetailCard(Icons.badge_outlined, 'Dashboard Flask / IAM', 'API /registros y /nfc/poll en $flaskDashboardUrl'),
        ],
      ),
    );
  }

  // Genera la vista de video
  Widget _buildVideoFeed(Map<String, dynamic> cam) {
    if (!_isStreaming) {
      return Container(
        color: Colors.black,
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: const [
              Icon(Icons.videocam_off, size: 40, color: Colors.white54),
              SizedBox(height: 6),
              Text('Transmisión pausada por el operador', style: TextStyle(fontSize: 11, color: Colors.white70)),
            ],
          ),
        ),
      );
    }

    final bool isEnabled = cam['enabled'] ?? true;
    if (!isEnabled) {
      return Container(
        color: const Color(0xFF1B1D21),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.videocam_off, color: kStatusWarning, size: 42),
              const SizedBox(height: 8),
              Text(
                '${cam['name']} está desactivada en config.yml',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13),
              ),
              const SizedBox(height: 4),
              const Text(
                'Frigate: campo enabled: false',
                style: TextStyle(color: Colors.white60, fontSize: 11),
              ),
            ],
          ),
        ),
      );
    }

    if (videoSourceType == 'frigate') {
      // Endpoint oficial reportado: GET /api/<camara>/latest.jpg?h=480
      final streamEndpoint = '$frigateBaseUrl/api/${cam['id']}/latest.jpg?h=480';
      return LiveStreamView(url: streamEndpoint);
    }

    if (videoSourceType == 'ip_webcam') {
      return LiveStreamView(url: customStreamUrl);
    }

    // Modo Demo (Simulación de Alta Calidad)
    return Container(
      decoration: const BoxDecoration(
        gradient: RadialGradient(
          center: Alignment.center,
          radius: 1.2,
          colors: [
            Color(0xFF1E2836),
            Color(0xFF0F141C),
          ],
        ),
      ),
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              _selectedCameraIndex == 0
                  ? Icons.sensor_door_outlined
                  : Icons.location_city_rounded,
              size: 46,
              color: kHubActionBlue,
            ),
            const SizedBox(height: 8),
            Text(cam['name']!, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white)),
            Text(cam['location']!, style: const TextStyle(color: Colors.white70, fontSize: 11)),
            const SizedBox(height: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: Colors.black54,
                borderRadius: BorderRadius.circular(4),
              ),
              child: const Text(
                'STREAM DEMO • FRIGATE NVR 24/7 ACTIVE',
                style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: Color(0xFF66E096)),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==================== PESTAÑA 2: RFID ACCESS LOGS ====================
  Widget _buildRfidLogsTab() {
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: const BoxDecoration(
            color: kHubSurface,
            border: Border(bottom: BorderSide(color: kHubBorder)),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: const [
                  Text('BITÁCORA DE CONTROL DE ACCESO', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: kHubSidebar)),
                  Text('Flask API: /registros & /nfc/poll', style: TextStyle(fontSize: 10, color: Colors.black54)),
                ],
              ),
              ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: kHubActionBlue,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  elevation: 0,
                ),
                icon: const Icon(Icons.tap_and_play, size: 18),
                label: const Text('Simular Pase', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                onPressed: _simulateCardSwipe,
              ),
            ],
          ),
        ),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.all(12),
            itemCount: accessEvents.length,
            itemBuilder: (context, index) {
              final ev = accessEvents[index];
              final isGranted = ev['status'] == 'GRANTED';
              final timeStr = DateFormat('HH:mm:ss').format(ev['time']);

              return Card(
                color: kHubSurface,
                margin: const EdgeInsets.only(bottom: 8),
                shape: RoundedRectangleBorder(
                  side: BorderSide(
                    color: isGranted ? kHubBorder : kStatusDanger.withValues(alpha: 0.6),
                    width: isGranted ? 1 : 1.5,
                  ),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: isGranted
                              ? kStatusSuccess.withValues(alpha: 0.12)
                              : kStatusDanger.withValues(alpha: 0.12),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          isGranted ? Icons.check_circle_outline : Icons.warning_amber_rounded,
                          color: isGranted ? kStatusSuccess : kStatusDanger,
                          size: 22,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(
                                  ev['user'],
                                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: kHubSidebar),
                                ),
                                Text(
                                  timeStr,
                                  style: const TextStyle(color: Colors.black45, fontSize: 11, fontFamily: 'monospace'),
                                ),
                              ],
                            ),
                            const SizedBox(height: 2),
                            Text(ev['role'], style: const TextStyle(fontSize: 11, color: Colors.black87)),
                            const SizedBox(height: 6),
                            Row(
                              children: [
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: kHubBackground,
                                    borderRadius: BorderRadius.circular(4),
                                    border: Border.all(color: kHubBorder),
                                  ),
                                  child: Text(
                                    'UID: ${ev['uid']}',
                                    style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: kHubActionBlue, fontWeight: FontWeight.bold),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Text(
                                  ev['verifiedBy'],
                                  style: const TextStyle(fontSize: 10, color: Colors.black54),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildDetailCard(IconData icon, String title, String subtitle) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: kHubSurface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: kHubBorder),
      ),
      child: Row(
        children: [
          Icon(icon, size: 20, color: kHubActionBlue),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(fontSize: 11, color: Colors.black54)),
                Text(subtitle, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: kHubSidebar)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// Widget que refresca el snapshot cada 90ms para video continuo sin lag
class LiveStreamView extends StatefulWidget {
  final String url;
  const LiveStreamView({super.key, required this.url});

  @override
  State<LiveStreamView> createState() => _LiveStreamViewState();
}

class _LiveStreamViewState extends State<LiveStreamView> {
  late Timer _timer;
  int _tick = 0;

  @override
  void initState() {
    super.initState();
    // Refresco a 90ms (~11 FPS) para respuesta fluida
    _timer = Timer.periodic(const Duration(milliseconds: 90), (_) {
      if (mounted) setState(() => _tick++);
    });
  }

  @override
  void dispose() {
    _timer.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    String baseUrl = widget.url;
    if (baseUrl.endsWith('/video')) {
      baseUrl = baseUrl.replaceAll('/video', '/shot.jpg');
    }

    final sep = baseUrl.contains('?') ? '&' : '?';
    final freshUrl = '$baseUrl${sep}_t=$_tick';

    return Image.network(
      freshUrl,
      fit: BoxFit.cover,
      gaplessPlayback: true,
      loadingBuilder: (context, child, loadingProgress) {
        if (loadingProgress == null) return child;
        return Container(
          color: Colors.black,
          child: const Center(
            child: CircularProgressIndicator(color: kHubActionBlue, strokeWidth: 2),
          ),
        );
      },
      errorBuilder: (context, error, stackTrace) {
        return Container(
          color: Colors.black,
          padding: const EdgeInsets.all(12),
          child: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.wifi_off_rounded, color: kStatusWarning, size: 36),
                const SizedBox(height: 8),
                Text(
                  'Conectando al stream...\n$baseUrl\n\nVerifica la conexión al servidor local',
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontSize: 10, color: Colors.white70),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
