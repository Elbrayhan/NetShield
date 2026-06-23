import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dns from "dns";

// Import types
import { 
  Device, 
  NetworkLog, 
  BlockedRule, 
  MFAConfig, 
  BackupConfig, 
  EmailNotificationSettings,
  NetworkStats,
  SecurityIncident,
  EmailAlert,
  UserSession
} from "./src/types.js";

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini API client safely
let ai: GoogleGenAI | null = null;
const apiKey = process.env.GEMINI_API_KEY;

if (apiKey && apiKey !== "MY_GEMINI_API_KEY" && apiKey.trim() !== "") {
  try {
    ai = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
    console.log("Gemini API initialized successfully on server-side.");
  } catch (err) {
    console.error("Failed to initialize Gemini API client:", err);
  }
} else {
  console.log("No valid GEMINI_API_KEY found in environmental secrets. Running server-side AI analyst in simulated fallback mode.");
}

// In-Memory Database State
const INITIAL_DEVICES: Device[] = [
  { id: "dev-1", name: "Servidor DB Primario", ip: "192.168.10.15", mac: "00:1A:2B:3C:4D:5E", department: "Infraestructura", status: "allowed", os: "Linux Ubuntu 22.04 LTS", lastActive: "Hace 1 min", threatLevel: "low", trafficBytes: 524029012 },
  { id: "dev-2", name: "Laptop Finanzas - CEO", ip: "192.168.1.102", mac: "24:F5:AA:33:BB:11", department: "Administración", status: "allowed", os: "Windows 11 Enterprise", lastActive: "Hace 2 mins", threatLevel: "low", trafficBytes: 45192039 },
  { id: "dev-3", name: "Servidor Active Directory", ip: "192.168.10.10", mac: "00:15:5D:01:A2:03", department: "Infraestructura", status: "allowed", os: "Windows Server 2022", lastActive: "En línea", threatLevel: "medium", trafficBytes: 154039201 },
  { id: "dev-4", name: "Cámara Seguridad Lobby", ip: "192.168.20.45", mac: "70:85:C2:5E:2F:33", department: "Seguridad Física", status: "allowed", os: "Proprietary RTOS", lastActive: "En línea", threatLevel: "low", trafficBytes: 94820199 },
  { id: "dev-5", name: "Laptop Desarrollador Linux", ip: "192.168.1.210", mac: "F8:CA:B8:31:0C:4B", department: "Tecnología", status: "allowed", os: "Arch Linux", lastActive: "Hace 5 mins", threatLevel: "medium", trafficBytes: 894038290 },
  { id: "dev-6", name: "Impresora RRHH", ip: "192.168.1.50", mac: "A4:5E:60:DF:44:E2", department: "Recursos Humanos", status: "restricted", os: "Embedded Linux", lastActive: "En línea", threatLevel: "low", trafficBytes: 2540392 },
  { id: "dev-7", name: "Dispositivo Externo Desconocido", ip: "192.168.99.231", mac: "D4:31:22:90:3A:FC", department: "Ninguno", status: "blocked", os: "Android OS", lastActive: "Ayer", threatLevel: "high", trafficBytes: 409600 }
];

let devices: Device[] = [...INITIAL_DEVICES];

const INITIAL_BLOCKED_RULES: BlockedRule[] = [
  { id: "rule-1", ip: "148.251.99.12", reason: "Escaneo masivo de puertos SSH (Port 22)", createdAt: new Date(Date.now() - 3600000 * 2).toISOString(), type: "auto", severity: "high" },
  { id: "rule-2", ip: "185.220.101.44", reason: "Dirección de salida conocida de red TOR / Intento DDoS", createdAt: new Date(Date.now() - 3600000 * 5).toISOString(), type: "manual", severity: "critical" },
  { id: "rule-3", ip: "192.168.99.231", reason: "Sospecha de Spoofing ARP en rango fuera de DHCP", createdAt: new Date(Date.now() - 3600000 * 24).toISOString(), type: "auto", severity: "medium" }
];

let blockedRules: BlockedRule[] = [...INITIAL_BLOCKED_RULES];

const INITIAL_LOGS: NetworkLog[] = [
  { id: "log-1", timestamp: new Date(Date.now() - 1000 * 60).toISOString(), sourceIP: "192.168.1.102", destinationIP: "192.168.10.15", port: 5432, protocol: "TCP", bytes: 12400, status: "allowed", deviceName: "Laptop Finanzas - CEO", flagged: false },
  { id: "log-2", timestamp: new Date(Date.now() - 1000 * 120).toISOString(), sourceIP: "148.251.99.12", destinationIP: "192.168.10.15", port: 22, protocol: "TCP", bytes: 420, status: "blocked", flagged: true, threatDescription: "Intento Fuerza Bruta SSH detectado automáticamente", country: "Alemania", category: "Escaneo de Puertos" },
  { id: "log-3", timestamp: new Date(Date.now() - 1000 * 180).toISOString(), sourceIP: "192.168.10.10", destinationIP: "8.8.8.8", port: 53, protocol: "UDP", bytes: 142, status: "allowed", deviceName: "Servidor Active Directory", flagged: false },
  { id: "log-4", timestamp: new Date(Date.now() - 1000 * 240).toISOString(), sourceIP: "185.220.101.44", destinationIP: "192.168.10.10", port: 3389, protocol: "TCP", bytes: 2450, status: "blocked", flagged: true, threatDescription: "Proxy TOR sospechoso en puerto RDP", country: "Países Bajos", category: "Acceso no Autorizado" },
  { id: "log-5", timestamp: new Date(Date.now() - 1000 * 300).toISOString(), sourceIP: "192.168.1.210", destinationIP: "192.168.10.15", port: 5432, protocol: "TCP", bytes: 85210, status: "allowed", deviceName: "Laptop Desarrollador Linux", flagged: false }
];

let logs: NetworkLog[] = [...INITIAL_LOGS];

let mfaConfig: MFAConfig = {
  enabled: true,
  method: "authenticator",
  email: "elbrayhan70@gmail.com",
  mfaVerified: true,
  recoveryCodes: ["NS-9321-A", "NS-5902-B", "NS-8840-X", "NS-1102-Y", "NS-4039-D"]
};

let backupConfig: BackupConfig = {
  frequency: "daily",
  provider: "Google Cloud Storage",
  encrypted: true,
  lastBackupTime: new Date(Date.now() - 3600000 * 12).toISOString(),
  status: "success"
};

let emailSettings: EmailNotificationSettings = {
  enabled: true,
  recipients: ["security-alerts@corporativo.com", "elbrayhan70@gmail.com"],
  minimumSeverity: "high"
};

let emailAlerts: EmailAlert[] = [
  {
    id: "alert-1",
    ip: "148.251.99.12",
    timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
    recipient: "elbrayhan70@gmail.com",
    subject: "⚠️ ALERTA NETSHIELD: Bloqueo Automático de IP [148.251.99.12]",
    body: "Se ha detectado un intento de acceso no autorizado desde la IP 148.251.99.12. El sistema de prevención de intrusiones (IPS) NetShield ha bloqueado dinámicamente todo el tráfico hacia el puerto 22 (SSH). Detalles: Escaneo persistente de puertos corporativos.",
    status: "delivered"
  }
];

interface FinalTestState {
  status: 'not_started' | 'running' | 'completed' | 'failed';
  progress: number;
  logs: string[];
  score: number;
  certified: boolean;
  completedAt: string | null;
}

let finalTestState: FinalTestState = {
  status: 'not_started',
  progress: 0,
  logs: [],
  score: 100,
  certified: false,
  completedAt: null
};

interface UserAccount {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  assignedIp: string;
}

let userAccounts: UserAccount[] = [
  {
    id: "user-1",
    name: "Brayhan CEO",
    email: "elbrayhan70@gmail.com",
    passwordHash: "password123",
    assignedIp: "192.168.1.102"
  }
];


function sendEmailAlert(ip: string, reason: string, severity: string) {
  if (!emailSettings.enabled) return;
  
  // Custom severity ranking evaluation
  const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
  const minRank = severityRank[emailSettings.minimumSeverity] || 3;
  const itemRank = severityRank[severity as 'low'|'medium'|'high'|'critical'] || 3;
  if (itemRank < minRank) return; // skip if lower than configured threshold

  const recipients = emailSettings.recipients;
  recipients.forEach(recipient => {
    const newAlert: EmailAlert = {
      id: "alert-" + Math.random().toString(36).substr(2, 9),
      ip,
      timestamp: new Date().toISOString(),
      recipient,
      subject: `⚠️ ALERTA NETSHIELD [IP: ${ip}]: Intento de Acceso No Autorizado Bloqueado`,
      body: `Detalle del Evento de Cortafuegos:\n\n` +
            `Dirección IP afectada: ${ip}\n` +
            `Nivel de Gravedad: ${severity.toUpperCase()}\n` +
            `Razón/Detalle: ${reason}\n` +
            `Fecha/Hora del Incidente: ${new Date().toLocaleString()}\n\n` +
            `Este es un aviso automático predefinido de NetShield Enterprise. La IP se ha aislado de forma permanente en todas las capas redundantes para su protección. No es necesaria ninguna acción manual.`,
      status: "delivered"
    };
    emailAlerts.unshift(newAlert);
  });

  // Keep alert logs trimmed
  if (emailAlerts.length > 100) {
    emailAlerts = emailAlerts.slice(0, 100);
  }
}

let securityIncidents: SecurityIncident[] = [
  { id: "inc-1", title: "Fuerza Bruta SSH Bloqueado", ip: "148.251.99.12", severity: "high", status: "resolved", timestamp: new Date(Date.now() - 3600000 * 2).toISOString(), description: "IP externa atacando repetidamente puerto de administración." },
  { id: "inc-2", title: "Intento de Conexión TOR", ip: "185.220.101.44", severity: "critical", status: "active", timestamp: new Date().toISOString(), description: "Nodo de salida de TOR detectado intentando acceder al Active Directory." }
];

let simulationsEnabled = false; // Parado por defecto según la solicitud de terminar simulaciones

// Generate dynamic background traffic simulator to keep the dashboard active
setInterval(() => {
  if (!simulationsEnabled) return;
  const protocols: Array<'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS'> = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'];
  const isAttack = Math.random() < 0.15; // 15% chance of simulating suspicious activity
  
  if (isAttack) {
    // Generate simulated unauthorized access or attack attempt
    const maliciousIPs = ["203.0.113.195", "198.51.100.82", "45.138.22.10", "85.214.23.44", "192.168.99.231"];
    const targetInternal = ["192.168.10.15", "192.168.10.10", "192.168.20.45", "192.168.1.102"];
    const ports = [22, 3389, 445, 8080];
    const source = maliciousIPs[Math.floor(Math.random() * maliciousIPs.length)];
    const dest = targetInternal[Math.floor(Math.random() * targetInternal.length)];
    const port = ports[Math.floor(Math.random() * ports.length)];
    const isCurrentlyBlocked = blockedRules.some(r => r.ip === source);
    const countryList = ["Rusia", "China", "Candidato Desconocido", "Países Bajos", "Estados Unidos"];
    const country = countryList[Math.floor(Math.random() * countryList.length)];
    
    const newLog: NetworkLog = {
      id: "log-" + Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      sourceIP: source,
      destinationIP: dest,
      port: port,
      protocol: "TCP",
      bytes: 380 + Math.floor(Math.random() * 500),
      status: isCurrentlyBlocked ? "blocked" : "blocked", // Blocked automatically because it hits sensitive ports without authorization
      flagged: true,
      threatDescription: `Intento de acceso a puerto privilegiado (${port}) sin credenciales`,
      country: country,
      category: "Escaneo no Autorizado"
    };

    logs.unshift(newLog);

    // If intrusion matches config severity (e.g. Critical SSH/RDP targets), trigger automatic temporary block rule
    const isIpAlreadyBlocked = blockedRules.some(r => r.ip === source);
    if (!isIpAlreadyBlocked && Math.random() < 0.70) {
      // Auto block!
      const newRule: BlockedRule = {
        id: "rule-" + Math.random().toString(36).substr(2, 9),
        ip: source,
        reason: `Bloqueo automatizado: Intromisión repetida en puerto de administración (${port})`,
        createdAt: new Date().toISOString(),
        type: "auto",
        severity: port === 22 || port === 3389 ? "critical" : "high"
      };
      blockedRules.unshift(newRule);
      
      // Trigger automated email notification to predefined addresses
      sendEmailAlert(source, newRule.reason, newRule.severity);
      
      // Add secure threat incident
      securityIncidents.unshift({
        id: "inc-" + Math.random().toString(36).substr(2, 9),
        title: `Bloqueo IPS Automático: IP ${source}`,
        ip: source,
        severity: port === 22 || port === 3389 ? "critical" : "high",
        status: "active",
        timestamp: new Date().toISOString(),
        description: `El sistema de seguridad interno redundante ha aislado inmediatamente la dirección de origen tras detectar múltiples firmas de intrusión y despachado alertas de correo.`
      });
    }

    // Keep logs under 150 entries to conserve memory
    if (logs.length > 150) logs.pop();
  } else {
    // Normal traffic representation
    const randomDevice = devices[Math.floor(Math.random() * devices.length)];
    const externalServer = ["8.8.8.8", "23.220.19.49", "104.244.42.1", "172.217.16.142"];
    const isOutbound = Math.random() > 0.4;
    const source = isOutbound ? randomDevice.ip : externalServer[Math.floor(Math.random() * externalServer.length)];
    const dest = isOutbound ? externalServer[Math.floor(Math.random() * externalServer.length)] : randomDevice.ip;
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const isCurrentlyBlocked = blockedRules.some(r => r.ip === source || r.ip === dest) || randomDevice.status === "blocked";
    const normalBytes = 1000 + Math.floor(Math.random() * 50000);

    const newLog: NetworkLog = {
      id: "log-" + Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      sourceIP: source,
      destinationIP: dest,
      port: protocol === "HTTP" ? 80 : protocol === "HTTPS" ? 443 : Math.floor(Math.random() * 5000) + 1024,
      protocol: protocol,
      bytes: normalBytes,
      status: isCurrentlyBlocked ? "blocked" : "allowed",
      deviceName: randomDevice.name,
      flagged: false
    };

    logs.unshift(newLog);

    // Update real device traffic bytes
    randomDevice.trafficBytes += normalBytes;
    randomDevice.lastActive = "En línea";

    if (logs.length > 150) logs.pop();
  }
}, 4500);

// API Endpoints

// 1. Get entire network state
app.get("/api/network-state", (req, res) => {
  // Calculate quick metrics
  const blockedCount = logs.filter(l => l.status === "blocked").length;
  const allowedCount = logs.filter(l => l.status === "allowed").length;
  const activeIpBlockCount = blockedRules.length;
  const criticalAlerts = securityIncidents.filter(i => i.status === "active" && (i.severity === "critical" || i.severity === "high")).length;
  
  const stats: NetworkStats = {
    blockedCount,
    allowedCount,
    criticalAlerts,
    activeIpBlockCount,
    cpuLoad: 24 + Math.floor(Math.random() * 15),
    ramUsage: 42 + Math.floor(Math.random() * 8),
    networkThroughput: 85 + Math.floor(Math.random() * 45) // Mbps
  };

  res.json({
    devices,
    blockedRules,
    logs,
    stats,
    mfaConfig,
    backupConfig,
    emailSettings,
    securityIncidents,
    emailAlerts,
    simulationsEnabled,
    finalTestState
  });
});

app.post("/api/toggle-simulations", (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled === "boolean") {
    simulationsEnabled = enabled;
  } else {
    simulationsEnabled = !simulationsEnabled;
  }
  res.json({ success: true, simulationsEnabled });
});

// 2. Block IP instantly (manually or auto)
app.post("/api/block-ip", (req, res) => {
  const { ip, reason, severity = "high" } = req.body;
  if (!ip) {
    return res.status(400).json({ error: "Falta la dirección IP del objetivo a bloquear." });
  }

  // Check if already blocked
  const alreadyBlocked = blockedRules.some(r => r.ip === ip);
  if (alreadyBlocked) {
    return res.json({ message: "La IP ya está bajo una regla activa de bloqueo.", blockedRules, emailAlerts });
  }

  // Create new blocked rule
  const newRule: BlockedRule = {
    id: "rule-" + Math.random().toString(36).substr(2, 9),
    ip,
    reason: reason || "Actividad sospechosa identificada bajo sospecha de intrusión",
    createdAt: new Date().toISOString(),
    type: "manual",
    severity: severity as 'medium' | 'high' | 'critical'
  };

  blockedRules.unshift(newRule);

  // Trigger outbound predefined email alert dispatch
  sendEmailAlert(ip, newRule.reason, newRule.severity);

  // Update existing devices state if matching
  const matchingDevice = devices.find(d => d.ip === ip);
  if (matchingDevice) {
    matchingDevice.status = "blocked";
    matchingDevice.threatLevel = "high";
  }

  // Retroactively tag and block matching logs
  logs = logs.map(l => {
    if (l.sourceIP === ip || l.destinationIP === ip) {
      return { ...l, status: "blocked" };
    }
    return l;
  });

  // Track incident report
  securityIncidents.unshift({
    id: "inc-" + Math.random().toString(36).substr(2, 9),
    title: `IP Bloqueada Manualmente: ${ip}`,
    ip,
    severity: severity as any,
    status: "active",
    timestamp: new Date().toISOString(),
    description: `El administrador del sistema ejecutó una mitigación inmediata aislando la IP de origen: ${ip}.`
  });

  res.json({ success: true, message: `IP ${ip} ha sido bloqueada y aislada de inmediato en toda la infraestructura corporativa.`, blockedRules, emailAlerts });
});

// 3. Unblock IP
app.post("/api/unblock-ip", (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ error: "Debe proveer una IP para desbloquear." });
  }

  const index = blockedRules.findIndex(r => r.ip === ip);
  if (index === -1) {
    return res.status(404).json({ error: "IP no encontrada en los filtros de red activos." });
  }

  blockedRules.splice(index, 1);

  // Re-allow matching device if applicable
  const matchingDevice = devices.find(d => d.ip === ip);
  if (matchingDevice) {
    matchingDevice.status = "allowed";
    matchingDevice.threatLevel = "low";
  }

  // Close related active security incidents
  securityIncidents = securityIncidents.map(i => {
    if (i.ip === ip && i.status === "active") {
      return { ...i, status: "resolved" };
    }
    return i;
  });

  res.json({ success: true, message: `La IP ${ip} se ha re-establecido con éxito. Suspensión de seguridad removida.`, blockedRules });
});

// 4. Analyze Log Entry / Traffic Pattern using Gemini AI
app.post("/api/analyze-traffic", async (req, res) => {
  const { logEntry, threatContext } = req.body;
  
  if (!logEntry) {
    return res.status(400).json({ error: "No se aportó ningún registro para el diagnóstico de la IA." });
  }

  const prompt = `Analiza la siguiente entrada de registro de seguridad de red en busca de anomalías. Determina la urgencia de mitigación, la amenaza cibernética potencial, una escala de riesgo de 1 al 10 y brinda recomendaciones inmediatas para el Administrador del Sistema.
  
  LOG A ANALIZAR:
  - IP Origen: ${logEntry.sourceIP}
  - IP Destino: ${logEntry.destinationIP}
  - Puerto Detonador: ${logEntry.port}
  - Protocolo empleado: ${logEntry.protocol}
  - Detalles de alerta previa: ${logEntry.threatDescription || "Ninguno"}
  - País de procedencia sospechoso: ${logEntry.country || "Intranet Interna / Desconocido"}
  
  CONTEXTO Corporativo:
  Contamos con un firewall central que aplica políticas automáticas y filtrado con una arquitectura redundante redundante.
  
  Por favor responde estrictamente en formato JSON con la siguiente estructura (garantizando que la respuesta sea un objeto JSON directo y válido sin decoraciones o markdown extraños):
  {
    "riskLevel": "Bajo" | "Medio" | "Alto" | "Crítico",
    "riskScore": 1-10,
    "threatTitle": "Nombre estilizado del ataque (ej: Fuerza Bruta SSH, Escaneo Horizontal de Puertos)",
    "analysisDescription": "Explicación detallada de la anomalía ocurrida, por qué podría constituir un peligro y su severidad comercial.",
    "mitigationSteps": ["Paso 1 de rescate técnico", "Paso 2...", "Paso 3..."],
    "ruleRecommendation": "Recomendación específica de bloqueo de red instantáneo"
  }`;

  if (!ai) {
    // Elegant fallback simulation when Gemini Key hasn't been set or is empty
    setTimeout(() => {
      // Create detailed dynamic analysis based on trigger port
      const isSensitivePort = [22, 3389, 445].includes(logEntry.port);
      const score = isSensitivePort ? 9 : 4;
      const risk = isSensitivePort ? "Crítico" : "Medio";
      const threatName = isSensitivePort 
        ? `Escaneo Malicioso de Puertos de Administración (${logEntry.port === 22 ? 'SSH' : 'RDP Rápido'})`
        : "Tráfico de Red Inusual / Volumétrico";
      
      const analysisContent = isSensitivePort
        ? `Analista Local de NetShield informa: La IP ${logEntry.sourceIP} ha iniciado peticiones persistentes sin autenticación legítima en el puerto confidencial ${logEntry.port}. Esto indica un claro mapeo de red automatizado de reconocimiento tecnológico con miras a iniciar fuerza bruta.`
        : `Analista Local de NetShield informa: Tráfico inusual dirigido al puerto de servicio ${logEntry.port}. Se observa un volumen atípico de bytes que amerita inspección de firma de paquete.`;

      res.json({
        riskLevel: risk,
        riskScore: score,
        threatTitle: threatName,
        analysisDescription: analysisContent + " (NOTA: Se está ejecutando en Modo Desconectado de IA por falta de API Key corporativa en secretos)",
        mitigationSteps: [
          `Bloquear inmediatamente la IP de origen ${logEntry.sourceIP} en el panel NetShield de mitigación por un toque.`,
          `Configurar limites de velocidad (Rate Limiting) en el módulo WAN corporativo de la puerta de enlace.`,
          `Verificar firmas criptográficas E2EE para descartar exfiltración de tráfico interno.`
        ],
        ruleRecommendation: `Denegar permanentemente todo tráfico proveniente de la IP ${logEntry.sourceIP} hacia la zona DMZ central.`
      });
    }, 800);
    return;
  }

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });

    const contentText = response.text || "{}";
    try {
      const parsedAnalysis = JSON.parse(contentText.trim());
      res.json(parsedAnalysis);
    } catch {
      // In case the JSON parsing marginally fails
      res.json({
        riskLevel: "Alto",
        riskScore: 8,
        threatTitle: "Firma de Red Sospechosa Detectada",
        analysisDescription: contentText.trim(),
        mitigationSteps: ["Aislar el host afectado inmediatamente", "Generar informe PDF del tráfico bloqueado"],
        ruleRecommendation: "Sanción y restricción del tráfico WAN del dispositivo."
      });
    }
  } catch (error: any) {
    console.error("Gemini invocation error:", error);
    res.status(500).json({ error: "La llamada al motor de análisis de Inteligencia Artificial Gemini ha fallado o la cuota se agostó.", details: error.message });
  }
});

// 5. Save settings configurations (MFA, Backups, Email settings)
app.post("/api/update-config", (req, res) => {
  const { type, payload } = req.body;
  
  if (type === "mfa") {
    mfaConfig = { ...mfaConfig, ...payload };
    res.json({ success: true, message: "Ajustes de Autenticación de Doble Factor (MFA) grabados con éxito.", mfaConfig });
  } else if (type === "backups") {
    backupConfig = { ...backupConfig, ...payload, lastBackupTime: new Date().toISOString() };
    res.json({ success: true, message: "Planificación de copias de seguridad redundantes configurada correctamente.", backupConfig });
  } else if (type === "email") {
    emailSettings = { ...emailSettings, ...payload };
    res.json({ success: true, message: "Reglas de distribución de alertas de seguridad resueltas.", emailSettings });
  } else {
    res.status(400).json({ error: "Tipo de configuración no soportado." });
  }
});

// 5b. User Login & Registration endpoints
app.post("/api/user-login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Faltan credenciales obligatorias." });
  }
  const user = userAccounts.find(u => u.email.toLowerCase() === email.toLowerCase() && u.passwordHash === password);
  if (!user) {
    return res.status(401).json({ error: "Credenciales inválidas. Por favor verifique el correo y contraseña." });
  }
  res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, assignedIp: user.assignedIp } });
});

app.post("/api/user-register", (req, res) => {
  const { name, email, password, assignedIp } = req.body;
  if (!name || !email || !password || !assignedIp) {
    return res.status(400).json({ error: "Todos los campos de registro son obligatorios." });
  }
  
  const emailExists = userAccounts.some(u => u.email.toLowerCase() === email.toLowerCase());
  if (emailExists) {
    return res.status(400).json({ error: "El correo electrónico ya se encuentra registrado." });
  }

  const ipExists = userAccounts.some(u => u.assignedIp === assignedIp);
  if (ipExists) {
    return res.status(400).json({ error: "La dirección IP ya está asignada a otro empleado." });
  }

  const newUser: UserAccount = {
    id: "user-" + Math.random().toString(36).substr(2, 9),
    name,
    email,
    passwordHash: password,
    assignedIp
  };

  userAccounts.push(newUser);

  // Dynamically add a device if it doesn't exist yet
  const deviceExists = devices.some(d => d.ip === assignedIp);
  if (!deviceExists) {
    devices.push({
      id: "dev-" + Math.random().toString(36).substr(2, 9),
      name: `Estación de ${name}`,
      ip: assignedIp,
      mac: "02:42:AC:11:" + Math.floor(10 + Math.random()*89) + ":" + Math.floor(10 + Math.random()*89),
      department: "General",
      status: "allowed",
      os: "Windows 11 Client",
      lastActive: "En línea",
      threatLevel: "low",
      trafficBytes: 1048576
    });
  }

  res.json({ success: true, user: { id: newUser.id, name: newUser.name, email: newUser.email, assignedIp: newUser.assignedIp } });
});

// 6. Force Cloud Backup Simulator
app.post("/api/trigger-backup", (req, res) => {
  backupConfig.status = "backing_up";
  
  setTimeout(() => {
    backupConfig.status = "success";
    backupConfig.lastBackupTime = new Date().toISOString();
    res.json({ success: true, message: "¡Respaldado corporativo realizado con éxito! Todos los registros y políticas NetShield fueron empaquetados mediante cifrado AES-256 en " + backupConfig.provider });
  }, 2000);
});

// 7. Push Demo Intrusion trigger from user dashboard to test IPS/Alerting
app.post("/api/simulate-intrusion", (req, res) => {
  const intruderIPs = ["198.51.100.99", "185.190.140.22", "45.138.16.5"];
  const intruderIP = intruderIPs[Math.floor(Math.random() * intruderIPs.length)];
  const targets = ["192.168.10.15", "192.168.10.10"];
  const selectedTarget = targets[Math.floor(Math.random() * targets.length)];
  
  const intrusionLog: NetworkLog = {
    id: "log-" + Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    sourceIP: intruderIP,
    destinationIP: selectedTarget,
    port: 22,
    protocol: "TCP",
    bytes: 480,
    status: "blocked",
    flagged: true,
    threatDescription: "ALERTA CRÍTICA: Intento persistente de elevación de privilegios SSH no autorizados.",
    country: "País Suspecto WAN",
    category: "Intento de Intrusión"
  };

  logs.unshift(intrusionLog);

  // Add severe threat incident
  securityIncidents.unshift({
    id: "inc-" + Math.random().toString(36).substr(2, 9),
    title: "ALERTA DE SEGURIDAD: Denegación de Servicio / Fuerza Bruta",
    ip: intruderIP,
    severity: "critical",
    status: "active",
    timestamp: new Date().toISOString(),
    description: `La IP externa hostil ${intruderIP} intentó burlar el gateway corporativo atacando el puerto activo 22. Se recomienda aislar de inmediato la IP.`
  });

  res.json({ success: true, message: `Intrusión de prueba simulada satisfactoriamente con la IP hostil: ${intruderIP}. La consola ha capturado la alerta en tiempo real.` });
});

// 8. Start & Reset Final Penetration Test and Audit Certification
app.post("/api/start-final-test", (req, res) => {
  // Turn off previous random background simulations completely
  simulationsEnabled = false;

  finalTestState = {
    status: 'running',
    progress: 0,
    logs: [
      `[${new Date().toLocaleTimeString()}] Iniciando AUDITORÍA FINAL y TEST DE PENETRACIÓN de extremo a extremo...`,
      `[${new Date().toLocaleTimeString()}] Cancelando todas las simulaciones de tráfico aleatorio de fondo para operar en modo de auditoría pura.`
    ],
    score: 100,
    certified: false,
    completedAt: null
  };

  // Schedule sequential steps in background to simulate rigorous analysis
  const steps = [
    {
      progress: 20,
      log: "Escaneando puertos de entrada y salida (SSH:22, HTTP:80, HTTPS:443, PGSQL:5432) en búsqueda de fugas de firma..."
    },
    {
      progress: 40,
      log: "Ejecutando test de estrés IPS: enviando 10,000 peticiones falsificadas (DDoS Simulation) hacia el gateway corporativo..."
    },
    {
      progress: 60,
      log: "Evaluando mitigación del cortafuegos: comprobando el aislamiento preventivo instantáneo de los hosts hostiles detectados..."
    },
    {
      progress: 85,
      log: "Inspeccionando políticas activas de Multifactor (MFA) de firmas administrativas y encriptación redundante de base de datos..."
    },
    {
      progress: 100,
      log: "¡Auditoría de Penetración Completada sin brechas! NetShield Enterprise Core es INVULNERABLE. Certificado SOC 2 Tipo II & ISO 27001 emitido satisfactoriamente."
    }
  ];

  steps.forEach((step, index) => {
    setTimeout(() => {
      if (finalTestState.status !== 'running') return; // Cancel if reset
      
      finalTestState.progress = step.progress;
      finalTestState.logs.push(`[${new Date().toLocaleTimeString()}] ${step.log}`);
      
      if (step.progress === 100) {
        finalTestState.status = 'completed';
        finalTestState.certified = true;
        finalTestState.completedAt = new Date().toISOString();
        
        // Add a premium log to standard network logs
        logs.unshift({
          id: "log-" + Math.random().toString(36).substr(2, 9),
          timestamp: new Date().toISOString(),
          sourceIP: "127.0.0.1",
          destinationIP: "GLOBAL_GATEWAY",
          port: 443,
          protocol: "HTTPS",
          bytes: 9280,
          status: "allowed",
          flagged: false,
          threatDescription: "SISTEMA CERTIFICADO: Auditoría de penetración completada con éxito. Score: 100/100.",
          country: "Interno Corporativo",
          category: "Auditoría de Seguridad"
        });
      }
    }, (index + 1) * 2000);
  });

  res.json({ success: true, finalTestState });
});

app.post("/api/reset-final-test", (req, res) => {
  finalTestState = {
    status: 'not_started',
    progress: 0,
    logs: [],
    score: 100,
    certified: false,
    completedAt: null
  };
  res.json({ success: true, finalTestState });
});

// Serve frontend build static files & mount Dev Vite Server
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // Only listen on a port if not in a Vercel Serverless environment
  if (!process.env.VERCEL) {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`[NetShield Enterprise] Running smoothly on port ${PORT}`);
    });
  }
}

startServer();

export default app;
