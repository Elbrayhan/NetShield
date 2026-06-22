import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Wifi, 
  FileDown, 
  AlertOctagon, 
  Server, 
  Lock, 
  Key, 
  RefreshCw, 
  Undo,
  Search, 
  Cpu, 
  FileSpreadsheet, 
  Plus, 
  Trash2, 
  UserCheck, 
  Mail, 
  Layers, 
  Zap, 
  Database,
  CloudLightning,
  AlertCircle,
  Clock,
  Eye,
  Filter,
  Users
} from 'lucide-react';

import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';

import { jsPDF } from 'jspdf';
import 'jspdf-autotable';

import { 
  Device, 
  NetworkLog, 
  BlockedRule, 
  MFAConfig, 
  BackupConfig, 
  EmailNotificationSettings,
  NetworkStats,
  SecurityIncident
} from '../types';

interface AdminPanelProps {
  devices: Device[];
  blockedRules: BlockedRule[];
  logs: NetworkLog[];
  stats: NetworkStats;
  mfaConfig: MFAConfig;
  backupConfig: BackupConfig;
  emailSettings: EmailNotificationSettings;
  securityIncidents: SecurityIncident[];
  onRefresh: () => void;
  onBlockIp: (ip: string, reason: string, severity: string) => Promise<any>;
  onUnblockIp: (ip: string) => Promise<any>;
  onUpdateConfig: (type: string, payload: any) => Promise<any>;
  onTriggerBackup: () => Promise<any>;
  onSimulateIntrusion: () => Promise<any>;
}

export default function AdminPanel({
  devices,
  blockedRules,
  logs,
  stats,
  mfaConfig,
  backupConfig,
  emailSettings,
  securityIncidents,
  onRefresh,
  onBlockIp,
  onUnblockIp,
  onUpdateConfig,
  onTriggerBackup,
  onSimulateIntrusion
}: AdminPanelProps) {
  
  // State for search & filters
  const [logSearchQuery, setLogSearchQuery] = useState('');
  const [logStatusFilter, setLogStatusFilter] = useState<'all' | 'allowed' | 'blocked'>('all');
  const [selectedDeviceFilter, setSelectedDeviceFilter] = useState<string | null>(null);
  
  // State for manual IP blocking form
  const [manualIp, setManualIp] = useState('');
  const [manualReason, setManualReason] = useState('');
  const [manualSeverity, setManualSeverity] = useState('high');
  const [blockingStatusMsg, setBlockingStatusMsg] = useState('');

  // AI Assistant modal state
  const [aiAnalysisLog, setAiAnalysisLog] = useState<NetworkLog | null>(null);
  const [aiAnalysisResult, setAiAnalysisResult] = useState<any | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Backup loading state
  const [isBackingUp, setIsBackingUp] = useState(false);
  const [backupSuccessMsg, setBackupSuccessMsg] = useState('');

  // Configuration edit forms state
  const [editMfaMethod, setEditMfaMethod] = useState(mfaConfig.method);
  const [editMfaEnabled, setEditMfaEnabled] = useState(mfaConfig.enabled);
  const [editBackupFreq, setEditBackupFreq] = useState(backupConfig.frequency);
  const [editBackupProvider, setEditBackupProvider] = useState(backupConfig.provider);
  const [editEmailRecipients, setEditEmailRecipients] = useState(emailSettings.recipients.join(', '));
  const [editEmailSeverity, setEditEmailSeverity] = useState(emailSettings.minimumSeverity);
  const [configResultMsg, setConfigResultMsg] = useState('');

  // Active admin views: 'dashboard' | 'devices' | 'rules' | 'alerts' | 'backups'
  const [activeTab, setActiveTab] = useState<'general' | 'devices' | 'rules' | 'config'>('general');

  // Multi-factor simulator challenge state
  const [mfaChallenge, setMfaChallenge] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [isMfaVerified, setIsMfaVerified] = useState(mfaConfig.mfaVerified);
  const [mfaErrorMsg, setMfaErrorMsg] = useState('');

  // Trigger auto refresh simulation statistics every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      onRefresh();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // Filter logs list based on user controls
  const filteredLogs = logs.filter(log => {
    const matchesSearch = 
      log.sourceIP.includes(logSearchQuery) || 
      log.destinationIP.includes(logSearchQuery) || 
      (log.deviceName && log.deviceName.toLowerCase().includes(logSearchQuery.toLowerCase())) ||
      (log.threatDescription && log.threatDescription.toLowerCase().includes(logSearchQuery.toLowerCase()));
    
    const matchesStatus = logStatusFilter === 'all' ? true : log.status === logStatusFilter;
    
    const matchesDevice = selectedDeviceFilter === null ? true : 
      (log.sourceIP === selectedDeviceFilter || log.destinationIP === selectedDeviceFilter || log.deviceName === selectedDeviceFilter);

    return matchesSearch && matchesStatus && matchesDevice;
  });

  // Calculate stats for graphics
  const areaChartData = logs.slice().reverse().map((log, index) => {
    const timestamp = new Date(log.timestamp);
    const hour = timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return {
      name: hour,
      permitido: log.status === 'allowed' ? log.bytes / 1024 : 0,
      bloqueado: log.status === 'blocked' ? log.bytes / 1024 : 0,
    };
  }).slice(-15); // Show latest 15 activities

  // Compute category threat distribution
  const threatCategoriesCounts: { [key: string]: number } = {};
  logs.forEach(l => {
    if (l.status === 'blocked') {
      const cat = l.category || 'Reconocimiento WAN';
      threatCategoriesCounts[cat] = (threatCategoriesCounts[cat] || 0) + 1;
    }
  });

  const pieChartData = Object.keys(threatCategoriesCounts).map(name => ({
    name,
    value: threatCategoriesCounts[name]
  }));

  if (pieChartData.length === 0) {
    pieChartData.push({ name: 'Sin Amenazas Críticas', value: 1 });
  }

  const PIE_COLORS = ['#EF4444', '#F97316', '#FBBF24', '#3B82F6', '#8B5CF6'];

  const handleMfaLoginVerify = () => {
    if (mfaCode === '123456' || mfaCode === '654321' || mfaConfig.recoveryCodes.includes(mfaCode.toUpperCase())) {
      setIsMfaVerified(true);
      setMfaErrorMsg('');
    } else {
      setMfaErrorMsg('Código de verificación doble factor incorrecto. Intente con "123456" para propósitos del demo.');
    }
  };

  const handleManualBlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualIp.trim()) return;
    try {
      await onBlockIp(manualIp, manualReason || 'Denegación asignada por administrador', manualSeverity);
      setBlockingStatusMsg(`Dirección IP ${manualIp} aislada de inmediato.`);
      setManualIp('');
      setManualReason('');
      setTimeout(() => setBlockingStatusMsg(''), 4000);
    } catch {
      setBlockingStatusMsg('Inconveniente al registrar cortafuegos.');
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      await onUnblockIp(ip);
      setBlockingStatusMsg(`Regla de bloqueo depurada para IP: ${ip}`);
      setTimeout(() => setBlockingStatusMsg(''), 4000);
    } catch {
      setBlockingStatusMsg('Error al revocar regla.');
    }
  };

  const handleTriggerBackupClick = async () => {
    setIsBackingUp(true);
    setBackupSuccessMsg('');
    try {
      const res = await onTriggerBackup();
      setIsBackingUp(false);
      setBackupSuccessMsg(res.message || 'Respaldo concluido con firmas AES-256 completadas.');
    } catch {
      setIsBackingUp(false);
      setBackupSuccessMsg('Error en el conducto de resguardo.');
    }
  };

  const handleUpdateConfigSubmit = async (e: React.FormEvent, type: 'mfa' | 'backups' | 'email') => {
    e.preventDefault();
    let payload = {};
    if (type === 'mfa') {
      payload = { enabled: editMfaEnabled, method: editMfaMethod };
    } else if (type === 'backups') {
      payload = { frequency: editBackupFreq, provider: editBackupProvider };
    } else if (type === 'email') {
      payload = { recipients: editEmailRecipients.split(',').map(s => s.trim()), minimumSeverity: editEmailSeverity };
    }

    try {
      await onUpdateConfig(type, payload);
      setConfigResultMsg('Ajustes corporativos NetShield aplicados exitosamente.');
      setTimeout(() => setConfigResultMsg(''), 4000);
    } catch {
      setConfigResultMsg('Error al guardar configuración global.');
    }
  };

  // Run Gemini AI Security Agent helper
  const handleAnalyzeWithAI = async (log: NetworkLog) => {
    setAiAnalysisLog(log);
    setIsAiLoading(true);
    setAiError(null);
    setAiAnalysisResult(null);

    try {
      const res = await fetch('/api/analyze-traffic', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ logEntry: log })
      });
      
      if (!res.ok) {
        throw new Error('Respuesta hostil del servidor de diagnóstico.');
      }
      const data = await res.json();
      setAiAnalysisResult(data);
    } catch (e: any) {
      setAiError(e.message || 'Error invocando al copiloto de IA Gemini.');
    } finally {
      setIsAiLoading(false);
    }
  };

  // Generate official enterprise Security audit PDF report
  const generateAuditReportPDF = () => {
    const doc = new jsPDF() as any;
    const dateStr = new Date().toLocaleDateString();
    
    // Header Style
    doc.setFillColor(15, 23, 42); // slate 900
    doc.rect(0, 0, 210, 40, 'F');
    
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    doc.setFont('helvetica', 'bold');
    doc.text('NETSHIELD ENTERPRISE - AUDITORIA DE RED', 14, 20);
    
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`CONSORCIO CORPORATIVO - FECHA DE IMPRONTACIÓN: ${dateStr}`, 14, 28);
    doc.text(`RESPONSABLE DE AUDITORIA: elbrayhan70@gmail.com `, 14, 34);
    
    // Quick summary layout
    doc.setTextColor(30, 41, 59);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('1. Resumen de Seguridad Corporativa', 14, 52);
    
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`- Total de Registros de Tráfico de Red Capturados: ${logs.length}`, 14, 60);
    doc.text(`- Rangos u Ordenamiento de IP Bloqueadas Activas: ${blockedRules.length}`, 14, 66);
    doc.text(`- Incidencias de Confianza Resueltas / Mitigadas: ${securityIncidents.length}`, 14, 72);
    doc.text(`- Sistema Multifactor (MFA/2FA): ACTIVADO y Cifrado de Extremo a Extremo`, 14, 78);
    doc.text(`- Método Copias de Seguridad Automatizadas: ${backupConfig.frequency.toUpperCase()} en ${backupConfig.provider}`, 14, 84);

    // Grid of Device table
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('2. Dispositivos Autorizados bajo Monitoreo E2EE', 14, 96);
    
    const deviceHeaders = [['ID', 'Nombre de Equipo', 'Dirección IP', 'Dirección MAC', 'Departamento', 'Estado Red', 'Amenaza']];
    const deviceData = devices.map(d => [d.id, d.name, d.ip, d.mac, d.department, d.status.toUpperCase(), d.threatLevel.toUpperCase()]);
    
    doc.autoTable({
      startY: 102,
      head: deviceHeaders,
      body: deviceData,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59] },
      styles: { fontSize: 8 },
    });

    const finalY = doc.lastAutoTable.finalY + 12;

    // Grid of Block rules
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('3. Filtros y Reglas Activas de Bloqueo Automático e IPS', 14, finalY);

    const blockHeaders = [['IP', 'Razón Técnica del Bloqueo', 'Declarado del Sistema', 'Modo', 'Severidad']];
    const blockData = blockedRules.map(r => [r.ip, r.reason, new Date(r.createdAt).toLocaleString(), r.type.toUpperCase(), r.severity.toUpperCase()]);

    doc.autoTable({
      startY: finalY + 6,
      head: blockHeaders,
      body: blockData,
      theme: 'grid',
      headStyles: { fillColor: [239, 68, 68] },
      styles: { fontSize: 8 },
    });

    // Signatures and compliance stamps
    const footerY = doc.lastAutoTable.finalY + 20;
    doc.setTextColor(100, 116, 139);
    doc.setFontSize(9);
    doc.text('Declaración del Sello de Cumplimiento Técnico NetShield e2cc:', 14, footerY);
    doc.text('Este documento sirve como descargo electrónico e historial forense de conformidad con las directrices ISO 27001.', 14, footerY + 5);
    doc.text('Todos los respaldos y políticas fueron auditados bajo algoritmos criptográficos redundantes de clave simétrica corporativa.', 14, footerY + 10);
    
    doc.save(`Auditoria-Seguridad-Mensual-${dateStr.replace(/\//g, '-')}.pdf`);
  };

  // Render Login challenge if MFA simulation is not approved
  if (!isMfaVerified) {
    return (
      <div className="flex items-center justify-center min-h-[80vh] px-4">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl shadow-xl overflow-hidden p-8">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-slate-900 text-white mb-4 shadow">
              <Shield className="w-7 h-7" />
            </div>
            <h2 className="text-2xl font-bold text-slate-800 tracking-tight">NetShield Enterprise</h2>
            <p className="text-xs text-slate-500 mt-2">Doble Factor de Autenticación de Alta Seguridad Corporativo Obligatorio (MFA)</p>
          </div>

          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-6">
            <div className="flex gap-3">
              <Key className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-amber-900">Modo Simulación Activo</p>
                <p className="text-xs text-amber-700 mt-1">El sistema NetShield requiere un código secundario. Introduce el código genérico con valor <strong className="font-bold underline text-amber-900">123456</strong> para validar.</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-2">Método Seleccionado: {mfaConfig.method.toUpperCase()} ({mfaConfig.email})</label>
              <input 
                type="text" 
                maxLength={6}
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="Introduzca el código OTP de 6 dígitos"
                className="w-full px-4 py-3 bg-slate-50 border border-slate-300 rounded-xl text-center font-mono text-lg font-bold tracking-widest focus:outline-none focus:ring-2 focus:ring-slate-800 focus:bg-white"
              />
            </div>

            {mfaErrorMsg && (
              <p className="text-xs font-medium text-red-600 text-center">{mfaErrorMsg}</p>
            )}

            <button 
              onClick={handleMfaLoginVerify}
              className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-semibold rounded-xl transition duration-200 outline-none flex items-center justify-center gap-2"
            >
              <UserCheck className="w-4 h-4" />
              Validar Identidad y Acceder
            </button>
          </div>

          <div className="mt-6 pt-6 border-t border-slate-200 text-center">
            <span className="text-[10px] text-slate-400 font-mono tracking-tight">Cifrado de Extremo a Extremo (E2EE) Activo</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-16">
      
      {/* Upper quick stats grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        
        {/* Core Threat summary */}
        <div className="bg-slate-900 text-white rounded-2xl p-6 shadow-md border border-slate-800 relative overflow-hidden">
          <div className="absolute right-4 top-4 text-emerald-500 flex items-center gap-1 bg-emerald-950/40 px-2 py-0.5 rounded-full text-[10px] font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            E2EE Activo
          </div>
          <p className="text-xs text-slate-400 font-medium">Estado General de IPS</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold tracking-tight">Protegido</span>
          </div>
          <p className="text-[11px] text-slate-300 mt-2 flex items-center gap-1.5 line-clamp-1">
            <ShieldCheck className="w-4.5 h-4.5 text-emerald-400" /> Archivo de red redundante activo
          </p>
        </div>

        {/* Total blocked statistics counts */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs text-slate-500 font-medium">Mitigaciones Activas</p>
              <h3 className="text-2xl font-bold text-slate-800 mt-1">{stats.activeIpBlockCount} IPs Bloqueadas</h3>
            </div>
            <span className="bg-red-50 text-red-600 p-2 rounded-xl">
              <ShieldAlert className="w-5 h-5" />
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-3 flex items-center gap-1 font-mono">
            <span>Último descarte automático: Hace un instante</span>
          </p>
        </div>

        {/* Cloud backup status indicators */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs text-slate-500 font-medium">Nube Respaldos Redundantes</p>
              <h3 className="text-sm font-bold text-slate-800 mt-2 truncate">
                {backupConfig.provider}
              </h3>
            </div>
            <span className="bg-blue-50 text-blue-600 p-2 rounded-xl">
              <Database className="w-5 h-5" />
            </span>
          </div>
          <div className="mt-3 flex items-center justify-between">
            <span className="text-[10px] font-semibold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full">
              {backupConfig.status === 'success' ? 'Sincronizado' : 'Resguardando'}
            </span>
            <span className="text-[10px] text-slate-400 font-mono">
              Frecuencia: {backupConfig.frequency}
            </span>
          </div>
        </div>

        {/* Simulated server resource indicators */}
        <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs text-slate-500 font-medium font-mono">Carga Máquina Gateway</p>
              <div className="flex gap-4 mt-1">
                <div>
                  <span className="text-[10px] text-slate-400 block font-mono">RAM</span>
                  <span className="text-base font-bold text-slate-700">{stats.ramUsage}%</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 block font-mono">CPU</span>
                  <span className="text-base font-bold text-slate-700">{stats.cpuLoad}%</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 block font-mono">Tráfico</span>
                  <span className="text-base font-bold text-slate-700">{stats.networkThroughput} Mbps</span>
                </div>
              </div>
            </div>
            <span className="bg-indigo-50 text-indigo-600 p-2 rounded-xl">
              <Cpu className="w-5 h-5" />
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1 font-mono">Canalización de subprocesos aislados</p>
        </div>

      </div>

      {/* Corporate Incident and PDF Export line bar */}
      <div className="bg-slate-50 rounded-2xl border border-slate-200 p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="bg-red-500 text-white p-2 rounded-full animate-pulse">
            <AlertOctagon className="w-4 h-4" />
          </div>
          <div>
            <p className="text-xs font-semibold text-slate-800">
              {securityIncidents.filter(i => i.status === 'active').length} Amenazas detectadas hoy en tiempo real
            </p>
            <p className="text-[11px] text-slate-500">Módulos Redundantes de mitigación autónoma activos</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Simulate threat trigger */}
          <button
            onClick={async () => {
              await onSimulateIntrusion();
              onRefresh();
            }}
            className="px-4 py-2 bg-amber-50 border border-amber-200 text-amber-700 hover:bg-amber-100 font-medium text-xs rounded-xl transition flex items-center gap-1.5"
            title="Simula un ataque externo hostil para probar en tiempo real la captación del cortafuegos"
          >
            <CloudLightning className="w-4 h-4" />
            Simular Intrusión
          </button>

          {/* Export audit PDF document */}
          <button 
            onClick={generateAuditReportPDF}
            className="px-4 py-2 bg-slate-900 border border-slate-800 text-white hover:bg-slate-800 font-semibold text-xs rounded-xl transition flex items-center gap-1.5 shadow"
          >
            <FileDown className="w-4 h-4" />
            Exportar Auditoría PDF
          </button>
        </div>
      </div>

      {/* Sub menu tabs */}
      <div className="border-b border-slate-200 flex space-x-6">
        <button 
          onClick={() => setActiveTab('general')}
          className={`pb-4 text-sm font-semibold border-b-2 transition ${activeTab === 'general' ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-400 hover:text-slate-600'}`}
        >
          Tráfico y Diagnósticos Copilot
        </button>
        <button 
          onClick={() => setActiveTab('devices')}
          className={`pb-4 text-sm font-semibold border-b-2 transition ${activeTab === 'devices' ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-400 hover:text-slate-600'}`}
        >
          Inventario E2EE Dispositivos ({devices.length})
        </button>
        <button 
          onClick={() => setActiveTab('rules')}
          className={`pb-4 text-sm font-semibold border-b-2 transition ${activeTab === 'rules' ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-400 hover:text-slate-600'}`}
        >
          Reglas del Cortafuegos ({blockedRules.length})
        </button>
        <button 
          onClick={() => setActiveTab('config')}
          className={`pb-4 text-sm font-semibold border-b-2 transition ${activeTab === 'config' ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-400 hover:text-slate-600'}`}
        >
          Servidores Nube, Correo y MFA
        </button>
      </div>

      {/* Main interactive area */}
      {activeTab === 'general' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left charts and configuration console: 2 cols */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Visual statistics area chart */}
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm">
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h3 className="text-base font-bold text-slate-800">Carga de Tráfico Filtrada por Segundo</h3>
                  <p className="text-xs text-slate-400 mt-1">Tráfico en KB/s de solicitudes permitidas vs intentos mitigados en tiempo real</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1 text-xs text-indigo-500 font-medium">
                    <span className="w-2.5 h-2.5 rounded-full bg-indigo-500"></span> Permitido
                  </span>
                  <span className="flex items-center gap-1 text-xs text-red-500 font-medium">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Mitigado
                  </span>
                </div>
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={areaChartData}>
                    <defs>
                      <linearGradient id="colorPermitido" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#4F46E5" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#4F46E5" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorBloqueado" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#F1F5F9" />
                    <XAxis dataKey="name" style={{ fontSize: 9, fill: '#94A3B8' }} tickLine={false} />
                    <YAxis style={{ fontSize: 9, fill: '#94A3B8' }} tickLine={false} />
                    <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8, border: '1px solid #E2E8F0' }} />
                    <Area type="monotone" dataKey="permitido" stroke="#4F46E5" strokeWidth={2} fillOpacity={1} fill="url(#colorPermitido)" />
                    <Area type="monotone" dataKey="bloqueado" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#colorBloqueado)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Real-time searchable logs table */}
            <div className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden">
              <div className="p-6 border-b border-slate-100 flex flex-wrap justify-between items-center gap-4">
                <div>
                  <h3 className="text-base font-bold text-slate-800">Inspección Forense de Paquetes y Conexiones</h3>
                  <p className="text-xs text-slate-400 mt-1">Haga clic en un registro sospechoso para someter su patrón al diagnóstico de la IA.</p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {/* Status switches */}
                  <select
                    value={logStatusFilter}
                    onChange={(e: any) => setLogStatusFilter(e.target.value)}
                    className="p-2 border border-slate-200 rounded-xl text-xs bg-slate-50 focus:bg-white text-slate-600 focus:outline-none"
                  >
                    <option value="all">Ver Todo el Tráfico</option>
                    <option value="allowed">Solo Permitido</option>
                    <option value="blocked">Solo Bloqueado / IPS</option>
                  </select>

                  <div className="relative">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                    <input 
                      type="text" 
                      placeholder="Filtrar por IP, dispositivo..."
                      value={logSearchQuery}
                      onChange={(e) => setLogSearchQuery(e.target.value)}
                      className="pl-9 pr-4 py-2 border border-slate-200 rounded-xl text-xs bg-slate-50 focus:bg-white focus:outline-none placeholder-slate-400 w-44"
                    />
                  </div>

                  {selectedDeviceFilter && (
                    <button 
                      onClick={() => setSelectedDeviceFilter(null)}
                      className="px-3 py-1.5 bg-red-50 text-red-600 font-medium text-xs rounded-xl hover:bg-red-100 flex items-center gap-1"
                    >
                      Limpiar Filtro
                      <Undo className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              {/* Grid content */}
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 text-slate-400 text-[10px] uppercase font-semibold font-mono tracking-wider border-b border-slate-100">
                      <th className="px-6 py-3">Timestamp / Canal</th>
                      <th className="px-6 py-3">Surgimiento (Origen)</th>
                      <th className="px-6 py-3">Hacia (Destino)</th>
                      <th className="px-6 py-3">Servicio / Puerto</th>
                      <th className="px-6 py-3">Fallo / Decisión</th>
                      <th className="px-6 py-3 text-right">Análisis Copilot</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-xs">
                    {filteredLogs.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="text-center py-8 text-slate-400">
                          Ningún paquete de telemetría cumple con las restricciones de filtrado.
                        </td>
                      </tr>
                    ) : (
                      filteredLogs.map(log => (
                        <tr key={log.id} className="hover:bg-slate-50 group">
                          <td className="px-6 py-3.5 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="px-6 py-3.5 whitespace-nowrap">
                            <span 
                              onClick={() => setSelectedDeviceFilter(log.sourceIP)}
                              className="font-medium text-slate-800 cursor-pointer hover:underline"
                            >
                              {log.sourceIP} 
                            </span>
                            {log.deviceName && log.sourceIP.startsWith("192.") && (
                              <span className="text-[10px] text-slate-400 font-medium block">
                                Enlace: {log.deviceName}
                              </span>
                            )}
                          </td>
                          <td className="px-6 py-3.5 font-mono text-slate-600 whitespace-nowrap">
                            {log.destinationIP}
                          </td>
                          <td className="px-6 py-3.5 font-mono whitespace-nowrap">
                            <span className="bg-slate-100 px-1.5 py-0.5 rounded text-[10px] text-slate-600 mr-1.5">
                              {log.protocol}
                            </span>
                            Port {log.port}
                          </td>
                          <td className="px-6 py-3.5 whitespace-nowrap">
                            {log.status === 'blocked' ? (
                              <span className="inline-flex items-center gap-1 font-semibold text-red-600 bg-red-50 px-2 py-0.5 rounded-full text-[10px]">
                                <ShieldAlert className="w-3 h-3" /> Bloqueado IPS
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 font-semibold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-full text-[10px]">
                                <ShieldCheck className="w-3 h-3" /> Autorizado
                              </span>
                            )}
                          </td>
                          <td className="px-6 py-3.5 text-right whitespace-nowrap">
                            <button
                              onClick={() => handleAnalyzeWithAI(log)}
                              className="px-2.5 py-1 text-[11px] border border-slate-200 hover:border-slate-800 text-slate-700 bg-white hover:bg-slate-50 font-semibold rounded-lg flex items-center gap-1 inline-flex transition"
                            >
                              <Zap className="w-3.5 h-3.5 text-indigo-500 fill-indigo-100" />
                              Analizar con IA
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>

          {/* Right sidebar stats & quick actions: 1 col */}
          <div className="space-y-8">

            {/* Quick manual block configuration */}
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-1.5">
                <ShieldAlert className="w-5 h-5 text-red-500" />
                Cislar IP Sospechosa
              </h3>
              <p className="text-xs text-slate-400 mt-1">Bloqueo permanente del host. El aislamiento de capa 3 se propagará automáticamente en la topología redundante.</p>

              {blockingStatusMsg && (
                <div className="mt-3 text-xs bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-xl p-3">
                  {blockingStatusMsg}
                </div>
              )}

              <form onSubmit={handleManualBlockSubmit} className="mt-4 space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Dirección IP de Destinatario</label>
                  <input 
                    type="text" 
                    value={manualIp}
                    onChange={(e) => setManualIp(e.target.value)}
                    placeholder="Ej: 185.190.140.42"
                    required
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900 bg-slate-50 focus:bg-white"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Motivo Técnico de Sanción</label>
                  <input 
                    type="text" 
                    value={manualReason}
                    onChange={(e) => setManualReason(e.target.value)}
                    placeholder="Ej: Tráfico de exfiltración o flood"
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900 bg-slate-50 focus:bg-white"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-semibold text-slate-600 block mb-1">Severidad</label>
                    <select
                      value={manualSeverity}
                      onChange={(e) => setManualSeverity(e.target.value)}
                      className="w-full p-2 border border-slate-300 rounded-xl text-xs bg-slate-50"
                    >
                      <option value="medium">Media</option>
                      <option value="high">Alta</option>
                      <option value="critical">Crítico</option>
                    </select>
                  </div>
                  
                  <div className="flex items-end">
                    <button 
                      type="submit"
                      className="w-full py-2 bg-red-600 hover:bg-red-700 text-white font-semibold text-xs rounded-xl flex items-center justify-center gap-1 transition"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      Bloquear IP
                    </button>
                  </div>
                </div>
              </form>
            </div>

            {/* Distribution Pie chart of threats */}
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm">
              <h3 className="text-base font-bold text-slate-800">Distribución de Amenazas Mitigadas</h3>
              <p className="text-xs text-slate-400 mt-1">Clasificación forense del tráfico de red que violó las políticas IPS corporatvas</p>

              <div className="h-44 mt-4 flex items-center justify-center">
                {pieChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={70}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {pieChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip formatter={(value) => `${value} incidentes`} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="text-xs text-slate-400">Sin incidentes bloqueados hoy.</p>
                )}
              </div>

              {/* Custom detailed Legend */}
              <div className="mt-4 space-y-1.5 max-h-36 overflow-y-auto">
                {pieChartData.map((item, index) => (
                  <div key={item.name} className="flex justify-between items-center text-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }}></span>
                      <span className="text-slate-600 truncate max-w-44 block">{item.name}</span>
                    </div>
                    <span className="font-mono text-slate-400">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Redundant backups control status panel */}
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm space-y-4">
              <div>
                <h3 className="text-sm font-bold text-slate-800 flex items-center gap-1.5">
                  <Database className="w-4.5 h-4.5 text-indigo-500" />
                  Copias de Seguridad Cifradas
                </h3>
                <p className="text-xs text-slate-400 mt-1">Los respaldos NetShield operan con redundancia en la nube. Criptografía AES-256 local integrada.</p>
              </div>

              <div className="bg-slate-50 rounded-xl p-3 border border-slate-100 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-500">Servidor Nube Destino</span>
                  <strong className="text-slate-700 font-mono font-semibold">{backupConfig.provider}</strong>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-500">Cifrado Simétrico Extra</span>
                  <span className="text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full font-semibold text-[10px]">Activado</span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-500">Último Guardado</span>
                  <span className="text-slate-600 font-mono text-[10px]">{new Date(backupConfig.lastBackupTime).toLocaleString()}</span>
                </div>
              </div>

              {backupSuccessMsg && (
                <p className="text-xs text-indigo-700 font-semibold bg-indigo-50 rounded-lg p-2.5 border border-indigo-100">
                  {backupSuccessMsg}
                </p>
              )}

              <button 
                onClick={handleTriggerBackupClick}
                disabled={isBackingUp}
                className="w-full py-2.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-white text-xs font-semibold rounded-xl flex items-center justify-center gap-2 transition"
              >
                <RefreshCw className={`w-4 h-4 ${isBackingUp ? 'animate-spin' : ''}`} />
                {isBackingUp ? 'Generando Copia Segura...' : 'Respaldar Red ahora'}
              </button>
            </div>

          </div>

        </div>
      )}

      {/* Devices list and monitoring inventory */}
      {activeTab === 'devices' && (
        <div className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden">
          <div className="p-6 border-b border-slate-100 flex justify-between items-center">
            <div>
              <h3 className="text-base font-bold text-slate-800">Inventario y Topología de Equipos Corporativos</h3>
              <p className="text-xs text-slate-400 mt-1">Dispositivos internos vigilados automáticamente por las firmas de interceptación criptográficas NetShield.</p>
            </div>
            <span className="text-xs bg-indigo-50 text-indigo-600 px-3 py-1 rounded-full font-semibold">
              E2EE Activado Extremo a Extremo
            </span>
          </div>

          <div className="divide-y divide-slate-100">
            {devices.map(device => {
              const isFiltered = selectedDeviceFilter === device.ip;
              
              return (
                <div key={device.id} className="p-6 hover:bg-slate-50 transition flex flex-col md:flex-row md:items-center justify-between gap-4">
                  
                  {/* Left info */}
                  <div className="flex items-start gap-4">
                    <div className="bg-slate-100 p-3 rounded-2xl text-slate-600 flex-shrink-0 mt-0.5">
                      <Server className="w-6 h-6" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h4 className="font-semibold text-slate-800 text-sm">{device.name}</h4>
                        <span className="px-2 py-0.5 font-mono text-[10px] bg-slate-100 text-slate-500 rounded">
                          {device.department}
                        </span>
                        
                        {/* OS tag */}
                        <span className="text-[10px] text-slate-400">
                          {device.os}
                        </span>
                      </div>

                      <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-slate-500">
                        <div>
                          <span>IP de origen: </span>
                          <strong className="font-mono text-slate-700">{device.ip}</strong>
                        </div>
                        <div>
                          <span>MAC física: </span>
                          <strong className="font-mono text-slate-700">{device.mac}</strong>
                        </div>
                        <div>
                          <span>Última Actividad: </span>
                          <strong className="text-slate-600">{device.lastActive}</strong>
                        </div>
                        <div>
                          <span>Tráfico Consumido: </span>
                          <strong className="text-slate-600">{(device.trafficBytes / (1024 * 1024)).toFixed(2)} MB</strong>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Actions right */}
                  <div className="flex items-center justify-end gap-3 self-end md:self-center">
                    
                    {/* Status indicators */}
                    <div className="text-right mr-2">
                      <span className="text-[10px] text-slate-400 block font-semibold uppercase font-mono tracking-wider">Nivel de Riesgo</span>
                      {device.threatLevel === 'high' ? (
                        <span className="text-xs font-semibold text-red-600">Crítico / Alto</span>
                      ) : device.threatLevel === 'medium' ? (
                        <span className="text-xs font-semibold text-amber-600">Medio</span>
                      ) : (
                        <span className="text-xs font-semibold text-emerald-600">Bajo (Seguro)</span>
                      )}
                    </div>

                    {/* Filter logs with this IP */}
                    <button
                      onClick={() => {
                        setSelectedDeviceFilter(device.ip);
                        setActiveTab('general');
                      }}
                      className="px-3 py-1.5 bg-slate-50 text-slate-700 text-xs font-semibold rounded-xl border border-slate-200 hover:bg-slate-100 flex items-center gap-1 transition"
                    >
                      <Filter className="w-3.5 h-3.5" />
                      Filtrar Logs
                    </button>

                    {/* Block/Unblock interaction */}
                    {device.status === 'blocked' ? (
                      <button 
                        onClick={() => handleUnblock(device.ip)}
                        className="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl transition"
                      >
                        Habilitar IP
                      </button>
                    ) : (
                      <button 
                        onClick={() => onBlockIp(device.ip, 'Mitigación manual de inventario corporativo', 'high')}
                        className="px-3 py-1.5 bg-red-50 hover:bg-red-100 text-red-600 text-xs font-semibold rounded-xl transition"
                      >
                        Mitigar (Bloquear)
                      </button>
                    )}
                  </div>

                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Rules block configuration tab */}
      {activeTab === 'rules' && (
        <div className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden p-6 space-y-6">
          <div>
            <h3 className="text-base font-bold text-slate-800">Políticas y Filtros de Cortafuegos del Sistema</h3>
            <p className="text-xs text-slate-400 mt-1">Direcciones IP prohibidas temporal o permanentemente por firmas heurísticas IPS o por comandos administrados.</p>
          </div>

          <div className="border border-slate-100 rounded-2xl divide-y divide-slate-100">
            {blockedRules.length === 0 ? (
              <p className="p-6 text-center text-xs text-slate-400">Sin reglas activas. El cortafuegos está vacío.</p>
            ) : (
              blockedRules.map(rule => (
                <div key={rule.id} className="p-4 hover:bg-slate-50 transition flex items-center justify-between gap-4 text-xs">
                  <div className="flex items-center gap-4">
                    <div className="bg-red-50 text-red-600 p-2 rounded-xl">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <strong className="font-mono text-sm text-slate-800">{rule.ip}</strong>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${rule.type === 'auto' ? 'bg-amber-50 text-amber-700 border border-amber-200' : 'bg-slate-100 text-slate-700'}`}>
                          {rule.type === 'auto' ? 'SISTEMA IPS AUTOMÁTICO' : 'MANUAL ADMIN'}
                        </span>
                      </div>
                      <p className="text-slate-500 mt-1">{rule.reason}</p>
                      <span className="text-[10px] text-slate-400 font-mono">Declarada en reglas: {new Date(rule.createdAt).toLocaleString()}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="text-[10px] bg-red-50 text-red-700 px-2 py-0.5 rounded-full font-semibold uppercase">{rule.severity}</span>
                    <button 
                      onClick={() => handleUnblock(rule.ip)}
                      className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition"
                      title="Quitar exclusión de red"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Corporate Advanced setups configuration panel (Security Settings) */}
      {activeTab === 'config' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          
          {/* Double factor and emails settings */}
          <div className="space-y-8">
            
            {/* MFA settings form */}
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-1.5">
                <Lock className="w-5 h-5 text-slate-700" />
                Autenticación Multifactor (MFA)
              </h3>
              <p className="text-xs text-slate-400 mt-1">Refuerce las cuentas de administrador con contraseñas de un solo uso (OTP) e historial corporativo.</p>

              <form onSubmit={(e) => handleUpdateConfigSubmit(e, 'mfa')} className="mt-4 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-700">Habilitar doble factor obligatorio</span>
                  <input 
                    type="checkbox" 
                    checked={editMfaEnabled}
                    onChange={(e) => setEditMfaEnabled(e.target.checked)}
                    className="w-4 h-4 rounded text-slate-900 focus:ring-slate-900"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Método preferente</label>
                  <select
                    value={editMfaMethod}
                    onChange={(e: any) => setEditMfaMethod(e.target.value)}
                    className="w-full text-xs p-2 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none"
                  >
                    <option value="authenticator">Google Authenticator / Duo OTP</option>
                    <option value="email">Por correo electrónico ({mfaConfig.email})</option>
                  </select>
                </div>

                <div className="bg-slate-50 rounded-xl p-3 text-[11px] text-slate-500 font-mono space-y-1">
                  <strong className="text-slate-600 block text-xs font-bold font-sans not-italic mb-1">Códigos de Recuperación Backups:</strong>
                  {mfaConfig.recoveryCodes.map(code => (
                    <span key={code} className="inline-block bg-white border border-slate-200 rounded px-1.5 py-0.5 text-slate-700 mr-1.5 my-0.5">{code}</span>
                  ))}
                </div>

                <button 
                  type="submit"
                  className="px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-white font-semibold text-xs rounded-xl transition"
                >
                  Guardar Ajustes MFA
                </button>
              </form>
            </div>

            {/* In-realtime email configurations options */}
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-1.5">
                <Mail className="w-5 h-5 text-slate-700" />
                Alertas vía Correo Electrónico
              </h3>
              <p className="text-xs text-slate-400 mt-1">Despacho instantáneo de firmas de intrusión y alertas de firewall corporativo.</p>

              <form onSubmit={(e) => handleUpdateConfigSubmit(e, 'email')} className="mt-4 space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Destinatarios autorizados (Separados por coma)</label>
                  <input 
                    type="text" 
                    value={editEmailRecipients}
                    onChange={(e) => setEditEmailRecipients(e.target.value)}
                    className="w-full text-xs p-2 border border-slate-300 rounded-xl focus:outline-none bg-slate-50 focus:bg-white"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Gravedad Mínima de Disparo</label>
                  <select
                    value={editEmailSeverity}
                    onChange={(e: any) => setEditEmailSeverity(e.target.value)}
                    className="w-full text-xs p-2 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none"
                  >
                    <option value="low">Cualquier evento de telemetria (Bajo)</option>
                    <option value="medium">Mapeos y reglas (Medio)</option>
                    <option value="high">IPS Auto-Bloqueos (Alto)</option>
                    <option value="critical">Alertas RDP e Intrusiones (Crítico)</option>
                  </select>
                </div>

                <button 
                  type="submit"
                  className="px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-white font-semibold text-xs rounded-xl transition"
                >
                  Definir Canales de Alerta
                </button>
              </form>
            </div>

          </div>

          {/* Backup frequency configure */}
          <div className="space-y-8">
            
            <div className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-1.5">
                <Layers className="w-5 h-5 text-slate-700" />
                Planificación de Respaldos Redundantes
              </h3>
              <p className="text-xs text-slate-400 mt-1">Respaldos redundantes automatizados en servidores de nube líderes del sector.</p>

              {configResultMsg && (
                <div className="my-3 text-xs text-emerald-700 bg-emerald-50 rounded-xl p-3">
                  {configResultMsg}
                </div>
              )}

              <form onSubmit={(e) => handleUpdateConfigSubmit(e, 'backups')} className="mt-4 space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Frecuencia Automatizada</label>
                  <select
                    value={editBackupFreq}
                    onChange={(e: any) => setEditBackupFreq(e.target.value)}
                    className="w-full text-xs p-2 bg-slate-50 border border-slate-200 rounded-xl"
                  >
                    <option value="hourly">Cada hora (Protección de alta transaccionalidad)</option>
                    <option value="daily">Diariamente (Recomendado estándar)</option>
                    <option value="weekly">Semanalmente (Ahorro de almacenamiento)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1">Proveedor de Almacenamiento en la Nube</label>
                  <select
                    value={editBackupProvider}
                    onChange={(e: any) => setEditBackupProvider(e.target.value)}
                    className="w-full text-xs p-2 bg-slate-50 border border-slate-200 rounded-xl"
                  >
                    <option value="Google Cloud Storage">Google Cloud Storage Bucket (Recomendado)</option>
                    <option value="Amazon S3">Amazon Simple Storage Service S3 Secure</option>
                    <option value="Azure Blob">Microsoft Azure Blob Storage</option>
                  </select>
                </div>

                <div className="bg-emerald-50 rounded-xl p-3 border border-emerald-200">
                  <span className="text-xs font-semibold text-emerald-800 block">Doble Cifrado AES-256 Forzado</span>
                  <p className="text-[11px] text-emerald-600 mt-1">Cifra adicionalmente las copias de seguridad antes de la transmisión a los servidores de la nube para asegurar que todos los datos sensibles se mantengan confidenciales de extremo a extremo.</p>
                </div>

                <button 
                  type="submit"
                  className="px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-white font-semibold text-xs rounded-xl transition"
                >
                  Guardar Ajustes Copias Nube
                </button>
              </form>
            </div>

            {/* Architecture declaration details */}
            <div className="bg-slate-900 text-slate-300 rounded-2xl p-6 space-y-3 shadow-md border border-slate-800">
              <span className="text-emerald-400 font-mono text-[10px] tracking-wider uppercase font-bold block">Topología Tecnológica NetShield</span>
              <h4 className="text-sm font-bold text-white">Arquitectura de Red Redundante Tolerante a Fallos</h4>
              <p className="text-xs text-slate-400">
                La solución redundante NetShield se ejecuta acoplada a múltiples zonas de disponibilidad en Cloud Run concurrentes, lo cual garantiza una accesibilidad permanente del 99.99%. Los cambios de políticas de firewall se sincronizan al instante en los appliances satélites corporativos mundiales.
              </p>
            </div>

          </div>

        </div>
      )}

      {/* AI Diagnóstico Modal Dialog popup */}
      {aiAnalysisLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl shadow-xl border border-slate-200 w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            
            {/* Header */}
            <div className="bg-slate-900 p-6 text-white flex justify-between items-start">
              <div>
                <span className="text-[10px] bg-indigo-500/25 border border-indigo-500/50 text-indigo-300 px-2 py-0.5 rounded font-mono block w-fit">
                  COPILOTO ANALISTA IA GEMINI Active
                </span>
                <h3 className="text-lg font-bold mt-2">Diagnóstico de Seguridad Asistido</h3>
              </div>
              <button 
                onClick={() => setAiAnalysisLog(null)}
                className="text-slate-400 hover:text-white font-bold text-lg"
              >
                &times;
              </button>
            </div>

            {/* Content info wrapper */}
            <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto">
              
              {/* Log context info */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-50 rounded-xl p-4 border border-slate-100 text-xs text-slate-600">
                <div>
                  <span className="text-slate-400 block font-mono text-[10px]">Origen sospechoso</span>
                  <strong className="font-mono text-slate-800">{aiAnalysisLog.sourceIP}</strong>
                </div>
                <div>
                  <span className="text-slate-400 block font-mono text-[10px]">Servidor objetivo</span>
                  <strong className="font-mono text-slate-800">{aiAnalysisLog.destinationIP}</strong>
                </div>
                <div>
                  <span className="text-slate-400 block font-mono text-[10px]">Puerto / Canal</span>
                  <strong className="font-mono text-slate-800">Port {aiAnalysisLog.port} ({aiAnalysisLog.protocol})</strong>
                </div>
                <div>
                  <span className="text-slate-400 block font-mono text-[10px]">Región Geográfica</span>
                  <strong className="text-slate-800 font-semibold">{aiAnalysisLog.country || 'Intranet'}</strong>
                </div>
              </div>

              {/* Loader feedback */}
              {isAiLoading && (
                <div className="flex flex-col items-center justify-center py-12 space-y-4">
                  <div className="w-12 h-12 rounded-full border-4 border-indigo-100 border-t-indigo-600 animate-spin"></div>
                  <p className="text-xs font-semibold text-slate-600">Gemini está evaluando patrones y firmas de paquetes sospechosos...</p>
                </div>
              )}

              {/* Error feedback */}
              {aiError && (
                <div className="bg-red-50 text-red-700 p-4 rounded-xl border border-red-100 text-xs">
                  <strong>Inconveniente en la AI:</strong> {aiError}
                </div>
              )}

              {/* Render result */}
              {aiAnalysisResult && (
                <div className="space-y-6">
                  
                  {/* Score badge bar */}
                  <div className="flex items-center justify-between gap-4 py-3 border-b border-slate-150">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-500 font-semibold">Urgencia Evaluada:</span>
                      <span className={`px-2.5 py-0.5 rounded-full font-bold text-xs ${
                        aiAnalysisResult.riskLevel === 'Crítico' || aiAnalysisResult.riskLevel === 'Alto'
                          ? 'bg-red-100 text-red-700'
                          : 'bg-amber-100 text-amber-700'
                      }`}>
                        {aiAnalysisResult.riskLevel}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                      Riesgo Numérico:
                      <strong className="text-slate-800 font-extrabold text-lg">{aiAnalysisResult.riskScore}/10</strong>
                    </div>
                  </div>

                  {/* Threat Description */}
                  <div className="space-y-2">
                    <h4 className="font-bold text-slate-800 text-sm flex items-center gap-1">
                      <AlertCircle className="w-4 h-4 text-indigo-500" />
                      Firma Identificada: &ldquo;{aiAnalysisResult.threatTitle}&rdquo;
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed bg-indigo-50/20 border border-indigo-100/50 p-4 rounded-xl">
                      {aiAnalysisResult.analysisDescription}
                    </p>
                  </div>

                  {/* Mitigation steps bullet points */}
                  <div className="space-y-3">
                    <h5 className="font-semibold text-xs text-slate-700">Protocolos de Mitigación Inmediata Sugeridos por IA:</h5>
                    <ul className="space-y-2">
                      {aiAnalysisResult.mitigationSteps?.map((step: string, i: number) => (
                        <li key={i} className="flex gap-2 text-xs text-slate-600 text-left items-start">
                          <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 flex items-center justify-center font-bold text-[10px] flex-shrink-0 mt-0.5">
                            {i + 1}
                          </span>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Rule recommendation advice */}
                  <div className="bg-amber-50 border border-amber-250 rounded-xl p-4 text-xs text-amber-900">
                    <strong className="font-bold">Recomendación Cortafuegos:</strong>
                    <p className="mt-1 font-mono">{aiAnalysisResult.ruleRecommendation}</p>
                  </div>

                </div>
              )}

            </div>

            {/* Actions Footer */}
            <div className="bg-slate-50 p-6 border-t border-slate-150 flex items-center justify-end gap-3">
              <button 
                onClick={() => setAiAnalysisLog(null)}
                className="px-4 py-2 border border-slate-200 text-slate-700 hover:bg-slate-100 rounded-xl text-xs font-semibold"
              >
                Cerrar Diagnóstico
              </button>

              {aiAnalysisResult && (
                <button
                  onClick={async () => {
                    await onBlockIp(aiAnalysisLog.sourceIP, aiAnalysisResult.ruleRecommendation || 'Acción mitigatoria recomendada por Gemini AI', 'high');
                    setAiAnalysisLog(null);
                    onRefresh();
                  }}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-xl text-xs flex items-center gap-1.5 shadow"
                >
                  <ShieldAlert className="w-4 h-4" />
                  Aislar IP #{aiAnalysisLog.sourceIP} de Inmediato
                </button>
              )}
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
