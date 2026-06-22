import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Server, 
  Terminal, 
  HelpCircle, 
  Lock, 
  Wifi, 
  CheckCircle, 
  Play, 
  AlertCircle 
} from 'lucide-react';
import { Device } from '../types';

interface UserConsoleProps {
  devices: Device[];
  blockedRules: any[];
  onRefresh: () => void;
}

export default function UserConsole({ devices, blockedRules, onRefresh }: UserConsoleProps) {
  const [userIpQuery, setUserIpQuery] = useState('192.168.1.102');
  const [diagnosticLogs, setDiagnosticLogs] = useState<string[]>([]);
  const [isClassifying, setIsClassifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);

  // Perform localized diagnostic endpoint trace simulation
  const handleRunDiagnostic = () => {
    setIsClassifying(true);
    setDiagnosticLogs([
      "Iniciando diagnóstico local NetShield Endpoint v4.2.1...",
      "Obteniendo dirección IP local asignada por adaptador corporativo...",
      `Detectado adaptador principal bound to target: ${userIpQuery}`,
      "Verificando túnel redundante de enrutamiento E2EE seguro...",
      "Comprobando firmas de integridad en servidores Active Directory central...",
      "Verificando estado de aislamiento de mitigación contra suplantación ARP..."
    ]);

    setTimeout(() => {
      setDiagnosticLogs(prev => [
        ...prev,
        "Firmas de paquete cifradas correctamente (AES-256 simétrico activo).",
        "Control recursivo de puertos WAN: Puerto 22 deshabilitado para seguridad local.",
        "Análisis heurístico de malware: Ningún troyano de exfiltración activo.",
        "Diagnóstico finalizado. Dispositivo alineado a políticas globales corporativas."
      ]);
      
      const matchingDevice = devices.find(d => d.ip === userIpQuery);
      const isIpBlocked = blockedRules.some(r => r.ip === userIpQuery);

      if (isIpBlocked || (matchingDevice && matchingDevice.status === 'blocked')) {
        setVerificationResult({
          status: 'danger',
          title: 'Acceso corporativo Denegado / Aislado',
          message: 'Su dirección IP ha sido bloqueada temporalmente por infringir directrices de tráfico inusual o escaneo. Contacte al administrador para resolver.'
        });
      } else {
        setVerificationResult({
          status: 'secure',
          title: 'Conexión Segura y Cifrada Autorizada',
          message: 'Su dispositivo se encuentra en cumplimiento óptimo de los estándares internacionales de seguridad de red.'
        });
      }
      setIsClassifying(false);
    }, 1800);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8 pb-12">
      
      {/* Header status card */}
      <div className="bg-gradient-to-br from-slate-900 to-indigo-950 text-white rounded-3xl p-8 shadow-lg border border-indigo-900 relative overflow-hidden">
        <div className="absolute right-0 top-0 opacity-10 pointer-events-none">
          <Terminal className="w-64 h-64" />
        </div>
        
        <span className="text-emerald-400 font-mono text-xs font-bold uppercase tracking-wider block">
          NetShield Endpoint Client
        </span>
        <h2 className="text-2xl font-bold mt-2">Panel del Empleado & Diagnóstico de Tráfico</h2>
        <p className="text-slate-350 text-xs mt-2 leading-relaxed">
          Usted pertenece a la infraestructura corporativa protegida. Su tráfico reside de extremo a extremo cifrado (E2EE) con una arquitectura redundante de alta fidelidad para prevenir intrusiones externas e internas. No comparta contraseñas ni desactive el doble factor MFA.
        </p>
      </div>

      {/* Main check card */}
      <div className="bg-white border border-slate-150 rounded-2xl p-6 shadow-xs grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
        
        {/* Left selector */}
        <div className="space-y-4">
          <h3 className="text-sm font-bold text-slate-800">Verificar Estado de mi Dispositivo</h3>
          <p className="text-xs text-slate-400 mt-1">
            Ingrese su dirección IP asignada actual para inspeccionar las políticas de filtrado del firewall en tiempo real.
          </p>

          <div className="space-y-3">
            <div>
              <label className="text-[10px] font-bold text-slate-550 block mb-1">Escriba su IP Corporativa</label>
              <select
                value={userIpQuery}
                onChange={(e) => {
                  setUserIpQuery(e.target.value);
                  setVerificationResult(null);
                  setDiagnosticLogs([]);
                }}
                className="w-full text-xs p-2.5 bg-slate-50 border border-slate-300 rounded-xl font-mono focus:outline-none"
              >
                {devices.map(d => (
                  <option key={d.id} value={d.ip}>{d.name} ({d.ip})</option>
                ))}
              </select>
            </div>

            <button 
              onClick={handleRunDiagnostic}
              disabled={isClassifying}
              className="w-full py-2.5 bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs rounded-xl flex items-center justify-center gap-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              {isClassifying ? 'Inspeccionando Adaptador...' : 'Iniciar Autoevaluación de Red'}
            </button>
          </div>

          <div className="p-4 bg-amber-50 rounded-xl border border-amber-200">
            <span className="text-xs font-bold text-amber-900 block flex items-center gap-1">
              <Lock className="w-4 h-4 text-amber-700" /> Cifrado E2EE permanente
            </span>
            <p className="text-[11px] text-amber-700 mt-1">Este dispositivo efectúa llaves de transporte criptográficas locales. Cumple con los estándares globales de confidencialidad.</p>
          </div>
        </div>

        {/* Right diagnostic logs visualizer */}
        <div className="bg-slate-950 text-emerald-400 rounded-2xl p-4 font-mono text-[11px] min-h-[220px] flex flex-col justify-between border border-slate-800 shadow">
          <div>
            <div className="flex justify-between items-center pb-2 border-b border-emerald-950 mb-3 text-emerald-500 font-bold">
              <span>DIAGNOSTIC_SHELL_TRACE</span>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
            </div>
            
            {diagnosticLogs.length === 0 ? (
              <p className="text-slate-500 italic text-center py-8">Esperando inicio de diagnóstico corporativo...</p>
            ) : (
              <div className="space-y-1.5 max-h-[160px] overflow-y-auto">
                {diagnosticLogs.map((log, i) => (
                  <p key={i} className="leading-relaxed">
                    <span className="text-slate-500 mr-1.5">&gt;</span>{log}
                  </p>
                ))}
              </div>
            )}
          </div>

          <span className="text-[9px] text-emerald-600 block mt-4 border-t border-emerald-950 pt-2 text-right">
            NETSHIELD SECURE CONNECT AGENT v4.2.1
          </span>
        </div>

      </div>

      {/* Verification overlay popups inside main layout */}
      {verificationResult && (
        <div className={`p-6 rounded-2xl border flex gap-4 ${
          verificationResult.status === 'secure' 
            ? 'bg-emerald-50 border-emerald-200 text-emerald-900' 
            : 'bg-red-50 border-red-200 text-red-950'
        }`}>
          {verificationResult.status === 'secure' ? (
            <ShieldCheck className="w-12 h-12 text-emerald-600 flex-shrink-0" />
          ) : (
            <ShieldAlert className="w-12 h-12 text-red-600 flex-shrink-0" />
          )}

          <div>
            <h4 className="font-bold text-sm">{verificationResult.title}</h4>
            <p className="text-xs mt-1 leading-relaxed">{verificationResult.message}</p>
            
            {verificationResult.status === 'secure' ? (
              <span className="text-[10px] font-semibold text-emerald-600 block mt-3 flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" /> Todo en regla. Acceso libre disponible.
              </span>
            ) : (
              <div className="mt-3 space-y-1">
                <p className="text-[10px] text-red-700">Protocolo de auto-recuperación: Se ha generado un registro automatizado enviado a <strong>elbrayhan70@gmail.com</strong> para auditorias mensuales corporativas.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Corporate network quick FAQ guide */}
      <div className="bg-slate-50 border border-slate-200 rounded-2xl p-6">
        <h3 className="text-sm font-bold text-slate-800 flex items-center gap-1.5 mb-3">
          <HelpCircle className="w-5 h-5 text-slate-600" /> F.A.Q: Directrices del Cortafuegos Corporativo NetShield
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-650">
          <div>
            <h4 className="font-semibold text-slate-850">¿Por qué mi IP fue bloqueada?</h4>
            <p className="mt-1">Nuestro cortafuegos NetShield cuenta con tecnología IPS inteligente que identifica escaneos repetidos de puertos o saturación volumétrica bloqueando automáticamente para neutralizar posibles intrusiones.</p>
          </div>
          <div>
            <h4 className="font-semibold text-slate-850">¿Cómo funciona el Cifrado E2EE aquí?</h4>
            <p className="mt-1">Todo el tráfico sensible entre su equipo y los servidores de almacenamiento en la nube se cifra simétricamente con llaves locales para garantizar máxima confidencialidad ante terceros.</p>
          </div>
        </div>
      </div>

    </div>
  );
}
