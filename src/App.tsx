import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Server, 
  RefreshCw, 
  User, 
  Lock, 
  AlertTriangle, 
  Wifi, 
  Check, 
  ArrowRight,
  Sparkles,
  Info
} from 'lucide-react';

import AdminPanel from './components/AdminPanel';
import UserConsole from './components/UserConsole';
import { 
  Device, 
  NetworkLog, 
  BlockedRule, 
  MFAConfig, 
  BackupConfig, 
  EmailNotificationSettings,
  NetworkStats,
  SecurityIncident
} from './types';

export default function App() {
  const [networkState, setNetworkState] = useState<{
    devices: Device[];
    blockedRules: BlockedRule[];
    logs: NetworkLog[];
    stats: NetworkStats;
    mfaConfig: MFAConfig;
    backupConfig: BackupConfig;
    emailSettings: EmailNotificationSettings;
    securityIncidents: SecurityIncident[];
  } | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  
  // Tab controller: 'admin_dashboard' | 'user_console'
  const [appRoleView, setAppRoleView] = useState<'admin_dashboard' | 'user_console'>('admin_dashboard');
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Fetch all states from the server
  const fetchNetworkState = async (silent = false) => {
    if (!silent) setIsRefreshing(true);
    try {
      const res = await fetch('/api/network-state');
      if (!res.ok) {
        throw new Error('No se pudo establecer un canal seguro con la interfaz NetShield.');
      }
      const data = await res.json();
      setNetworkState(data);
      setErrorMessage(null);
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'Canalización de servidor NetShield errónea.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchNetworkState();
    // Poll state silently every 6 seconds to capture live simulator telemetry
    const interval = setInterval(() => {
      fetchNetworkState(true);
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleBlockIp = async (ip: string, reason: string, severity: string) => {
    try {
      const res = await fetch('/api/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, severity })
      });
      if (!res.ok) throw new Error('Error al registrar bloqueo.');
      const data = await res.json();
      await fetchNetworkState(true);
      return data;
    } catch (err: any) {
      alert(err.message);
      throw err;
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      const res = await fetch('/api/unblock-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      if (!res.ok) throw new Error('Error al remover bloqueo.');
      const data = await res.json();
      await fetchNetworkState(true);
      return data;
    } catch (err: any) {
      alert(err.message);
      throw err;
    }
  };

  const handleUpdateConfig = async (type: string, payload: any) => {
    try {
      const res = await fetch('/api/update-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, payload })
      });
      if (!res.ok) throw new Error('Error al registrar ajustes.');
      const data = await res.json();
      await fetchNetworkState(true);
      return data;
    } catch (err: any) {
      alert(err.message);
      throw err;
    }
  };

  const handleTriggerBackup = async () => {
    try {
      const res = await fetch('/api/trigger-backup', { method: 'POST' });
      if (!res.ok) throw new Error('Error en el conducto de respaldo.');
      const data = await res.json();
      await fetchNetworkState(true);
      return data;
    } catch (err: any) {
      alert(err.message);
      throw err;
    }
  };

  const handleSimulateIntrusion = async () => {
    try {
      const res = await fetch('/api/simulate-intrusion', { method: 'POST' });
      if (!res.ok) throw new Error('Inconveniente al levantar ataque.');
      const data = await res.json();
      await fetchNetworkState(true);
      return data;
    } catch (err: any) {
      alert(err.message);
      throw err;
    }
  };

  // Main global layout render
  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-800 antialiased font-sans selection:bg-slate-900 selection:text-white">
      
      {/* Upper corporate main bar */}
      <header className="bg-white border-b border-slate-150 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 md:px-8 py-4 flex items-center justify-between flex-wrap gap-4">
          
          <div className="flex items-center gap-3">
            <div className="bg-slate-900 text-white p-2.5 rounded-2xl shadow-sm hover:scale-105 transition">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-extrabold text-slate-900 tracking-tight">NetShield</h1>
                <span className="text-[10px] uppercase tracking-widest font-mono bg-emerald-50 text-emerald-700 px-1.5 py-0.5 rounded-md font-bold">
                  Enterprise
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-medium">Control de IP y Mitigaciones Redundantes de Red</p>
            </div>
          </div>

          {/* Quick toggle views */}
          <div className="flex items-center gap-2">
            <div className="bg-slate-100 p-1 rounded-xl flex items-center border border-slate-200">
              <button 
                onClick={() => setAppRoleView('admin_dashboard')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                  appRoleView === 'admin_dashboard' 
                    ? 'bg-white shadow text-slate-900' 
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                <Server className="w-3.5 h-3.5 text-indigo-600" />
                Panel Administrador (E2EE)
              </button>
              
              <button 
                onClick={() => setAppRoleView('user_console')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                  appRoleView === 'user_console' 
                    ? 'bg-white shadow text-slate-900' 
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                <Terminal className="w-3.5 h-3.5 text-slate-650" />
                Consola de Usuario Final
              </button>
            </div>

            {/* Manual manual state refresh */}
            <button 
              onClick={() => fetchNetworkState(false)}
              className="p-2 border border-slate-200 bg-white hover:bg-slate-50 transition rounded-xl text-slate-650 flex items-center gap-1.5 text-xs font-semibold ml-2"
              title="Actualizar estado de red"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Refrescar</span>
            </button>
          </div>

        </div>
      </header>

      {/* Info notice explaining simulation features */}
      <div className="bg-indigo-50 border-b border-indigo-150 p-3 text-center">
        <div className="max-w-7xl mx-auto px-4 text-xs text-indigo-950 flex items-center justify-center gap-2 flex-wrap font-medium">
          <Sparkles className="w-4 h-4 text-indigo-600 flex-shrink-0" />
          <span>¡NetShield está operando en tiempo real con simulación activa de tráfico! Puedes aislar IPs y usar Copiloto IA con un solo clic.</span>
          <span className="bg-indigo-200 text-indigo-900 font-mono text-[9px] px-1.5 py-0.5 rounded uppercase font-bold">Modo Demostración</span>
        </div>
      </div>

      {/* Main core layout box container */}
      <main className="max-w-7xl mx-auto px-4 md:px-8 py-8">
        
        {isLoading ? (
          <div className="flex flex-col items-center justify-center min-h-[50vh] text-center space-y-4">
            <div className="w-12 h-12 rounded-full border-4 border-slate-200 border-t-slate-900 animate-spin"></div>
            <p className="text-sm font-semibold text-slate-600">Conectando con el cortafuegos redundante NetShield...</p>
          </div>
        ) : errorMessage ? (
          <div className="bg-red-50 border border-red-200 rounded-2xl p-6 text-center max-w-lg mx-auto space-y-4 shadow-sm">
            <AlertTriangle className="w-12 h-12 text-red-650 mx-auto" />
            <h3 className="text-base font-bold text-red-900">Servicio de Red Fuera de Línea</h3>
            <p className="text-xs text-red-700">{errorMessage}</p>
            <button 
              onClick={() => fetchNetworkState(false)}
              className="px-4 py-2 bg-slate-900 text-white hover:bg-slate-800 rounded-xl text-xs font-semibold"
            >
              Realizar Intento de Reconexión
            </button>
          </div>
        ) : networkState ? (
          
          appRoleView === 'admin_dashboard' ? (
            <AdminPanel 
              devices={networkState.devices}
              blockedRules={networkState.blockedRules}
              logs={networkState.logs}
              stats={networkState.stats}
              mfaConfig={networkState.mfaConfig}
              backupConfig={networkState.backupConfig}
              emailSettings={networkState.emailSettings}
              securityIncidents={networkState.securityIncidents}
              onRefresh={() => fetchNetworkState(true)}
              onBlockIp={handleBlockIp}
              onUnblockIp={handleUnblockIp}
              onUpdateConfig={handleUpdateConfig}
              onTriggerBackup={handleTriggerBackup}
              onSimulateIntrusion={handleSimulateIntrusion}
            />
          ) : (
            <UserConsole 
              devices={networkState.devices}
              blockedRules={networkState.blockedRules}
              onRefresh={() => fetchNetworkState(true)}
            />
          )

        ) : null}

      </main>

      {/* Elegant corporate footer */}
      <footer className="bg-white border-t border-slate-150 py-8 mt-12">
        <div className="max-w-7xl mx-auto px-4 md:px-8 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-500" />
            <span>&copy; {new Date().getFullYear()} NetShield Enterprise Corporation. Todos los derechos reservados.</span>
          </div>
          
          <div className="flex items-center gap-6 font-mono text-[10px]">
            <span>MFA SECURE CHANNELS</span>
            <span>E2EE SHA-256 ENCRYPTED</span>
            <span>REDUNDANCY 99.99%</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
