import React, { useState, useEffect } from 'react';
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
  AlertCircle,
  LogIn,
  UserPlus,
  LogOut,
  Laptop,
  Cpu,
  RefreshCw,
  Mail,
  UserCheck,
  Activity,
  Shield,
  Key
} from 'lucide-react';
import { Device, UserSession } from '../types';

interface UserConsoleProps {
  devices: Device[];
  blockedRules: any[];
  currentUser: UserSession | null;
  onUserLogin: (user: UserSession) => void;
  onUserLogout: () => void;
  onRefresh: () => void;
}

export default function UserConsole({ 
  devices, 
  blockedRules, 
  currentUser, 
  onUserLogin, 
  onUserLogout, 
  onRefresh 
}: UserConsoleProps) {
  // Auth Form tabs: 'login' | 'register'
  const [authTab, setAuthTab] = useState<'login' | 'register'>('login');
  
  // Login form state
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Register form state
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regIp, setRegIp] = useState('192.168.1.115');
  const [regError, setRegError] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);

  // Auto-remediation state
  const [isRemediating, setIsRemediating] = useState(false);
  const [remediationMsg, setRemediationMsg] = useState('');

  // Find logged in user's matching device
  const userDevice = currentUser 
    ? devices.find(d => d.ip === currentUser.assignedIp) 
    : null;

  // Determine if the logged-in user is currently blocked by the IPS
  const isUserIpBlocked = currentUser 
    ? blockedRules.some(r => r.ip === currentUser.assignedIp)
    : false;

  // Handle User Login API request
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setIsLoggingIn(true);
    
    try {
      const res = await fetch('/api/user-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password: loginPassword })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Fallo en la autenticación.');
      }
      
      onUserLogin(data.user);
      onRefresh();
    } catch (err: any) {
      setLoginError(err.message || 'Error de conexión con el servidor NetShield.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  // Handle User Registration API request
  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegError('');
    setIsRegistering(true);

    try {
      const res = await fetch('/api/user-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          name: regName, 
          email: regEmail, 
          password: regPassword, 
          assignedIp: regIp 
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'No se pudo crear la cuenta.');
      }

      onUserLogin(data.user);
      onRefresh();
    } catch (err: any) {
      setRegError(err.message || 'Error de conexión al registrar el host.');
    } finally {
      setIsRegistering(false);
    }
  };

  // Automated Self-Service Verified Unblock
  const handleRequestAutoUnblock = async () => {
    if (!currentUser) return;
    setIsRemediating(true);
    setRemediationMsg('Iniciando verificación multifactor de sesión...');

    setTimeout(async () => {
      try {
        setRemediationMsg('Identidad validada. Enviando comando de mitigación cifrado al gateway de NetShield...');
        
        const res = await fetch('/api/unblock-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: currentUser.assignedIp })
        });
        
        if (!res.ok) {
          throw new Error('El firewall denegó la mitigación automática.');
        }
        
        setRemediationMsg('¡Bloqueo preventivo retirado con éxito! Sincronizando topología de red...');
        setTimeout(() => {
          onRefresh();
          setIsRemediating(false);
          setRemediationMsg('');
        }, 1200);

      } catch (err: any) {
        setRemediationMsg(`Error: ${err.message || 'No se pudo resolver.'}`);
        setIsRemediating(false);
      }
    }, 1800);
  };

  // If NOT logged in, render the secure register & login interface
  if (!currentUser) {
    return (
      <div className="max-w-md mx-auto my-8">
        <div className="bg-white border border-slate-200 rounded-3xl shadow-xl overflow-hidden">
          
          {/* Header */}
          <div className="bg-slate-900 p-8 text-center text-white relative">
            <div className="absolute right-3 top-3">
              <span className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 text-[9px] px-2 py-0.5 rounded-full font-mono font-bold uppercase tracking-wider">
                E2EE Gateway
              </span>
            </div>
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 mb-3">
              <Shield className="w-6 h-6 text-indigo-400 animate-pulse" />
            </div>
            <h2 className="text-xl font-extrabold tracking-tight">Portal de Empleado NetShield</h2>
            <p className="text-slate-400 text-xs mt-1.5 leading-relaxed">
              Inicie sesión o registre su estación de trabajo para diagnosticar su canal de tráfico corporativo.
            </p>
          </div>

          {/* Form Tabs */}
          <div className="flex border-b border-slate-100 bg-slate-50/50 p-1">
            <button
              onClick={() => {
                setAuthTab('login');
                setLoginError('');
                setRegError('');
              }}
              className={`flex-1 py-3 text-xs font-bold rounded-2xl transition duration-150 flex items-center justify-center gap-1.5 ${
                authTab === 'login' 
                  ? 'bg-white text-slate-900 shadow-xs border border-slate-100' 
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <LogIn className="w-3.5 h-3.5" />
              Iniciar Sesión
            </button>
            <button
              onClick={() => {
                setAuthTab('register');
                setLoginError('');
                setRegError('');
              }}
              className={`flex-1 py-3 text-xs font-bold rounded-2xl transition duration-150 flex items-center justify-center gap-1.5 ${
                authTab === 'register' 
                  ? 'bg-white text-slate-900 shadow-xs border border-slate-100' 
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5" />
              Registrar Estación
            </button>
          </div>

          <div className="p-6">
            {/* LOGIN FORM */}
            {authTab === 'login' && (
              <form onSubmit={handleLoginSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 block">Correo Electrónico Corporativo</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-400">
                      <Mail className="w-4 h-4" />
                    </span>
                    <input 
                      type="email"
                      required
                      value={loginEmail}
                      onChange={(e) => setLoginEmail(e.target.value)}
                      placeholder="ej: nombre@corporativo.com"
                      className="w-full text-xs pl-9 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white transition"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 block">Contraseña de Red</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-400">
                      <Lock className="w-4 h-4" />
                    </span>
                    <input 
                      type="password"
                      required
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="Ingrese su contraseña"
                      className="w-full text-xs pl-9 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white transition"
                    />
                  </div>
                </div>

                {loginError && (
                  <p className="text-xs font-semibold text-red-600 bg-red-50 p-2.5 border border-red-200 rounded-xl leading-snug">
                    {loginError}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={isLoggingIn}
                  className="w-full py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white font-bold text-xs rounded-xl flex items-center justify-center gap-2 transition duration-150 shadow"
                >
                  <UserCheck className="w-4 h-4" />
                  {isLoggingIn ? 'Iniciando canal seguro...' : 'Verificar Firma y Acceder'}
                </button>

                {/* Simulated Creds Helper */}
                <div className="pt-4 border-t border-slate-100 space-y-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block font-mono">
                    Credenciales de Acceso Rápido:
                  </span>
                  <div className="p-3 bg-indigo-50 border border-indigo-100 rounded-xl space-y-1.5 text-[11px] text-indigo-950 font-mono">
                    <div className="flex justify-between">
                      <span>CEO: <strong>elbrayhan70@gmail.com</strong></span>
                      <span className="text-slate-400">Clave: <strong>password123</strong></span>
                    </div>
                    <div className="flex justify-between border-t border-indigo-100/50 pt-1">
                      <span>Dev: <strong>alex@corporativo.com</strong></span>
                      <span className="text-slate-400">Clave: <strong>alex123</strong></span>
                    </div>
                  </div>
                </div>
              </form>
            )}

            {/* REGISTER FORM */}
            {authTab === 'register' && (
              <form onSubmit={handleRegisterSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 block">Nombre Completo</label>
                  <input 
                    type="text"
                    required
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="ej: Brayhan Sanchez"
                    className="w-full text-xs px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white transition"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 block">Correo Corporativo</label>
                  <input 
                    type="email"
                    required
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="ej: brayhan@corporativo.com"
                    className="w-full text-xs px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white transition"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-slate-700 block">Contraseña de Red Segura</label>
                  <input 
                    type="password"
                    required
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    placeholder="Cree su clave"
                    className="w-full text-xs px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white transition"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between items-center">
                    <label className="text-xs font-bold text-slate-700 block">IP Estación Asignada</label>
                    <button 
                      type="button" 
                      onClick={() => {
                        const randomSuffix = Math.floor(105 + Math.random() * 140);
                        setRegIp(`192.168.1.${randomSuffix}`);
                      }} 
                      className="text-[10px] text-indigo-700 hover:underline font-bold"
                    >
                      Asignar IP libre
                    </button>
                  </div>
                  <input 
                    type="text"
                    required
                    value={regIp}
                    onChange={(e) => setRegIp(e.target.value)}
                    placeholder="ej: 192.168.1.115"
                    className="w-full text-xs px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl font-mono focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white transition"
                  />
                </div>

                {regError && (
                  <p className="text-xs font-semibold text-red-600 bg-red-50 p-2.5 border border-red-200 rounded-xl leading-snug">
                    {regError}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={isRegistering}
                  className="w-full py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white font-bold text-xs rounded-xl flex items-center justify-center gap-2 transition duration-150 shadow"
                >
                  <UserPlus className="w-4 h-4" />
                  {isRegistering ? 'Asociando con el gateway...' : 'Registrar Host y Unirse'}
                </button>
              </form>
            )}
          </div>

          {/* Footer security tag */}
          <div className="bg-slate-50 border-t border-slate-100 p-4 text-center">
            <span className="text-[10px] text-slate-400 font-mono tracking-tight flex items-center justify-center gap-1">
              <Lock className="w-3.5 h-3.5 text-slate-400" />
              SISTEMA INTEGRAL DE ACCESO REDUNDANTE CORPORATIVO
            </span>
          </div>

        </div>
      </div>
    );
  }

  // If LOGGED IN, render the customized, adaptive dashboard
  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12 animate-fade-in">
      
      {/* Personalized Welcome Banner */}
      <div className="bg-gradient-to-br from-slate-900 to-indigo-950 text-white rounded-3xl p-8 shadow-lg border border-indigo-900 relative overflow-hidden">
        <div className="absolute right-0 top-0 opacity-10 pointer-events-none">
          <Terminal className="w-64 h-64 text-indigo-400" />
        </div>
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[9px] px-2.5 py-0.5 rounded-full font-mono font-bold uppercase tracking-wider flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                Sesión Empleado Activa
              </span>
              <span className="text-slate-400 font-mono text-[10px]">ID: {currentUser.id}</span>
            </div>
            <h2 className="text-2xl font-black mt-2 tracking-tight">Bienvenido de vuelta, {currentUser.name}</h2>
            <p className="text-slate-300 text-xs leading-relaxed max-w-xl">
              Canalización de seguridad redundante conectada. Su estación está validada para comunicarse con el cortafuegos central NetShield bajo políticas E2EE.
            </p>
          </div>

          <button
            onClick={onUserLogout}
            className="self-start md:self-center bg-white/10 hover:bg-white/15 text-slate-200 border border-white/10 text-xs font-bold px-4 py-2 rounded-xl flex items-center gap-1.5 transition"
          >
            <LogOut className="w-3.5 h-3.5 text-red-400" />
            Cerrar Sesión
          </button>
        </div>
      </div>

      {/* Adaptive Bento Grid of Device Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Card 1: Connection & Status */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm flex flex-col justify-between space-y-4">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">IP Asignada</span>
              <span className="font-mono text-lg font-black text-slate-800">{currentUser.assignedIp}</span>
            </div>
            <div className={`p-2.5 rounded-xl ${isUserIpBlocked ? 'bg-red-50 text-red-600' : 'bg-emerald-50 text-emerald-600'}`}>
              {isUserIpBlocked ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>
          </div>
          
          <div className="pt-2 border-t border-slate-100 flex justify-between items-center">
            <span className="text-xs font-bold text-slate-500">Estado Firewall:</span>
            <span className={`text-xs font-bold font-mono uppercase px-2.5 py-0.5 rounded-full ${
              isUserIpBlocked 
                ? 'bg-red-100 text-red-800 border border-red-200 animate-pulse' 
                : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
            }`}>
              {isUserIpBlocked ? 'Aislado (IPS Banned)' : 'Autorizado'}
            </span>
          </div>
        </div>

        {/* Card 2: Operating System & Hardware Specs */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm flex flex-col justify-between space-y-4">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Dispositivo Corporativo</span>
              <span className="font-sans text-sm font-bold text-slate-800 truncate block max-w-[170px]" title={userDevice?.name || 'Estación Remota'}>
                {userDevice?.name || `Estación de ${currentUser.name}`}
              </span>
              <span className="text-[10px] text-slate-500 block font-mono">OS: {userDevice?.os || 'Windows 11 Client'}</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-100 text-slate-600">
              <Laptop className="w-5 h-5" />
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 flex justify-between items-center text-xs">
            <span className="font-bold text-slate-500">MAC Address:</span>
            <span className="font-mono text-slate-600">{userDevice?.mac || '02:42:AC:11:XX:YY'}</span>
          </div>
        </div>

        {/* Card 3: Traffic & Threat level telemetry */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm flex flex-col justify-between space-y-4">
          <div className="flex justify-between items-start">
            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Seguridad del Host</span>
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${
                  isUserIpBlocked 
                    ? 'bg-red-500' 
                    : (userDevice?.threatLevel === 'medium' ? 'bg-amber-500' : 'bg-emerald-500')
                }`}></span>
                <span className="text-xs font-bold text-slate-700 capitalize">
                  Nivel de Amenaza: {isUserIpBlocked ? 'Crítico' : (userDevice?.threatLevel || 'bajo')}
                </span>
              </div>
              <span className="text-[10px] text-slate-400 block font-mono">Consumo: {((userDevice?.trafficBytes || 1048576) / (1024 * 1024)).toFixed(2)} MB</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-100 text-slate-650">
              <Cpu className="w-5 h-5" />
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 flex justify-between items-center text-xs">
            <span className="font-bold text-slate-500">Último Tráfico:</span>
            <span className="font-mono text-slate-600">{userDevice?.lastActive || 'En línea'}</span>
          </div>
        </div>

      </div>

      {/* Auto-Mitigation Alert & Unblock flow if the user is currently blocked */}
      {isUserIpBlocked && (
        <div className="bg-red-50 border border-red-200 rounded-3xl p-6 space-y-4 shadow-sm animate-pulse-slow">
          <div className="flex gap-4">
            <ShieldAlert className="w-12 h-12 text-red-650 flex-shrink-0" />
            <div>
              <h3 className="text-base font-bold text-red-950">Aislamiento de Firewall IPS Activo</h3>
              <p className="text-xs text-red-750 mt-1.5 leading-relaxed">
                El sistema de prevención ha suspendido dinámicamente el acceso de red para su dirección IP <strong>{currentUser.assignedIp}</strong> debido a un incidente de tráfico o auditoría preventiva.
              </p>
              <p className="text-xs text-red-700 mt-2 font-medium">
                Al tener una sesión autorizada activa como empleado ({currentUser.email}), puede iniciar el protocolo de auto-mitigación certificado para restablecer su conexión de red de forma inmediata.
              </p>
            </div>
          </div>

          {remediationMsg && (
            <div className="bg-white border border-red-100 text-slate-800 p-3 rounded-xl text-xs font-mono flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-600 animate-ping"></span>
              {remediationMsg}
            </div>
          )}

          <div className="flex justify-end pt-2 border-t border-red-100">
            <button
              onClick={handleRequestAutoUnblock}
              disabled={isRemediating}
              className="px-5 py-2.5 bg-red-600 hover:bg-red-700 disabled:bg-slate-400 text-white font-bold text-xs rounded-xl flex items-center gap-2 transition shadow-sm"
            >
              <Key className="w-4 h-4" />
              {isRemediating ? 'Validando Firma de Red...' : 'Solicitar Desbloqueo de Host Seguro'}
            </button>
          </div>
        </div>
      )}

      {/* Corporate network FAQ guide */}
      <div className="bg-slate-50 border border-slate-200 rounded-2xl p-6">
        <h3 className="text-sm font-bold text-slate-800 flex items-center gap-1.5 mb-3">
          <HelpCircle className="w-5 h-5 text-slate-600" /> Ayuda & FAQ: Directrices de Tráfico Corporativo
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-slate-600 leading-relaxed">
          <div>
            <h4 className="font-bold text-slate-800">¿Cómo me protege NetShield?</h4>
            <p className="mt-1">Nuestra arquitectura redundante filtra proactivamente accesos no deseados o de riesgo elevado, manteniendo el resto del tráfico local encriptado.</p>
          </div>
          <div>
            <h4 className="font-bold text-slate-800">¿Qué pasa si mi estación de trabajo es aislada?</h4>
            <p className="mt-1">Si realiza tareas que simulan ataques como escaneo o saturación de puertos, el IPS lo aislará temporalmente. En este portal autenticado, puede liberarse validando sus credenciales.</p>
          </div>
        </div>
      </div>

    </div>
  );
}
