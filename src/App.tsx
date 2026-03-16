import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Zap, 
  Lock, 
  Unlock, 
  Server, 
  Globe, 
  AlertTriangle,
  Info,
  Database,
  Cpu,
  RefreshCw,
  XCircle,
  CheckCircle2
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area 
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Utility for tailwind classes
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---
interface Packet {
  id: string;
  timestamp: number;
  ip: string;
  requestRate: number;
  payloadSize: number;
  protocol: 'TCP' | 'UDP' | 'HTTP';
  isMalicious: boolean;
  classification: 'Normal' | 'Attack';
  confidence: number;
  isInspecting: boolean;
}

interface TrafficData {
  time: string;
  normal: number;
  attack: number;
  blocked: number;
}

// --- Constants ---
const MAX_LOG_SIZE = 15;
const CHART_DATA_POINTS = 30;
const INSPECTION_TIME = 1000; // ms
const INITIAL_IPS = [
  '192.168.1.45', '10.0.0.12', '172.16.0.5', '8.8.8.8', '1.1.1.1'
];
const ATTACK_IPS = [
  '45.12.89.1', '103.4.22.11', '198.51.100.24', '203.0.113.5'
];

export default function App() {
  // --- State ---
  const [packets, setPackets] = useState<Packet[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<TrafficData[]>([]);
  const [isAttackActive, setIsAttackActive] = useState(false);
  const [isPreventionEnabled, setIsPreventionEnabled] = useState(true);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());
  const [stats, setStats] = useState({
    totalRequests: 0,
    detectedAttacks: 0,
    blockedRequests: 0,
    serverLoad: 15, // Percentage
  });
  const [activeTab, setActiveTab] = useState<'dashboard' | 'analysis' | 'about'>('dashboard');

  // --- Refs for Simulation ---
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const counterRef = useRef(0);

  // --- Simulation Logic ---
  const generatePacket = (): Packet => {
    // Increase malicious probability during attack for better visibility
    const isMalicious = isAttackActive && Math.random() > 0.2; 
    const ip = isMalicious 
      ? ATTACK_IPS[Math.floor(Math.random() * ATTACK_IPS.length)]
      : INITIAL_IPS[Math.floor(Math.random() * INITIAL_IPS.length)];
    
    // Features for the "Random Forest" to analyze
    // Ensure malicious packets ALWAYS cross the detection threshold
    const requestRate = isMalicious ? 90 + Math.random() * 50 : 2 + Math.random() * 12;
    const payloadSize = isMalicious ? 600 + Math.random() * 400 : 40 + Math.random() * 160;
    const protocol = isMalicious ? (Math.random() > 0.5 ? 'UDP' : 'TCP') : 'HTTP';

    // Simulated Random Forest Classification Logic
    // Directly tie classification to malicious intent for demo clarity
    const classification = isMalicious ? 'Attack' : 'Normal';
    const confidence = isMalicious ? 0.88 + Math.random() * 0.11 : 0.94 + Math.random() * 0.05;

    return {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      ip,
      requestRate,
      payloadSize,
      protocol,
      isMalicious,
      classification,
      confidence,
      isInspecting: true
    };
  };

  useEffect(() => {
    timerRef.current = setInterval(() => {
      const newPacket = generatePacket();
      const isBlocked = blockedIps.has(newPacket.ip);

      // We log the packet even if it's from a blocked IP to show the "Prevention" in action
      // but we mark it as already blocked if necessary
      setPackets(prev => [newPacket, ...prev].slice(0, MAX_LOG_SIZE));
      
      // Schedule inspection completion
      setTimeout(() => {
        setPackets(prev => prev.map(p => 
          p.id === newPacket.id ? { ...p, isInspecting: false } : p
        ));

        // Auto-Prevention Logic: Block IP if classified as Attack
        if (isPreventionEnabled && newPacket.classification === 'Attack' && !blockedIps.has(newPacket.ip)) {
          setBlockedIps(prev => new Set(prev).add(newPacket.ip));
        }
      }, INSPECTION_TIME);

      // Update Stats
      setStats(prev => {
        const newTotal = prev.totalRequests + 1;
        const newDetected = newPacket.classification === 'Attack' ? prev.detectedAttacks + 1 : prev.detectedAttacks;
        const newBlocked = isBlocked ? prev.blockedRequests + 1 : prev.blockedRequests;
        
        let loadDelta = isAttackActive ? (isPreventionEnabled ? 0.2 : 4) : -1.5;
        const newLoad = Math.min(Math.max(12, prev.serverLoad + loadDelta), 100);

        return {
          totalRequests: newTotal,
          detectedAttacks: newDetected,
          blockedRequests: newBlocked,
          serverLoad: newLoad
        };
      });

      // Update Traffic History for Chart
      counterRef.current++;
      if (counterRef.current % 3 === 0) {
        setTrafficHistory(prev => {
          const newData: TrafficData = {
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            normal: isAttackActive ? 8 + Math.random() * 4 : 25 + Math.random() * 15,
            attack: isAttackActive ? (isPreventionEnabled ? 2 : 90 + Math.random() * 10) : 0,
            blocked: isPreventionEnabled && isAttackActive ? 80 + Math.random() * 20 : 0
          };
          return [...prev, newData].slice(-CHART_DATA_POINTS);
        });
      }
    }, 800); // Slower interval for better readability of the log

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isAttackActive, isPreventionEnabled, blockedIps]);

  const resetSimulation = () => {
    setBlockedIps(new Set());
    setPackets([]);
    setStats({ totalRequests: 0, detectedAttacks: 0, blockedRequests: 0, serverLoad: 15 });
    setTrafficHistory([]);
  };

  return (
    <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">
      {/* --- Header --- */}
      <header className="border-b border-[#141414] p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-serif italic font-bold tracking-tight">DDoS Shield ML</h1>
          <p className="text-xs font-mono opacity-60 uppercase tracking-widest mt-1">Real-time Detection & Prevention System</p>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setIsAttackActive(!isAttackActive)}
            className={cn(
              "px-4 py-2 rounded-full font-mono text-xs uppercase tracking-tighter transition-all flex items-center gap-2 border border-[#141414]",
              isAttackActive ? "bg-red-500 text-white border-red-600 shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]" : "bg-white hover:bg-gray-100"
            )}
          >
            {isAttackActive ? <ShieldAlert size={14} /> : <Zap size={14} />}
            {isAttackActive ? "Stop Attack Simulation" : "Simulate DDoS Attack"}
          </button>
          
          <button 
            onClick={() => setIsPreventionEnabled(!isPreventionEnabled)}
            className={cn(
              "px-4 py-2 rounded-full font-mono text-xs uppercase tracking-tighter transition-all flex items-center gap-2 border border-[#141414]",
              isPreventionEnabled ? "bg-emerald-500 text-white border-emerald-600 shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]" : "bg-white hover:bg-gray-100"
            )}
          >
            {isPreventionEnabled ? <Lock size={14} /> : <Unlock size={14} />}
            Prevention: {isPreventionEnabled ? "Active" : "Disabled"}
          </button>

          <button 
            onClick={resetSimulation}
            className="p-2 rounded-full border border-[#141414] bg-white hover:bg-gray-100 transition-all"
            title="Reset Simulation"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      {/* --- Navigation --- */}
      <nav className="flex border-b border-[#141414] bg-white/50 backdrop-blur-sm sticky top-0 z-10">
        {[
          { id: 'dashboard', label: 'Dashboard', icon: Activity },
          { id: 'analysis', label: 'ML Analysis', icon: Cpu },
          { id: 'about', label: 'Project Info', icon: Info },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={cn(
              "flex-1 py-4 px-6 flex items-center justify-center gap-2 font-mono text-[10px] uppercase tracking-widest transition-all border-r border-[#141414] last:border-r-0",
              activeTab === tab.id ? "bg-[#141414] text-[#E4E3E0]" : "hover:bg-white"
            )}
          >
            <tab.icon size={14} />
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="p-6 max-w-7xl mx-auto space-y-6">
        {activeTab === 'dashboard' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* --- Stats Cards --- */}
            <div className="lg:col-span-12 grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard 
                label="Server Load" 
                value={`${stats.serverLoad.toFixed(0)}%`} 
                icon={Server} 
                color={stats.serverLoad > 80 ? "text-red-600" : stats.serverLoad > 50 ? "text-orange-500" : "text-emerald-600"}
              />
              <StatCard 
                label="Total Requests" 
                value={stats.totalRequests.toLocaleString()} 
                icon={Globe} 
              />
              <StatCard 
                label="Attacks Detected" 
                value={stats.detectedAttacks.toLocaleString()} 
                icon={ShieldAlert} 
                color="text-red-600"
              />
              <StatCard 
                label="IPs Blocked" 
                value={blockedIps.size} 
                icon={Lock} 
                color="text-emerald-600"
              />
            </div>

            {/* --- Main Chart --- */}
            <div className="lg:col-span-8 bg-white border border-[#141414] p-6 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)]">
              <div className="flex justify-between items-center mb-6">
                <h2 className="font-serif italic text-xl">Real-time Traffic Monitor</h2>
                <div className="flex gap-4 font-mono text-[10px] uppercase tracking-tighter">
                  <span className="flex items-center gap-1"><span className="w-2 h-2 bg-emerald-500 rounded-full"></span> Normal</span>
                  <span className="flex items-center gap-1"><span className="w-2 h-2 bg-red-500 rounded-full"></span> Attack</span>
                  <span className="flex items-center gap-1"><span className="w-2 h-2 bg-gray-400 rounded-full"></span> Blocked</span>
                </div>
              </div>
              <div className="h-[300px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trafficHistory}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#eee" />
                    <XAxis dataKey="time" hide />
                    <YAxis hide domain={[0, 120]} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#141414', color: '#E4E3E0', border: 'none', fontFamily: 'monospace', fontSize: '10px' }}
                      itemStyle={{ color: '#E4E3E0' }}
                    />
                    <Area type="monotone" dataKey="normal" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.6} isAnimationActive={false} />
                    <Area type="monotone" dataKey="attack" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} isAnimationActive={false} />
                    <Area type="monotone" dataKey="blocked" stackId="1" stroke="#9ca3af" fill="#9ca3af" fillOpacity={0.6} isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* --- Blocked IPs List --- */}
            <div className="lg:col-span-4 bg-white border border-[#141414] p-6 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)] flex flex-col h-full">
              <h2 className="font-serif italic text-xl mb-4 flex items-center gap-2">
                <Lock size={18} /> Prevention Module
              </h2>
              <div className="flex-1 overflow-y-auto space-y-2 max-h-[300px] pr-2 custom-scrollbar">
                <AnimatePresence initial={false}>
                  {blockedIps.size === 0 ? (
                    <motion.div 
                      key="empty"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="h-full flex flex-col items-center justify-center opacity-30 py-10"
                    >
                      <ShieldCheck size={48} />
                      <p className="text-[10px] font-mono mt-2 uppercase">No IPs Blocked</p>
                    </motion.div>
                  ) : (
                    Array.from(blockedIps).reverse().map(ip => (
                      <motion.div 
                        key={ip}
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3, ease: "easeOut" }}
                        className="flex justify-between items-center p-3 bg-red-50 border border-red-200 rounded-lg"
                      >
                        <div className="flex items-center gap-2">
                          <XCircle size={14} className="text-red-500" />
                          <span className="font-mono text-xs font-bold">{ip}</span>
                        </div>
                        <span className="text-[8px] font-mono bg-red-500 text-white px-1 rounded uppercase">Blocked</span>
                      </motion.div>
                    ))
                  )}
                </AnimatePresence>
              </div>
            </div>

            {/* --- Live Packet Log --- */}
            <div className="lg:col-span-12 bg-white border border-[#141414] shadow-[8px_8px_0px_0px_rgba(20,20,20,1)] overflow-hidden">
              <div className="p-4 border-b border-[#141414] bg-[#141414] text-[#E4E3E0] flex justify-between items-center">
                <h2 className="font-mono text-[10px] uppercase tracking-widest flex items-center gap-2">
                  <Activity size={12} /> Live Traffic Analysis Log
                </h2>
                <div className="flex gap-4 text-[8px] font-mono opacity-60">
                  <span>RF MODEL: RANDOM FOREST HYBRID</span>
                  <span>DATASET: CICDDOS2019</span>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-gray-50 border-b border-[#141414]">
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Timestamp</th>
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Source IP</th>
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Req Rate</th>
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Payload</th>
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Protocol</th>
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Classification</th>
                      <th className="p-3 font-serif italic text-[11px] opacity-50 uppercase">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    <AnimatePresence initial={false}>
                      {packets.map((packet) => (
                        <motion.tr 
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ 
                            opacity: 1, 
                            x: 0,
                            backgroundColor: packet.isInspecting && packet.requestRate > 40 
                              ? '#fffbeb' // Subtle yellow warning during inspection
                              : '#fff' 
                          }}
                          key={packet.id} 
                          className={cn(
                            "border-b border-gray-100 transition-colors",
                            packet.isInspecting && packet.requestRate > 40 && "animate-pulse"
                          )}
                        >
                          <td className="p-3 font-mono text-[10px]">{new Date(packet.timestamp).toLocaleTimeString()}</td>
                          <td className="p-3 font-mono text-[10px] font-bold">{packet.ip}</td>
                          <td className="p-3 font-mono text-[10px]">{packet.requestRate.toFixed(1)} req/s</td>
                          <td className="p-3 font-mono text-[10px]">{packet.payloadSize.toFixed(0)} KB</td>
                          <td className="p-3 font-mono text-[10px]"><span className="bg-gray-100 px-1 rounded">{packet.protocol}</span></td>
                          <td className="p-3">
                            <AnimatePresence mode="wait">
                              {packet.isInspecting ? (
                                <motion.div 
                                  key="inspecting"
                                  initial={{ opacity: 0, y: 5 }}
                                  animate={{ opacity: 1, y: 0 }}
                                  exit={{ opacity: 0 }}
                                  className="flex flex-col gap-0.5"
                                >
                                  <div className="flex items-center gap-2 text-[9px] font-mono text-gray-400 uppercase italic">
                                    <RefreshCw size={10} className="animate-spin" />
                                    Inspecting...
                                  </div>
                                  <div className="flex gap-2 text-[7px] font-mono text-gray-300 uppercase tracking-tighter">
                                    <span>R:{packet.requestRate.toFixed(0)}</span>
                                    <span>S:{packet.payloadSize.toFixed(0)}</span>
                                    <span>P:{packet.protocol}</span>
                                  </div>
                                </motion.div>
                              ) : (
                                <motion.div
                                  key="classified"
                                  initial={{ scale: 0.8, opacity: 0 }}
                                  animate={{ scale: 1, opacity: 1 }}
                                  className="group relative"
                                >
                                  <span 
                                    className={cn(
                                      "text-[9px] font-mono px-2 py-0.5 rounded-full uppercase font-bold flex items-center gap-1 w-fit cursor-help",
                                      packet.classification === 'Attack' ? "bg-red-100 text-red-700" : "bg-emerald-100 text-emerald-700"
                                    )}
                                  >
                                    {packet.classification === 'Attack' ? <ShieldAlert size={10} /> : <ShieldCheck size={10} />}
                                    {packet.classification}
                                  </span>
                                  
                                  {/* Tooltip for features */}
                                  <div className="absolute left-0 bottom-full mb-2 hidden group-hover:block z-50">
                                    <div className="bg-[#141414] text-[#E4E3E0] p-2 rounded text-[8px] font-mono border border-gray-800 shadow-xl whitespace-nowrap">
                                      <p className="border-b border-gray-700 pb-1 mb-1 opacity-50 uppercase">Feature Vector</p>
                                      <p>Rate: {packet.requestRate.toFixed(2)} req/s</p>
                                      <p>Size: {packet.payloadSize.toFixed(0)} KB</p>
                                      <p>Proto: {packet.protocol}</p>
                                      <p className="mt-1 pt-1 border-t border-gray-700 text-emerald-400">Model: Random Forest</p>
                                    </div>
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </td>
                          <td className="p-3 font-mono text-[10px]">
                            {packet.isInspecting ? (
                              <span className="opacity-20">--</span>
                            ) : (
                              <div className="flex items-center gap-2">
                                <div className="w-12 h-1 bg-gray-100 rounded-full overflow-hidden">
                                  <div 
                                    className={cn("h-full", packet.classification === 'Attack' ? "bg-red-500" : "bg-emerald-500")} 
                                    style={{ width: `${packet.confidence * 100}%` }}
                                  />
                                </div>
                                {(packet.confidence * 100).toFixed(1)}%
                              </div>
                            )}
                          </td>
                        </motion.tr>
                      ))}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analysis' && (
          <div className="space-y-6">
            <div className="bg-white border border-[#141414] p-8 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)]">
              <h2 className="font-serif italic text-3xl mb-6">Machine Learning Pipeline</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                <AnalysisStep 
                  number="01" 
                  title="Data Collection" 
                  desc="Capturing live network traffic packets using tools like Wireshark or Scapy. Focus on IP headers and payload sizes."
                  icon={Database}
                />
                <AnalysisStep 
                  number="02" 
                  title="Preprocessing" 
                  desc="Normalization and feature selection using Pandas/NumPy to reduce noise and handle large CICDDoS2019 datasets."
                  icon={RefreshCw}
                />
                <AnalysisStep 
                  number="03" 
                  title="RF Classification" 
                  desc="Random Forest hybrid algorithm analyzes patterns (Normal vs. Attack) based on learned malicious behaviors."
                  icon={Cpu}
                />
                <AnalysisStep 
                  number="04" 
                  title="Prevention" 
                  desc="Automated blocking of identified malicious IPs via firewall or network gateway to protect server resources."
                  icon={Shield}
                />
              </div>

              <div className="mt-12 grid grid-cols-1 lg:grid-cols-2 gap-8 border-t border-gray-100 pt-12">
                <div>
                  <h3 className="font-serif italic text-xl mb-4">Random Forest Hybrid Logic</h3>
                  <p className="text-sm leading-relaxed opacity-70">
                    The system uses a <strong>Random Forest</strong> ensemble of decision trees. Each tree votes on whether a packet is malicious. 
                    The "Hybrid" approach enhances standard RF by incorporating real-time thresholding for request rates, reducing the 
                    <strong> Overfitting Error</strong> mentioned in your document.
                  </p>
                  <ul className="mt-4 space-y-2 font-mono text-[10px] uppercase tracking-tighter">
                    <li className="flex items-center gap-2"><CheckCircle2 size={12} className="text-emerald-500" /> High Accuracy on CICDDoS2019</li>
                    <li className="flex items-center gap-2"><CheckCircle2 size={12} className="text-emerald-500" /> Real-time Packet Inspection</li>
                    <li className="flex items-center gap-2"><CheckCircle2 size={12} className="text-emerald-500" /> Automated Firewall Integration</li>
                  </ul>
                </div>
                <div className="bg-gray-50 p-6 rounded-xl border border-dashed border-gray-300">
                  <h3 className="font-serif italic text-xl mb-4">Model Performance</h3>
                  <div className="space-y-4">
                    <ProgressBar label="Accuracy" value={98.4} color="bg-emerald-500" />
                    <ProgressBar label="Precision" value={97.2} color="bg-emerald-500" />
                    <ProgressBar label="Recall" value={99.1} color="bg-emerald-500" />
                    <ProgressBar label="F1-Score" value={98.1} color="bg-emerald-500" />
                  </div>
                </div>
              </div>

              <div className="mt-12 grid grid-cols-1 lg:grid-cols-2 gap-8 border-t border-gray-100 pt-12">
                {/* --- Feature Importance --- */}
                <div className="space-y-4">
                  <h3 className="font-serif italic text-xl flex items-center gap-2">
                    <Activity size={18} /> Feature Importance (Gini Impurity)
                  </h3>
                  <p className="text-[10px] font-mono opacity-60 uppercase tracking-tighter">
                    How much each feature contributes to the Random Forest decision.
                  </p>
                  <div className="h-[200px] w-full mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart layout="vertical" data={[
                        { name: 'Request Rate', value: 85 },
                        { name: 'Payload Size', value: 65 },
                        { name: 'Protocol Type', value: 30 },
                        { name: 'Packet Interval', value: 15 },
                      ]}>
                        <XAxis type="number" hide />
                        <YAxis dataKey="name" type="category" width={100} tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                        <Tooltip 
                          cursor={{ fill: 'transparent' }}
                          contentStyle={{ backgroundColor: '#141414', color: '#E4E3E0', border: 'none', fontFamily: 'monospace', fontSize: '10px' }}
                        />
                        <Line type="monotone" dataKey="value" stroke="#141414" strokeWidth={2} dot={{ r: 4, fill: '#141414' }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* --- Decision Boundary --- */}
                <div className="space-y-4">
                  <h3 className="font-serif italic text-xl flex items-center gap-2">
                    <Globe size={18} /> 2D Decision Boundary
                  </h3>
                  <div className="relative h-[200px] w-full border border-gray-200 rounded-lg overflow-hidden bg-emerald-50/30">
                    {/* Background Zones */}
                    <div className="absolute inset-0 flex">
                      <div className="w-[60%] h-full bg-emerald-500/5 border-r border-dashed border-emerald-200"></div>
                      <div className="w-[40%] h-full bg-red-500/5"></div>
                    </div>
                    
                    {/* Labels */}
                    <div className="absolute top-2 left-2 text-[8px] font-mono uppercase opacity-40">Normal Zone</div>
                    <div className="absolute top-2 right-2 text-[8px] font-mono uppercase text-red-600 opacity-40">Attack Zone</div>
                    
                    {/* Simulated Data Points */}
                    <div className="absolute inset-0 p-4">
                      {/* Normal Points */}
                      {[...Array(15)].map((_, i) => (
                        <div 
                          key={`n-${i}`}
                          className="absolute w-1.5 h-1.5 bg-emerald-500 rounded-full opacity-40"
                          style={{ 
                            left: `${10 + Math.random() * 45}%`, 
                            top: `${20 + Math.random() * 60}%` 
                          }}
                        />
                      ))}
                      {/* Attack Points */}
                      {[...Array(10)].map((_, i) => (
                        <div 
                          key={`a-${i}`}
                          className="absolute w-1.5 h-1.5 bg-red-500 rounded-full opacity-40"
                          style={{ 
                            left: `${65 + Math.random() * 25}%`, 
                            top: `${10 + Math.random() * 80}%` 
                          }}
                        />
                      ))}
                    </div>
                    
                    {/* Axes Labels */}
                    <div className="absolute bottom-1 left-1/2 -translate-x-1/2 text-[7px] font-mono uppercase tracking-widest opacity-30">Request Rate →</div>
                    <div className="absolute left-1 top-1/2 -translate-y-1/2 -rotate-90 text-[7px] font-mono uppercase tracking-widest opacity-30">Payload Size →</div>
                  </div>
                  <p className="text-[9px] font-mono opacity-60 leading-tight">
                    Visualization of the model's separation logic. High request rates combined with irregular payload sizes trigger the "Attack" classification.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'about' && (
          <div className="max-w-3xl mx-auto bg-white border border-[#141414] p-10 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)]">
            <h2 className="font-serif italic text-4xl mb-8 border-b border-gray-100 pb-4">Project Overview</h2>
            
            <div className="space-y-8">
              <section>
                <h3 className="font-mono text-[10px] uppercase tracking-widest text-emerald-600 mb-2">The Mission</h3>
                <p className="text-lg leading-relaxed font-serif italic">
                  "The aim of our project is to detect and prevent DDoS attacks in real time using machine learning. 
                  It helps to protect servers from being overloaded by fake traffic."
                </p>
              </section>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <section>
                  <h3 className="font-mono text-[10px] uppercase tracking-widest text-emerald-600 mb-2">Technology Stack</h3>
                  <ul className="space-y-2 font-mono text-xs">
                    <li className="flex justify-between border-b border-gray-50 pb-1"><span>Language</span> <span className="font-bold">Python</span></li>
                    <li className="flex justify-between border-b border-gray-50 pb-1"><span>Algorithm</span> <span className="font-bold">Random Forest</span></li>
                    <li className="flex justify-between border-b border-gray-50 pb-1"><span>Libraries</span> <span className="font-bold">Scikit-learn, Pandas</span></li>
                    <li className="flex justify-between border-b border-gray-50 pb-1"><span>Dataset</span> <span className="font-bold">CICDDoS2019</span></li>
                  </ul>
                </section>

                <section>
                  <h3 className="font-mono text-[10px] uppercase tracking-widest text-red-600 mb-2">Key Challenges</h3>
                  <div className="space-y-3">
                    <div>
                      <p className="text-[10px] font-bold uppercase">Large Datasets</p>
                      <p className="text-[10px] opacity-60">Handled using normalization and feature selection.</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase">Overfitting Error</p>
                      <p className="text-[10px] opacity-60">Solved by reducing tree depth and cross-validation.</p>
                    </div>
                  </div>
                </section>
              </div>

              <section className="bg-[#141414] text-[#E4E3E0] p-6 rounded-lg">
                <h3 className="font-mono text-[10px] uppercase tracking-widest opacity-50 mb-4">Real-world Scenario</h3>
                <p className="text-sm leading-relaxed italic font-serif">
                  "Let’s take the example of a banking website that handles thousands of users performing transactions every second. 
                  Our system built using the Random Forest-based hybrid algorithm constantly monitors live network traffic to ensure 
                  legitimate users are never blocked while attackers are instantly classified and stopped."
                </p>
              </section>
            </div>
          </div>
        )}
      </main>

      <footer className="p-10 border-t border-[#141414] mt-10 text-center">
        <p className="font-mono text-[10px] uppercase tracking-widest opacity-40">
          DDoS Shield ML • Built with Python Logic & React Simulation • 2026
        </p>
      </footer>

      {/* --- Global Styles --- */}
      <style dangerouslySetInnerHTML={{ __html: `
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #141414;
          border-radius: 10px;
        }
      `}} />
    </div>
  );
}

// --- Sub-components ---

function StatCard({ label, value, icon: Icon, color = "text-[#141414]" }: { label: string, value: string | number, icon: any, color?: string }) {
  return (
    <div className="bg-white border border-[#141414] p-4 shadow-[4px_4px_0px_0px_rgba(20,20,20,1)] flex items-center gap-4">
      <div className={cn("p-2 bg-gray-50 rounded-lg", color)}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-[10px] font-mono uppercase opacity-50 tracking-tighter">{label}</p>
        <p className={cn("text-xl font-serif italic font-bold", color)}>{value}</p>
      </div>
    </div>
  );
}

function AnalysisStep({ number, title, desc, icon: Icon }: { number: string, title: string, desc: string, icon: any }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <span className="font-serif italic text-2xl opacity-20">{number}</span>
        <div className="p-2 bg-gray-100 rounded-lg">
          <Icon size={18} />
        </div>
      </div>
      <h3 className="font-mono text-xs font-bold uppercase tracking-tight">{title}</h3>
      <p className="text-[10px] leading-relaxed opacity-60">{desc}</p>
    </div>
  );
}

function ProgressBar({ label, value, color }: { label: string, value: number, color: string }) {
  return (
    <div className="space-y-1">
      <div className="flex justify-between font-mono text-[9px] uppercase">
        <span>{label}</span>
        <span>{value}%</span>
      </div>
      <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
        <motion.div 
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 1, ease: "easeOut" }}
          className={cn("h-full", color)} 
        />
      </div>
    </div>
  );
}
