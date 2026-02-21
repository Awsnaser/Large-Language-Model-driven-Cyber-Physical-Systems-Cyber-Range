import React, { useState, useEffect, useRef, useCallback } from 'react';
import TopologyCanvas from './TopologyCanvas';
import { PublicationTopology } from './components/PublicationTopology';
import { SimulationData, RoundData, PlaybackState } from './types';
import { generateDemoData } from './demoData';

const CANVAS_WIDTH = 1100;
const CANVAS_HEIGHT = 700;

const App: React.FC = () => {
  const [simData, setSimData] = useState<SimulationData | null>(null);
  const [currentFrame, setCurrentFrame] = useState(0);
  const [playbackState, setPlaybackState] = useState<PlaybackState>('stopped');
  const [fps, setFps] = useState(3);
  const [compromisedSet, setCompromisedSet] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [publicationMode, setPublicationMode] = useState(false);
  const [showIPs, setShowIPs] = useState(true);
  const [compactMode, setCompactMode] = useState(false);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load demo data on mount
  useEffect(() => {
    const demo = generateDemoData();
    setSimData(demo);
  }, []);

  // Playback timer
  useEffect(() => {
    if (playbackState === 'playing' && simData) {
      timerRef.current = setInterval(() => {
        setCurrentFrame((prev) => {
          const next = prev + 1;
          if (next >= simData.rounds.length) {
            setPlaybackState('stopped');
            return 0;
          }
          return next;
        });
      }, 1000 / fps);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [playbackState, fps, simData]);

  // Update compromised set based on current round
  useEffect(() => {
    if (!simData || simData.rounds.length === 0) return;
    const round = simData.rounds[Math.min(currentFrame, simData.rounds.length - 1)];
    // Build compromised set from accumulated red successes up to this round
    const compSet = new Set<string>();
    for (let i = 0; i <= Math.min(currentFrame, simData.rounds.length - 1); i++) {
      const r = simData.rounds[i];
      if (r.red_result && r.red_result.startsWith('SUCCESS') && r.red_target && r.red_target !== 'NONE') {
        compSet.add(r.red_target);
      }
      if (r.red_result && r.red_result.startsWith('CRITICAL') && r.red_target && r.red_target !== 'NONE') {
        compSet.add(r.red_target);
      }
      // Blue restores remove compromises
      if (r.blue_action === 'RESTORE' && r.blue_target && r.blue_target !== 'NONE' && r.blue_result && r.blue_result.startsWith('DEFENSE')) {
        compSet.delete(r.blue_target);
      }
    }
    setCompromisedSet(compSet);
  }, [currentFrame, simData]);

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setError(null);
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target?.result as string) as SimulationData;
        setSimData(data);
        setCurrentFrame(0);
        setPlaybackState('stopped');
      } catch (err) {
        setError('Failed to parse JSON file. Expected SimulationData format.');
      } finally {
        setLoading(false);
      }
    };
    reader.readAsText(file);
  }, []);

  const handlePlay = () => {
    if (!simData || simData.rounds.length === 0) return;
    if (playbackState === 'playing') {
      setPlaybackState('paused');
    } else {
      if (currentFrame >= (simData?.rounds.length || 1) - 1) setCurrentFrame(0);
      setPlaybackState('playing');
    }
  };

  const handleStop = () => {
    setPlaybackState('stopped');
    setCurrentFrame(0);
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    setCurrentFrame(Number(e.target.value));
  };

  const currentRound: RoundData | null = simData
    ? simData.rounds[Math.min(currentFrame, simData.rounds.length - 1)] || null
    : null;

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', color: '#e2e8f0', padding: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: '#f1f5f9', margin: 0 }}>
            🔒 CPS Topology Animation Viewer
          </h1>
          <p style={{ fontSize: 13, color: '#94a3b8', margin: '4px 0 0 0' }}>
            {simData ? `${simData.total_ips} hosts • ${simData.subnets.length} subnets • ${simData.rounds.length} rounds` : 'No data loaded'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            onClick={() => fileInputRef.current?.click()}
            style={btnStyle('#334155')}
          >
            📂 Load JSON
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            style={{ display: 'none' }}
            onChange={handleFileUpload}
          />
          <button
            onClick={() => { setSimData(generateDemoData()); setCurrentFrame(0); setPlaybackState('stopped'); }}
            style={btnStyle('#1e40af')}
          >
            🔄 Demo Data
          </button>
          <button
            onClick={() => setPublicationMode(!publicationMode)}
            style={btnStyle(publicationMode ? '#059669' : '#64748b')}
          >
            {publicationMode ? '📄 Publication Mode' : '🎨 Interactive Mode'}
          </button>
          {publicationMode && (
            <>
              <button
                onClick={() => setShowIPs(!showIPs)}
                style={btnStyle(showIPs ? '#059669' : '#64748b')}
              >
                {showIPs ? '🌐 Hide IPs' : '🌐 Show IPs'}
              </button>
              <button
                onClick={() => setCompactMode(!compactMode)}
                style={btnStyle(compactMode ? '#059669' : '#64748b')}
              >
                {compactMode ? '📦 Compact' : '📐 Normal'}
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div style={{ background: '#7f1d1d', padding: '8px 14px', borderRadius: 6, marginBottom: 12, fontSize: 13 }}>
          ⚠️ {error}
        </div>
      )}

      {/* Main layout */}
      <div style={{ display: 'flex', gap: 16 }}>
        {/* Left: Canvas */}
        <div>
          {simData && (
            <>
              {publicationMode ? (
                <PublicationTopology
                  assets={simData.assets}
                  subnets={simData.subnets}
                  currentRound={currentRound}
                  compromisedSet={compromisedSet}
                  width={CANVAS_WIDTH}
                  height={CANVAS_HEIGHT}
                  showIPs={showIPs}
                  showLabels={true}
                  compact={compactMode}
                />
              ) : (
                <TopologyCanvas
                  assets={simData.assets}
                  subnets={simData.subnets}
                  subnetLinks={simData.subnet_links}
                  currentRound={currentRound}
                  compromisedSet={compromisedSet}
                  width={CANVAS_WIDTH}
                  height={CANVAS_HEIGHT}
                />
              )}
            </>
          )}

          {/* Playback controls */}
          <div style={{
            marginTop: 10,
            background: '#1e293b',
            borderRadius: 8,
            padding: '10px 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
          }}>
            <button onClick={handlePlay} style={btnStyle('#2563eb')}>
              {playbackState === 'playing' ? '⏸ Pause' : '▶ Play'}
            </button>
            <button onClick={handleStop} style={btnStyle('#475569')}>
              ⏹ Stop
            </button>

            <input
              type="range"
              min={0}
              max={Math.max((simData?.rounds.length || 1) - 1, 0)}
              value={currentFrame}
              onChange={handleSeek}
              style={{ flex: 1, accentColor: '#3b82f6' }}
            />

            <span style={{ fontSize: 12, color: '#94a3b8', minWidth: 80, textAlign: 'right' }}>
              Round {currentRound?.round || 0} / {simData?.rounds.length || 0}
            </span>

            <label style={{ fontSize: 11, color: '#64748b' }}>
              FPS:
              <input
                type="number"
                min={1}
                max={30}
                value={fps}
                onChange={(e) => setFps(Math.max(1, Math.min(30, Number(e.target.value))))}
                style={{
                  width: 40, marginLeft: 4, background: '#0f172a', color: '#e2e8f0',
                  border: '1px solid #334155', borderRadius: 4, padding: '2px 4px', fontSize: 11,
                }}
              />
            </label>
          </div>
        </div>

        {/* Right: Status panels */}
        <div style={{ width: 300, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Round info */}
          <Panel title="Round Status">
            {currentRound ? (
              <>
                <StatusRow label="Round" value={`${currentRound.round}`} />
                <StatusRow label="Attacker Zone" value={currentRound.attacker_zone} color={
                  currentRound.attacker_zone === 'OT' ? '#ef4444' :
                  currentRound.attacker_zone === 'DMZ' ? '#f59e0b' : '#3b82f6'
                } />
                <StatusRow label="Tank Level" value={`${currentRound.tank_level.toFixed(1)}%`} color={
                  currentRound.tank_level > 85 || currentRound.tank_level < 15 ? '#ef4444' : '#10b981'
                } />
                <StatusRow label="Compromised" value={`${currentRound.compromised_count}`} color={
                  currentRound.compromised_count > 2 ? '#ef4444' : '#f59e0b'
                } />
                <StatusRow label="Alerts" value={`${currentRound.alerts_total}`} />
                <StatusRow label="GP P(alarm)" value={`${currentRound.gp_p_alarm.toFixed(3)}`} color={
                  currentRound.gp_p_alarm > 0.7 ? '#ef4444' : '#94a3b8'
                } />
                <StatusRow label="GP P(damage)" value={`${currentRound.gp_p_damage.toFixed(3)}`} color={
                  currentRound.gp_p_damage > 0.3 ? '#ef4444' : '#94a3b8'
                } />
                {currentRound.alarm_flag > 0 && (
                  <div style={{ marginTop: 6, padding: '4px 8px', background: '#7f1d1d', borderRadius: 4, fontSize: 11, textAlign: 'center' }}>
                    ⚠️ ALARM ACTIVE
                  </div>
                )}
                {currentRound.damage_flag > 0 && (
                  <div style={{ marginTop: 4, padding: '4px 8px', background: '#991b1b', borderRadius: 4, fontSize: 11, textAlign: 'center', fontWeight: 700 }}>
                    💥 DAMAGE DETECTED
                  </div>
                )}
              </>
            ) : (
              <p style={{ fontSize: 12, color: '#64748b' }}>No round data</p>
            )}
          </Panel>

          {/* Red action */}
          <Panel title="🔴 Red Action">
            {currentRound ? (
              <>
                <StatusRow label="Action" value={currentRound.red_action || 'NONE'} color="#ef4444" />
                <StatusRow label="Target" value={currentRound.red_target || 'NONE'} />
                <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4, wordBreak: 'break-all' }}>
                  {currentRound.red_result}
                </div>
              </>
            ) : null}
          </Panel>

          {/* Blue action */}
          <Panel title="🔵 Blue Action">
            {currentRound ? (
              <>
                <StatusRow label="Action" value={currentRound.blue_action || 'NONE'} color="#3b82f6" />
                <StatusRow label="Target" value={currentRound.blue_target || 'NONE'} />
                <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4, wordBreak: 'break-all' }}>
                  {currentRound.blue_result}
                </div>
              </>
            ) : null}
          </Panel>

          {/* Compromised assets */}
          <Panel title={`Compromised (${compromisedSet.size})`}>
            {compromisedSet.size === 0 ? (
              <p style={{ fontSize: 11, color: '#64748b' }}>No compromised assets</p>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {Array.from(compromisedSet).map((aid) => (
                  <span key={aid} style={{
                    fontSize: 10, background: '#7f1d1d', color: '#fca5a5',
                    padding: '2px 6px', borderRadius: 3,
                  }}>
                    {aid}
                  </span>
                ))}
              </div>
            )}
          </Panel>

          {/* Tank gauge */}
          <Panel title="Tank Level">
            {currentRound && (
              <div style={{ position: 'relative', height: 120, background: '#0f172a', borderRadius: 6, overflow: 'hidden' }}>
                <div style={{
                  position: 'absolute', bottom: 0, left: 0, right: 0,
                  height: `${Math.max(0, Math.min(100, currentRound.tank_level))}%`,
                  background: currentRound.tank_level > 85 ? '#ef4444' :
                    currentRound.tank_level < 15 ? '#f59e0b' : '#3b82f6',
                  transition: 'height 0.3s ease',
                  opacity: 0.7,
                }} />
                {/* Safe band markers */}
                <div style={{ position: 'absolute', top: '15%', left: 0, right: 0, height: 1, background: '#ef444466' }} />
                <div style={{ position: 'absolute', top: '60%', left: 0, right: 0, height: 1, background: '#ef444466' }} />
                <div style={{
                  position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
                  fontSize: 18, fontWeight: 700, color: '#f1f5f9',
                  textShadow: '0 0 8px rgba(0,0,0,0.8)',
                }}>
                  {currentRound.tank_level.toFixed(1)}%
                </div>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
};

// Helper components
const Panel: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div style={{
    background: '#1e293b', borderRadius: 8, padding: '10px 14px',
    border: '1px solid #334155',
  }}>
    <h3 style={{ fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
      {title}
    </h3>
    {children}
  </div>
);

const StatusRow: React.FC<{ label: string; value: string; color?: string }> = ({ label, value, color }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
    <span style={{ color: '#64748b' }}>{label}</span>
    <span style={{ fontWeight: 600, color: color || '#e2e8f0' }}>{value}</span>
  </div>
);

const btnStyle = (bg: string): React.CSSProperties => ({
  background: bg,
  color: '#e2e8f0',
  border: 'none',
  padding: '6px 14px',
  borderRadius: 6,
  cursor: 'pointer',
  fontSize: 13,
  fontWeight: 500,
});

export default App;
