import { ChangeEvent, CSSProperties, ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import TopologyCanvas from './TopologyCanvas';
import { PublicationTopology } from './components/PublicationTopology';
import { generateDemoData } from './demoData';
import { normalizeSimulationData } from './schema';
import { PlaybackState, RoundData, SimulationData } from './types';

const CANVAS_WIDTH = 1100;
const CANVAS_HEIGHT = 700;

export default function App() {
  const [simData, setSimData] = useState<SimulationData>(() => normalizeSimulationData(generateDemoData()));
  const [currentFrame, setCurrentFrame] = useState(0);
  const [playbackState, setPlaybackState] = useState<PlaybackState>('stopped');
  const [fps, setFps] = useState(3);
  const [compromisedSet, setCompromisedSet] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [publicationMode, setPublicationMode] = useState(false);
  const [showIPs, setShowIPs] = useState(true);
  const [compactMode, setCompactMode] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (playbackState !== 'playing' || simData.rounds.length === 0) return undefined;
    const timer = window.setInterval(() => {
      setCurrentFrame((frame) => {
        if (frame + 1 >= simData.rounds.length) {
          setPlaybackState('stopped');
          return 0;
        }
        return frame + 1;
      });
    }, 1000 / fps);
    return () => window.clearInterval(timer);
  }, [fps, playbackState, simData.rounds.length]);

  useEffect(() => {
    const compromised = new Set<string>();
    for (const round of simData.rounds.slice(0, currentFrame + 1)) {
      if ((round.red_result.startsWith('SUCCESS') || round.red_result.startsWith('CRITICAL')) && round.red_target !== 'NONE') compromised.add(round.red_target);
      if (round.blue_action === 'RESTORE' && round.blue_result.startsWith('DEFENSE') && round.blue_target !== 'NONE') compromised.delete(round.blue_target);
    }
    setCompromisedSet(compromised);
  }, [currentFrame, simData]);

  const loadData = useCallback((raw: unknown) => {
    const normalized = normalizeSimulationData(raw);
    if (normalized.assets.length === 0) throw new Error('The file has no usable assets.');
    setSimData(normalized);
    setCurrentFrame(0);
    setPlaybackState('stopped');
  }, []);

  const handleFileUpload = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const result = reader.result;
        if (typeof result !== 'string') throw new Error('The selected file could not be read as text.');
        loadData(JSON.parse(result));
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : 'Failed to parse JSON.');
      }
    };
    reader.onerror = () => setError('Failed to read the selected file.');
    reader.readAsText(file);
    event.target.value = '';
  }, [loadData]);

  const currentRound: RoundData | null = simData.rounds[Math.min(currentFrame, Math.max(simData.rounds.length - 1, 0))] ?? null;
  const roundedTank = currentRound ? Math.max(0, Math.min(100, currentRound.tank_level)) : 0;

  return <main className="app-shell">
    <header className="header">
      <div><h1>🔒 CPS Topology Viewer</h1><p>{simData.total_ips} hosts · {simData.subnets.length} subnets · {simData.rounds.length} rounds</p></div>
      <div className="toolbar">
        <button onClick={() => fileInputRef.current?.click()} style={buttonStyle('#334155')}>📂 Load JSON</button>
        <input ref={fileInputRef} type="file" accept="application/json,.json" hidden onChange={handleFileUpload} />
        <button onClick={() => { loadData(generateDemoData()); setError(null); }} style={buttonStyle('#1e40af')}>🔄 Demo data</button>
        <button onClick={() => setPublicationMode((value) => !value)} style={buttonStyle(publicationMode ? '#059669' : '#64748b')}>{publicationMode ? '📄 Publication' : '🎨 Interactive'}</button>
        {publicationMode && <><button onClick={() => setShowIPs((value) => !value)} style={buttonStyle('#64748b')}>{showIPs ? 'Hide IPs' : 'Show IPs'}</button><button onClick={() => setCompactMode((value) => !value)} style={buttonStyle('#64748b')}>{compactMode ? 'Normal' : 'Compact'}</button></>}
      </div>
    </header>
    {error && <div className="error" role="alert">⚠️ {error}</div>}
    <section className="viewer-layout">
      <div className="viewer-column">
        {publicationMode ? <PublicationTopology assets={simData.assets} subnets={simData.subnets} currentRound={currentRound} compromisedSet={compromisedSet} width={CANVAS_WIDTH} height={CANVAS_HEIGHT} showIPs={showIPs} compact={compactMode} /> : <TopologyCanvas assets={simData.assets} subnets={simData.subnets} subnetLinks={simData.subnet_links} currentRound={currentRound} compromisedSet={compromisedSet} width={CANVAS_WIDTH} height={CANVAS_HEIGHT} />}
        <div className="controls"><button onClick={() => setPlaybackState((state) => state === 'playing' ? 'paused' : 'playing')} style={buttonStyle('#2563eb')} disabled={simData.rounds.length === 0}>{playbackState === 'playing' ? '⏸ Pause' : '▶ Play'}</button><button onClick={() => { setPlaybackState('stopped'); setCurrentFrame(0); }} style={buttonStyle('#475569')}>⏹ Stop</button><input aria-label="Round" type="range" min="0" max={Math.max(simData.rounds.length - 1, 0)} value={currentFrame} onChange={(event) => setCurrentFrame(Number(event.target.value))} /><span>Round {currentRound?.round ?? 0} / {simData.rounds.length}</span><label>FPS <input aria-label="Frames per second" type="number" min="1" max="30" value={fps} onChange={(event) => setFps(Math.max(1, Math.min(30, Number(event.target.value) || 1)))} /></label></div>
      </div>
      <aside className="status-column">
        <Panel title="Round status">{currentRound ? <><Status label="Attacker zone" value={currentRound.attacker_zone} /><Status label="Tank level" value={`${currentRound.tank_level.toFixed(1)}%`} /><Status label="Compromised" value={String(currentRound.compromised_count)} /><Status label="Alerts" value={String(currentRound.alerts_total)} /><Status label="P(alarm)" value={currentRound.gp_p_alarm.toFixed(3)} /><Status label="P(damage)" value={currentRound.gp_p_damage.toFixed(3)} /></> : <small>No round data supplied.</small>}</Panel>
        <Panel title="🔴 Red action">{currentRound ? <><Status label="Action" value={currentRound.red_action} /><Status label="Target" value={currentRound.red_target} /><small>{currentRound.red_result}</small></> : <small>No actions.</small>}</Panel>
        <Panel title="🔵 Blue action">{currentRound ? <><Status label="Action" value={currentRound.blue_action} /><Status label="Target" value={currentRound.blue_target} /><small>{currentRound.blue_result}</small></> : <small>No actions.</small>}</Panel>
        <Panel title={`Compromised (${compromisedSet.size})`}>{compromisedSet.size ? <div className="chips">{[...compromisedSet].map((id) => <span key={id}>{id}</span>)}</div> : <small>None</small>}</Panel>
        <Panel title="Tank level"><div className="tank"><div className="tank-fill" style={{ height: `${roundedTank}%`, background: roundedTank > 85 || roundedTank < 15 ? '#ef4444' : '#3b82f6' }} /><strong>{currentRound ? `${currentRound.tank_level.toFixed(1)}%` : '—'}</strong></div></Panel>
      </aside>
    </section>
  </main>;
}

function Panel({ title, children }: { title: string; children: ReactNode }) { return <section className="panel"><h2>{title}</h2>{children}</section>; }
function Status({ label, value }: { label: string; value: string }) { return <div className="status-row"><span>{label}</span><b>{value}</b></div>; }
function buttonStyle(background: string): CSSProperties { return { background }; }
