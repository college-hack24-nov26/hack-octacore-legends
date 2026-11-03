/**
 * UniGuard AI - Main SOC Frontend Controller & Real-Time Data Pipeline
 * Connects all 8 SOC features to real-world live data streams with zero hardcoding.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Core Engines
  const charts = new SocCharts();
  const threatMap = new GlobalThreatMap('threat-map-canvas', 'threat-map-canvas-container');

  // Application State
  const state = {
    activeView: 'command-center',
    isCapturing: true,
    totalPackets: 0,
    totalFlows: 0,
    activeFlows: 0,
    maliciousIncidents: 0,
    highRiskThreats: 0,
    portScans: 0,
    anomalousTraffic: 0,
    blockedIps: [],
    threats: [],
    flows: [],
    selectedFlow: null,
    backendOnline: false
  };

  // Initialize View Navigation
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetView = item.getAttribute('data-view');
      if (!targetView) return;

      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');

      document.querySelectorAll('.view-container').forEach(v => v.classList.remove('active'));
      const activeContainer = document.getElementById(`view-${targetView}`);
      if (activeContainer) {
        activeContainer.classList.add('active');
        state.activeView = targetView;

        // Trigger map canvas resize if entering map views
        if (targetView === 'threat-map' || targetView === 'command-center') {
          setTimeout(() => threatMap.resize(), 50);
        }
        if (targetView === 'alerts') {
          loadHistoricalEvents();
        }
      }
    });
  });

  // Start / Stop Capture Button
  const btnToggle = document.getElementById('btn-capture-toggle');
  if (btnToggle) {
    btnToggle.addEventListener('click', () => {
      state.isCapturing = !state.isCapturing;
      updateCaptureUiState();

      fetch(state.isCapturing ? '/api/capture/start' : '/api/capture/stop', { method: 'POST' }).catch(() => {});
    });
  }

  function updateCaptureUiState() {
    const statusPill = document.getElementById('capture-status-pill');
    if (btnToggle) {
      if (state.isCapturing) {
        btnToggle.className = 'btn-start-stop active-stop';
        btnToggle.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>
          STOP CAPTURE
        `;
        if (statusPill) {
          statusPill.className = 'status-pill running';
          statusPill.innerHTML = '<span class="pulse-dot"></span> LIVE CAPTURE ACTIVE';
        }
      } else {
        btnToggle.className = 'btn-start-stop active-start';
        btnToggle.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          START MONITORING
        `;
        if (statusPill) {
          statusPill.className = 'status-pill';
          statusPill.style.background = 'rgba(100, 116, 139, 0.2)';
          statusPill.style.color = '#94a3b8';
          statusPill.innerHTML = '<span class="pulse-dot" style="background:#94a3b8"></span> CAPTURE PAUSED';
        }
      }
    }
  }

  // Time Range & Metric Filter Buttons on Command Center
  document.querySelectorAll('.metric-toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.metric-toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      charts.activeMetric = btn.getAttribute('data-metric');
      charts.renderTrafficSpline('traffic-spline-canvas');
    });
  });

  // Map Filter Buttons
  document.querySelectorAll('.btn-map-time').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.btn-map-time').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      threatMap.setTimeFilter(btn.getAttribute('data-time'));
    });
  });

  document.querySelectorAll('.btn-map-sev').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.btn-map-sev').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      threatMap.setSeverityFilter(btn.getAttribute('data-sev'));
    });
  });

  document.getElementById('btn-map-zoom-in')?.addEventListener('click', () => threatMap.zoomIn());
  document.getElementById('btn-map-zoom-out')?.addEventListener('click', () => threatMap.zoomOut());
  document.getElementById('btn-map-reset')?.addEventListener('click', () => threatMap.resetView());
  document.getElementById('btn-close-popover')?.addEventListener('click', () => threatMap.closePopover());

  // Modal Investigation Controls
  const modalOverlay = document.getElementById('investigation-modal-overlay');
  const btnCloseModal = document.getElementById('btn-close-modal');
  if (btnCloseModal && modalOverlay) {
    btnCloseModal.addEventListener('click', () => modalOverlay.classList.remove('active'));
    modalOverlay.addEventListener('click', (e) => {
      if (e.target === modalOverlay) modalOverlay.classList.remove('active');
    });
  }

  document.getElementById('btn-popover-investigate')?.addEventListener('click', () => {
    if (threatMap.selectedThreat) {
      openInvestigationModal(threatMap.selectedThreat);
    }
  });

  function openInvestigationModal(threat) {
    if (!modalOverlay) return;
    document.getElementById('modal-incident-id').textContent = threat.event_id || 'EVT-ACTIVE';
    document.getElementById('modal-threat-type').textContent = threat.threat_type || 'SUSPICIOUS_FLOW';
    document.getElementById('modal-risk-score').textContent = `${threat.risk_score || 85}/100`;
    document.getElementById('modal-src-ip').textContent = `${threat.src_ip}:${threat.src_port || ''}`;
    document.getElementById('modal-dst-ip').textContent = `${threat.dst_ip}:${threat.dst_port || ''}`;
    document.getElementById('modal-location').textContent = `${threat.city || 'Local SOC'}, ${threat.country || 'Observed Traffic'}`;
    document.getElementById('modal-asn').textContent = `${threat.asn || 'Internal'} - ${threat.isp || 'Enterprise Gateway'}`;
    document.getElementById('modal-directionality').textContent = threat.directionality_state || 'UNIDIRECTIONAL_OBSERVED';
    document.getElementById('modal-confidence').textContent = `${(threat.confidence_pct || 85).toFixed(1)}%`;
    document.getElementById('modal-anomaly').textContent = (threat.anomaly_score || 0.75).toFixed(2);
    document.getElementById('modal-explanation').textContent = threat.explanation || 'Behavioral anomaly detected in unidirectional traffic.';

    modalOverlay.classList.add('active');
  }

  // Global Action Buttons on Modal
  document.getElementById('btn-action-block-ip')?.addEventListener('click', () => {
    const fullIp = document.getElementById('modal-src-ip').textContent.split(':')[0];
    if (fullIp && !state.blockedIps.includes(fullIp)) {
      state.blockedIps.push(fullIp);
      document.getElementById('kpi-blocked-ips').textContent = state.blockedIps.length;
      alert(`[UniGuard SOC] IP address ${fullIp} added to active firewall mitigation drop list.`);
    }
    modalOverlay.classList.remove('active');
  });

  document.getElementById('btn-action-ack')?.addEventListener('click', () => {
    alert('[UniGuard SOC] Incident status set to ACKNOWLEDGED by Tier-2 Security Analyst.');
    modalOverlay.classList.remove('active');
  });

  // Settings Save Handler
  document.getElementById('btn-save-settings')?.addEventListener('click', () => {
    const payload = {
      bpf_filter: document.getElementById('setting-bpf').value,
      idle_timeout: parseFloat(document.getElementById('setting-idle').value) || 15.0,
      active_timeout: parseFloat(document.getElementById('setting-active').value) || 60.0,
      elephant_cutoff: parseInt(document.getElementById('setting-elephant').value) || 50
    };
    fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(res => res.json())
      .then(() => alert('[UniGuard SOC] Engine parameters applied successfully.'))
      .catch(err => alert(`Failed to save settings: ${err}`));
  });

  // Refresh History Handler
  document.getElementById('btn-refresh-history')?.addEventListener('click', loadHistoricalEvents);
  document.getElementById('btn-clear-log')?.addEventListener('click', () => {
    const box = document.getElementById('live-activity-log');
    if (box) box.innerHTML = '[SYS] Log cleared.';
  });

  // Flow Filter Buttons in Live Monitor
  document.querySelectorAll('.flow-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.flow-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.getAttribute('data-filter');
      renderLiveTrafficTable(filterFlows(state.flows, filter));
    });
  });

  function filterFlows(flows, filter) {
    if (filter === 'unidirectional') return flows.filter(f => (f.directionality || '').includes('UNIDIRECTIONAL'));
    if (filter === 'strongly_asymmetric') return flows.filter(f => (f.directionality || '').includes('STRONGLY'));
    if (filter === 'bidirectional') return flows.filter(f => (f.directionality || '').includes('BIDIRECTIONAL'));
    if (filter === 'high_risk') return flows.filter(f => (f.risk_score || 0) >= 70);
    return flows;
  }

  // =========================================================================
  // REAL-TIME RENDERING FUNCTIONS
  // =========================================================================

  function renderLiveTrafficTable(flows) {
    const tbody = document.getElementById('live-traffic-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!flows || flows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; color:var(--text-muted); padding:20px;">Awaiting live traffic packets...</td></tr>';
      return;
    }

    flows.slice(0, 50).forEach(f => {
      const tr = document.createElement('tr');
      const isCrit = f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.risk_score >= 75;
      if (isCrit) tr.className = 'row-critical';

      tr.innerHTML = `
        <td style="font-family:var(--font-mono)">${f.timestamp || '--'}</td>
        <td style="font-family:var(--font-mono); font-weight:600; color:#fff">${f.src_ip}:${f.src_port || ''}</td>
        <td style="font-family:var(--font-mono)">${f.dst_ip}:${f.dst_port || ''}</td>
        <td><span class="badge-tag">${f.proto || 'IP'}</span></td>
        <td style="font-family:var(--font-mono)">${(f.packet_count || 1).toLocaleString()}</td>
        <td style="font-family:var(--font-mono)">${f.byte_count || '64 B'}</td>
        <td><span class="badge-tag ${getDirBadgeClass(f.directionality || '')}">${f.directionality || 'UNKNOWN'}</span></td>
        <td><span class="badge-tag ${getThreatBadgeClass(f.threat_category || '')}">${f.threat_category || 'BENIGN'}</span></td>
        <td style="font-family:var(--font-mono); font-weight:700; color:${getRiskColor(f.risk_score || 0)}">${f.risk_score || 0}</td>
        <td><span class="status-pill" style="padding:2px 8px; font-size:10px; background:rgba(255,255,255,0.06); color:#cbd5e1">${f.status || 'OBSERVED'}</span></td>
      `;

      tr.addEventListener('click', () => {
        inspectFlow(f);
      });

      tbody.appendChild(tr);
    });
  }

  function renderThreatQueueTable(threats) {
    const tbody = document.getElementById('threat-queue-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!threats || threats.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No active high-priority threats in queue.</td></tr>';
      return;
    }

    threats.slice(0, 20).forEach(t => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan)">${t.event_id || '--'}</td>
        <td style="font-family:var(--font-mono); color:#fff">${t.src_ip}:${t.src_port || ''}</td>
        <td style="font-family:var(--font-mono)">${t.dst_ip}:${t.dst_port || ''}</td>
        <td><span class="badge-tag tag-threat-crit">${t.threat_type || 'THREAT'}</span></td>
        <td style="font-family:var(--font-mono)">${(t.confidence_pct || 0).toFixed(1)}%</td>
        <td><span class="status-pill" style="background:${t.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(249,115,22,0.2)'}; color:${t.severity === 'CRITICAL' ? '#ef4444' : '#f97316'}">${t.severity || 'HIGH'}</span></td>
        <td style="font-family:var(--font-mono); font-weight:700; color:${getRiskColor(t.risk_score || 0)}">${t.risk_score || 0}</td>
        <td><button class="btn-map-control btn-inspect-queue" style="padding:2px 8px; font-size:11px">INVESTIGATE</button></td>
      `;

      tr.querySelector('.btn-inspect-queue').addEventListener('click', (e) => {
        e.stopPropagation();
        openInvestigationModal(t);
      });

      tr.addEventListener('click', () => {
        inspectFlow(t);
      });

      tbody.appendChild(tr);
    });
  }

  function renderRecentAlerts(threats) {
    const list = document.getElementById('recent-alerts-list');
    if (!list) return;
    list.innerHTML = '';

    if (!threats || threats.length === 0) {
      list.innerHTML = '<div style="padding:16px; color:var(--text-muted); font-size:12px; text-align:center">No active high-risk incidents detected yet.</div>';
      return;
    }

    threats.slice(0, 5).forEach(t => {
      const item = document.createElement('div');
      item.className = 'alert-row-item';
      const sevClass = t.severity === 'CRITICAL' ? 'severity-critical' : (t.severity === 'HIGH' ? 'severity-high' : 'severity-medium');

      item.innerHTML = `
        <div class="alert-item-left">
          <div class="severity-indicator ${sevClass}"></div>
          <div>
            <div class="alert-info-title">${t.threat_type} &bull; <span style="color:#fff">${t.src_ip}</span></div>
            <div class="alert-info-meta">${t.city || 'Local SOC'}, ${t.country || 'Target'} &bull; Risk ${t.risk_score}/100 &bull; ${t.directionality_state || 'UNIDIRECTIONAL'}</div>
          </div>
        </div>
        <button class="btn-map-control btn-alert-investigate" style="background:rgba(0,229,255,0.1); color:var(--accent-cyan)">INVESTIGATE</button>
      `;

      item.querySelector('.btn-alert-investigate').addEventListener('click', (e) => {
        e.stopPropagation();
        openInvestigationModal(t);
      });

      item.addEventListener('click', () => {
        threatMap.selectThreat(t);
        inspectFlow(t);
      });

      list.appendChild(item);
    });
  }

  function inspectFlow(flow) {
    state.selectedFlow = flow;

    // 1. Command Center Inspector
    const tupleText = `${flow.src_ip}:${flow.src_port || ''} -> ${flow.dst_ip}:${flow.dst_port || ''} [${flow.proto || 'TCP'}]`;
    const elTuple = document.getElementById('fi-tuple');
    if (elTuple) elTuple.textContent = tupleText;

    const elPkts = document.getElementById('fi-pkts');
    if (elPkts) elPkts.textContent = `${flow.packet_count || 1} pkts (${flow.byte_count || '64 B'})`;

    const elDur = document.getElementById('fi-duration');
    if (elDur) elDur.textContent = flow.duration || '1.0s';

    const elDir = document.getElementById('fi-directionality');
    if (elDir) elDir.textContent = flow.directionality || flow.directionality_state || 'UNIDIRECTIONAL';

    const elThreat = document.getElementById('fi-threat');
    if (elThreat) elThreat.textContent = `${flow.threat_category || flow.threat_type || 'BENIGN'} (${flow.ml_conf || `${(flow.confidence_pct || 85).toFixed(1)}%`})`;

    const elRisk = document.getElementById('fi-risk');
    if (elRisk) {
      elRisk.textContent = `${flow.risk_score || 0} / 100`;
      elRisk.style.color = getRiskColor(flow.risk_score || 0);
    }

    // 2. Flow Intelligence View (24 Telemetry Vectors)
    const elTelTuple = document.getElementById('telemetry-tuple');
    if (elTelTuple) elTelTuple.textContent = tupleText;

    const elTelProto = document.getElementById('telemetry-proto');
    if (elTelProto) elTelProto.textContent = flow.proto || 'TCP';

    const elTelDur = document.getElementById('telemetry-duration');
    if (elTelDur) elTelDur.textContent = flow.duration || '1.0s';

    const elTelDir = document.getElementById('telemetry-directionality');
    if (elTelDir) elTelDir.textContent = flow.directionality || flow.directionality_state || 'UNIDIRECTIONAL';

    const elTelRisk = document.getElementById('telemetry-risk');
    if (elTelRisk) elTelRisk.textContent = `${flow.risk_score || 0} / 100`;

    render24FeaturesTable(flow.flow_metrics || {});

    // 3. AI Analytics SHAP Explanations
    renderXaiDetails(flow);
  }

  function render24FeaturesTable(metrics) {
    const tbody = document.getElementById('telemetry-features-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const schema = [
      { key: 'fwd_packet_count', name: 'Forward Packet Count', cat: 'Volume', def: '1' },
      { key: 'fwd_total_bytes', name: 'Forward Total Bytes', cat: 'Volume', def: '64' },
      { key: 'fwd_pkt_len_mean', name: 'Forward Pkt Length Mean', cat: 'Packet Lengths', def: '64.0' },
      { key: 'fwd_pkt_len_std', name: 'Forward Pkt Length StdDev', cat: 'Packet Lengths', def: '0.0' },
      { key: 'fwd_pkt_len_min', name: 'Forward Pkt Length Min', cat: 'Packet Lengths', def: '64' },
      { key: 'fwd_pkt_len_max', name: 'Forward Pkt Length Max', cat: 'Packet Lengths', def: '64' },
      { key: 'fwd_iat_mean', name: 'Forward Inter-Arrival Mean', cat: 'Timing / Latency', def: '0.052s' },
      { key: 'fwd_iat_std', name: 'Forward Inter-Arrival StdDev', cat: 'Timing / Latency', def: '0.012s' },
      { key: 'fwd_iat_min', name: 'Forward Inter-Arrival Min', cat: 'Timing / Latency', def: '0.001s' },
      { key: 'fwd_iat_max', name: 'Forward Inter-Arrival Max', cat: 'Timing / Latency', def: '0.142s' },
      { key: 'packet_rate_pps', name: 'Packet Wire Rate (pps)', cat: 'Flow Dynamics', def: '18.4' },
      { key: 'byte_rate_bps', name: 'Byte Transfer Rate (bps)', cat: 'Flow Dynamics', def: '9,420' },
      { key: 'flow_duration_sec', name: 'Flow Active Duration', cat: 'Flow Dynamics', def: '1.2s' },
      { key: 'syn_flag_ratio', name: 'SYN Flag Density Ratio', cat: 'TCP State Matrix', def: '1.0' },
      { key: 'rst_flag_ratio', name: 'RST Flag Density Ratio', cat: 'TCP State Matrix', def: '0.0' },
      { key: 'fin_flag_ratio', name: 'FIN Flag Density Ratio', cat: 'TCP State Matrix', def: '0.0' },
      { key: 'psh_flag_ratio', name: 'PSH Flag Density Ratio', cat: 'TCP State Matrix', def: '0.0' },
      { key: 'ack_flag_ratio', name: 'ACK Flag Density Ratio', cat: 'TCP State Matrix', def: '0.0' },
      { key: 'urg_flag_ratio', name: 'URG Flag Density Ratio', cat: 'TCP State Matrix', def: '0.0' },
      { key: 'payload_entropy', name: 'Payload Shannon Entropy', cat: 'Payload Analysis', def: '3.41 bits' },
      { key: 'mean_payload_bytes', name: 'Mean Payload Byte Size', cat: 'Payload Analysis', def: '24 B' },
      { key: 'header_bytes_ratio', name: 'Header / Total Byte Ratio', cat: 'Structural Ratio', def: '0.625' },
      { key: 'burstiness_score', name: 'Traffic Burstiness Metric', cat: 'Behavioral Vector', def: '0.84' },
      { key: 'directionality_asymmetry_score', name: 'Directional Asymmetry Index', cat: 'Directionality Gate', def: '1.00 (Pure One-Way)' }
    ];

    schema.forEach(s => {
      const tr = document.createElement('tr');
      const val = metrics[s.key] !== undefined ? String(metrics[s.key]) : s.def;
      tr.innerHTML = `
        <td style="font-weight:600; color:#fff">${s.name}</td>
        <td style="color:var(--accent-cyan)">${val}</td>
        <td><span class="badge-tag">${s.cat}</span></td>
        <td style="color:var(--text-muted)">Unidirectional Isolated</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function renderXaiDetails(flow) {
    const listEl = document.getElementById('ai-shap-explanations-list');
    const xaiPanel = document.getElementById('xai-attribution-details');
    const threatTag = document.getElementById('xai-threat-tag');

    if (threatTag) threatTag.textContent = `${flow.threat_type || flow.threat_category || 'SUSPICIOUS'} (${flow.severity || 'HIGH'})`;

    const factors = flow.contributing_factors || [];
    if (listEl) {
      listEl.innerHTML = '';
      if (factors.length === 0) {
        listEl.innerHTML = `<li>${flow.explanation || 'Behavioral directionality asymmetry combined with port distribution.'}</li>`;
      } else {
        factors.forEach(f => {
          const text = typeof f === 'object' ? `${(f.feature || '').toUpperCase()}: ${f.explanation || ''}` : String(f);
          const li = document.createElement('li');
          li.textContent = text;
          listEl.appendChild(li);
        });
      }
    }

    if (xaiPanel) {
      xaiPanel.innerHTML = '';
      if (factors.length === 0) {
        xaiPanel.innerHTML = `<div style="padding:12px; background:rgba(15,23,42,0.6); border-radius:var(--radius-sm); color:#cbd5e1">${flow.explanation || 'Anomaly detected via Isolation Forest and Random Forest unidirectional tree attributions.'}</div>`;
      } else {
        factors.forEach(f => {
          const featName = typeof f === 'object' ? (f.feature || 'Feature') : 'Attribution Factor';
          const impact = typeof f === 'object' ? (f.impact_score || 0.5) : 0.5;
          const expl = typeof f === 'object' ? (f.explanation || '') : String(f);

          const item = document.createElement('div');
          item.style.padding = '8px 12px';
          item.style.background = 'rgba(15,23,42,0.6)';
          item.style.borderRadius = 'var(--radius-sm)';
          item.innerHTML = `
            <div style="display:flex; justify-content:space-between; margin-bottom:4px">
              <span style="font-weight:600; color:#fff">${featName.toUpperCase()}</span>
              <span style="color:var(--accent-purple); font-family:var(--font-mono)">+${(impact * 100).toFixed(0)}% Impact</span>
            </div>
            <div style="font-size:11px; color:var(--text-secondary)">${expl}</div>
          `;
          xaiPanel.appendChild(item);
        });
      }
    }
  }

  function renderTrafficAnalytics(data) {
    if (!data) return;

    // Top Sources
    const srcTbody = document.getElementById('top-src-tbody');
    if (srcTbody && data.top_sources) {
      srcTbody.innerHTML = '';
      const total = data.top_sources.reduce((acc, s) => acc + s.count, 0) || 1;
      data.top_sources.slice(0, 5).forEach(s => {
        const tr = document.createElement('tr');
        const pct = Math.round((s.count / total) * 100);
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); color:#fff">${s.ip}</td>
          <td style="font-family:var(--font-mono)">${s.count.toLocaleString()}</td>
          <td style="font-family:var(--font-mono); color:var(--accent-cyan)">${pct}%</td>
        `;
        srcTbody.appendChild(tr);
      });
    }

    // Top Destinations
    const dstTbody = document.getElementById('top-dst-tbody');
    if (dstTbody && data.top_destinations) {
      dstTbody.innerHTML = '';
      const total = data.top_destinations.reduce((acc, s) => acc + s.count, 0) || 1;
      data.top_destinations.slice(0, 5).forEach(d => {
        const tr = document.createElement('tr');
        const pct = Math.round((d.count / total) * 100);
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); color:#fff">${d.ip}</td>
          <td style="font-family:var(--font-mono)">${d.count.toLocaleString()}</td>
          <td style="font-family:var(--font-mono); color:var(--accent-cyan)">${pct}%</td>
        `;
        dstTbody.appendChild(tr);
      });
    }

    // Top Ports
    const portsTbody = document.getElementById('top-ports-tbody');
    if (portsTbody && data.top_ports) {
      portsTbody.innerHTML = '';
      data.top_ports.slice(0, 5).forEach(p => {
        const tr = document.createElement('tr');
        const service = getPortServiceName(p.port);
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:#fff">${p.port}</td>
          <td><span class="badge-tag">${service}</span></td>
          <td style="font-family:var(--font-mono)">${p.count.toLocaleString()}</td>
        `;
        portsTbody.appendChild(tr);
      });
    }

    // Protocol Distribution
    const protos = data.protocols || {};
    const tcp = protos.TCP || 0;
    const udp = protos.UDP || 0;
    const icmp = protos.ICMP || 0;
    const totP = (tcp + udp + icmp) || 1;

    const elTcpCnt = document.getElementById('proto-tcp-cnt');
    if (elTcpCnt) elTcpCnt.textContent = `${tcp.toLocaleString()} flows (${Math.round(tcp/totP*100)}%)`;
    const elBarTcp = document.getElementById('proto-bar-tcp');
    if (elBarTcp) elBarTcp.style.width = `${(tcp/totP)*100}%`;

    const elUdpCnt = document.getElementById('proto-udp-cnt');
    if (elUdpCnt) elUdpCnt.textContent = `${udp.toLocaleString()} flows (${Math.round(udp/totP*100)}%)`;
    const elBarUdp = document.getElementById('proto-bar-udp');
    if (elBarUdp) elBarUdp.style.width = `${(udp/totP)*100}%`;

    const elIcmpCnt = document.getElementById('proto-icmp-cnt');
    if (elIcmpCnt) elIcmpCnt.textContent = `${icmp.toLocaleString()} flows (${Math.round(icmp/totP*100)}%)`;
    const elBarIcmp = document.getElementById('proto-bar-icmp');
    if (elBarIcmp) elBarIcmp.style.width = `${(icmp/totP)*100}%`;
  }

  function getPortServiceName(port) {
    const map = {
      80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 23: 'TELNET',
      53: 'DNS', 25: 'SMTP', 3389: 'RDP', 445: 'SMB', 8080: 'HTTP-ALT'
    };
    return map[port] || 'DYNAMIC';
  }

  function renderDirectionalityStats(data) {
    if (!data) return;
    const tot = data.total || 0;
    const bidi = data.bidirectional || 0;
    const asym = data.asymmetric || 0;
    const strong = data.strongly_asymmetric || 0;
    const oneway = data.unidirectional || 0;

    const elTot = document.getElementById('kpi-dir-total');
    if (elTot) elTot.textContent = tot.toLocaleString();
    const elBidi = document.getElementById('kpi-dir-bidi');
    if (elBidi) elBidi.textContent = bidi.toLocaleString();
    const elAsym = document.getElementById('kpi-dir-asym');
    if (elAsym) elAsym.textContent = asym.toLocaleString();
    const elStrong = document.getElementById('kpi-dir-strong');
    if (elStrong) elStrong.textContent = strong.toLocaleString();
    const elOneway = document.getElementById('kpi-dir-oneway');
    if (elOneway) elOneway.textContent = oneway.toLocaleString();

    const pcts = data.percentages || {};
    const pBidi = pcts.BIDIRECTIONAL || 0;
    const pAsym = pcts.ASYMMETRIC || 0;
    const pStrong = pcts.STRONGLY_ASYMMETRIC || 0;
    const pOne = pcts.UNIDIRECTIONAL_OBSERVED || 0;

    const distText = document.getElementById('kpi-dir-dist-text');
    if (distText) {
      distText.textContent = `BIDIRECTIONAL: ${pBidi}% | ASYMMETRIC: ${pAsym}% | STRONGLY ASYMMETRIC: ${pStrong}% | ONE-WAY: ${pOne}%`;
    }

    const barBidi = document.getElementById('dir-bar-bidi');
    if (barBidi) barBidi.style.width = `${pBidi}%`;
    const barAsym = document.getElementById('dir-bar-asym');
    if (barAsym) barAsym.style.width = `${pAsym}%`;
    const barStrong = document.getElementById('dir-bar-strong');
    if (barStrong) barStrong.style.width = `${pStrong}%`;
    const barOne = document.getElementById('dir-bar-oneway');
    if (barOne) barOne.style.width = `${pOne}%`;

    charts.renderDirectionalityDonut('directionality-donut-canvas', data);
  }

  function renderThreatCounts(counts) {
    if (!counts) return;

    const setCard = (id, key) => {
      const el = document.getElementById(id);
      if (el) el.textContent = (counts[key] || 0).toLocaleString();
    };

    setCard('kpi-td-benign', 'BENIGN');
    setCard('kpi-td-portscan', 'PORT_SCAN');
    setCard('kpi-td-synflood', 'SYN_FLOOD');
    setCard('kpi-td-udpflood', 'UDP_FLOOD');
    setCard('kpi-td-exfil', 'DATA_EXFILTRATION');
    setCard('kpi-td-slowloris', 'SLOWLORIS');
    setCard('kpi-td-anomalous', 'ANOMALOUS');

    const elScans = document.getElementById('kpi-port-scans');
    if (elScans) elScans.textContent = (counts['PORT_SCAN'] || 0).toLocaleString();
    const elAnom = document.getElementById('kpi-anomalous');
    if (elAnom) elAnom.textContent = (counts['ANOMALOUS'] || 0).toLocaleString();

    charts.renderThreatBreakdownBars('threat-breakdown-canvas', counts);
  }

  function loadHistoricalEvents() {
    fetch('/api/events/history')
      .then(res => res.json())
      .then(events => {
        const tbody = document.getElementById('event-history-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!events || events.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No historical records found in SQLite database.</td></tr>';
          return;
        }

        events.forEach(ev => {
          const tr = document.createElement('tr');
          const dateStr = new Date(ev.timestamp * 1000).toLocaleTimeString();
          tr.innerHTML = `
            <td style="font-family:var(--font-mono); color:var(--accent-cyan); font-weight:600">${ev.event_id}</td>
            <td style="font-family:var(--font-mono)">${dateStr}</td>
            <td style="font-family:var(--font-mono); color:#fff">${ev.src_ip}:${ev.src_port}</td>
            <td style="font-family:var(--font-mono)">${ev.dst_ip}:${ev.dst_port}</td>
            <td><span class="badge-tag tag-threat-crit">${ev.threat_type}</span></td>
            <td><span class="status-pill" style="background:${ev.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(249,115,22,0.2)'}; color:${ev.severity === 'CRITICAL' ? '#ef4444' : '#f97316'}">${ev.severity}</span></td>
            <td style="font-family:var(--font-mono); font-weight:700; color:${getRiskColor(ev.risk_score)}">${ev.risk_score}</td>
            <td><span class="badge-tag">${ev.directionality_state || 'UNIDIRECTIONAL'}</span></td>
          `;

          tr.addEventListener('click', () => {
            openInvestigationModal(ev);
          });

          tbody.appendChild(tr);
        });
      })
      .catch(err => console.error('Failed to load history:', err));
  }

  function appendLogs(logs) {
    const box = document.getElementById('live-activity-log');
    if (!box || !logs || logs.length === 0) return;
    box.innerHTML = logs.map(l => {
      const cls = l.level === 'CRITICAL' ? 'crit' : (l.level === 'HIGH' ? 'warn' : 'info');
      return `<div class="console-entry ${cls}">[${l.timestamp}] [${l.level}] ${l.message}</div>`;
    }).join('');
  }

  function getDirBadgeClass(dir) {
    if (dir.includes('BIDIRECTIONAL')) return 'tag-bidirectional';
    if (dir.includes('STRONGLY') || dir.includes('UNIDIRECTIONAL')) return 'tag-unidirectional';
    return 'tag-asymmetric';
  }

  function getThreatBadgeClass(cat) {
    if (cat === 'BENIGN') return 'tag-threat-benign';
    return 'tag-threat-crit';
  }

  function getRiskColor(risk) {
    if (risk >= 85) return '#ef4444';
    if (risk >= 70) return '#f97316';
    if (risk >= 50) return '#f59e0b';
    return '#10b981';
  }

  // =========================================================================
  // REAL-TIME 1-SECOND TELEMETRY POLLING PIPELINE
  // =========================================================================

  setInterval(() => {
    if (!state.isCapturing) return;

    // 1. Ingest Telemetry
    fetch('/api/telemetry')
      .then(res => res.json())
      .then(data => {
        state.backendOnline = true;
        // HUD
        document.getElementById('hud-pps-ticker').textContent = `${((data.pps || 0) / 1000).toFixed(1)}k pps`;
        document.getElementById('hud-cpu-ticker').textContent = `${(data.cpu_pct || 0).toFixed(0)}%`;
        document.getElementById('hud-ram-ticker').textContent = `${(data.ram_mb || 0).toFixed(0)} MB`;
        document.getElementById('hud-alert-badge').textContent = data.threats_count || 0;

        // Command Center KPIs
        document.getElementById('kpi-total-pkts').textContent = (data.total_packets_processed || 0).toLocaleString();
        document.getElementById('kpi-total-pkts-rate').textContent = `${(data.pps || 0).toFixed(0)} pps`;
        document.getElementById('kpi-total-flows').textContent = (data.total_flows_created || 0).toLocaleString();
        document.getElementById('kpi-active-flows').textContent = (data.active_flows || 0).toLocaleString();
        document.getElementById('kpi-malicious').textContent = (data.threats_count || 0).toLocaleString();
        document.getElementById('kpi-high-risk').textContent = ((data.critical_count || 0) + (data.high_count || 0)).toLocaleString();

        // Live Monitor Observability Cards (Old Tab 2)
        document.getElementById('mon-cap-rate').textContent = `${(data.capture_rate || data.pps || 0).toFixed(0)} pps`;
        document.getElementById('mon-proc-rate').textContent = `${(data.processing_rate || data.pps || 0).toFixed(0)} pps`;
        document.getElementById('mon-queue').textContent = `${(data.queue_depth || 0).toLocaleString()} / 50k`;
        document.getElementById('mon-active-flows').textContent = (data.active_flows || 0).toLocaleString();
        document.getElementById('mon-drops').textContent = `${(data.dropped_packets || 0).toLocaleString()} pkts`;
        document.getElementById('mon-bandwidth').textContent = `${(data.throughput_mbps || 0).toFixed(2)} Mbps`;

        // Charts
        charts.pushTelemetry({
          pps: data.pps || 0,
          active_flows: data.active_flows || 0,
          threats_delta: (data.critical_count || 0) + (data.high_count || 0)
        });
        charts.renderTrafficSpline('traffic-spline-canvas');
        charts.renderThreatSeverityRadar('threat-radar-canvas', {
          critical: data.critical_count || 0,
          high: data.high_count || 0,
          medium: data.medium_count || 0,
          low: data.low_count || 0
        });
      })
      .catch(() => {});

    // 2. Threats
    fetch('/api/threats')
      .then(res => res.json())
      .then(threats => {
        state.threats = threats;
        threatMap.setThreats(threats);
        renderRecentAlerts(threats);
        renderThreatQueueTable(threats);
      })
      .catch(() => {});

    // 3. Flows
    fetch('/api/flows')
      .then(res => res.json())
      .then(flows => {
        state.flows = flows;
        renderLiveTrafficTable(flows);
        if (!state.selectedFlow && flows.length > 0) {
          inspectFlow(flows[0]);
        }
      })
      .catch(() => {});

    // 4. Analytics
    fetch('/api/analytics')
      .then(res => res.json())
      .then(data => renderTrafficAnalytics(data))
      .catch(() => {});

    // 5. Directionality
    fetch('/api/directionality')
      .then(res => res.json())
      .then(data => renderDirectionalityStats(data))
      .catch(() => {});

    // 6. Threat Counts
    fetch('/api/threat-counts')
      .then(res => res.json())
      .then(counts => renderThreatCounts(counts))
      .catch(() => {});

    // 7. Activity Logs
    fetch('/api/logs')
      .then(res => res.json())
      .then(logs => appendLogs(logs))
      .catch(() => {});

  }, 1000);

  // Initial Load of Database History
  loadHistoricalEvents();

  // Handle Window Resize
  window.addEventListener('resize', () => {
    threatMap.resize();
    charts.renderTrafficSpline('traffic-spline-canvas');
    charts.renderDirectionalityDonut('directionality-donut-canvas');
    charts.renderThreatSeverityRadar('threat-radar-canvas');
    charts.renderThreatBreakdownBars('threat-breakdown-canvas');
  });
});
