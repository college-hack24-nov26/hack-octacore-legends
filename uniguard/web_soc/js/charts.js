/**
 * UniGuard AI - High-Performance Pure Canvas & SVG SOC Charting Engine
 * 
 * Provides responsive, hardware-accelerated dark cyber visualization without
 * external library dependencies. Supports real-time spline graphs, threat diamond
 * radar, directionality donuts, and SHAP bar visualizers.
 */

class SocCharts {
  constructor() {
    this.trafficHistory = [];
    this.maxHistory = 60;
    this.activeMetric = 'pps'; // 'pps', 'bps', 'active_flows', 'threats'
    
    // Initialize clean baseline with 0 values (no fabricated initial traffic)
    const now = Date.now();
    for (let i = 59; i >= 0; i--) {
      this.trafficHistory.push({
        time: new Date(now - i * 1000),
        pps: 0,
        bps: 0,
        active_flows: 0,
        threats: 0
      });
    }
  }

  pushTelemetry(point) {
    this.trafficHistory.push({
      time: new Date(),
      pps: point.pps || 0,
      bps: (point.pps || 0) * 850,
      active_flows: point.active_flows || 0,
      threats: point.threats_delta || 0
    });
    if (this.trafficHistory.length > this.maxHistory) {
      this.trafficHistory.shift();
    }
  }

  renderTrafficSpline(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth;
    const h = canvas.height = canvas.parentElement.clientHeight || 180;

    ctx.clearRect(0, 0, w, h);

    if (this.trafficHistory.length < 2) return;

    const values = this.trafficHistory.map(d => d[this.activeMetric]);
    const maxVal = Math.max(...values, 10);
    const minVal = 0;

    // Grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const y = (h / 4) * i;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Determine metric color
    let strokeColor = '#00e5ff';
    let gradTop = 'rgba(0, 229, 255, 0.35)';
    if (this.activeMetric === 'threats') {
      strokeColor = '#ef4444';
      gradTop = 'rgba(239, 68, 68, 0.4)';
    } else if (this.activeMetric === 'bps') {
      strokeColor = '#3b82f6';
      gradTop = 'rgba(59, 130, 246, 0.35)';
    } else if (this.activeMetric === 'active_flows') {
      strokeColor = '#a855f7';
      gradTop = 'rgba(168, 85, 247, 0.35)';
    }

    // Calculate curve points
    const stepX = w / (this.trafficHistory.length - 1);
    const points = values.map((val, idx) => {
      const x = idx * stepX;
      const y = h - ((val - minVal) / (maxVal - minVal)) * (h - 20) - 10;
      return { x, y };
    });

    // Draw area fill
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, gradTop);
    grad.addColorStop(1, 'rgba(5, 8, 17, 0.0)');

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      const xc = (points[i - 1].x + points[i].x) / 2;
      const yc = (points[i - 1].y + points[i].y) / 2;
      ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw stroke line
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      const xc = (points[i - 1].x + points[i].x) / 2;
      const yc = (points[i - 1].y + points[i].y) / 2;
      ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.2;
    ctx.shadowColor = strokeColor;
    ctx.shadowBlur = 10;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Current latest point dot
    const latest = points[points.length - 1];
    ctx.fillStyle = '#fff';
    ctx.beginPath();
    ctx.arc(latest.x, latest.y, 4, 0, Math.PI * 2);
    ctx.fill();
  }

  renderDirectionalityDonut(canvasId, stats) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth;
    const h = canvas.height = canvas.parentElement.clientHeight || 180;
    ctx.clearRect(0, 0, w, h);

    const bidi = Number(stats?.bidirectional ?? stats?.BIDIRECTIONAL ?? 0);
    const asym = Number(stats?.asymmetric ?? stats?.ASYMMETRIC ?? 0);
    const strong = Number(stats?.strongly_asymmetric ?? stats?.STRONGLY_ASYMMETRIC ?? 0);
    const oneway = Number(stats?.unidirectional ?? stats?.UNIDIRECTIONAL_OBSERVED ?? 0);

    const data = [
      { label: 'BIDIRECTIONAL', val: bidi, color: '#10b981' },
      { label: 'ASYMMETRIC', val: asym, color: '#f59e0b' },
      { label: 'STRONGLY ASYM', val: strong, color: '#f97316' },
      { label: 'UNIDIRECTIONAL', val: oneway, color: '#a855f7' }
    ];

    const total = bidi + asym + strong + oneway;
    const cx = w * 0.35;
    const cy = h * 0.5;
    const outerR = Math.min(cx, cy) * 0.85;
    const innerR = outerR * 0.65;

    if (total === 0) {
      // Empty state ring
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
      ctx.arc(cx, cy, innerR, Math.PI * 2, 0, true);
      ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.fill();

      ctx.fillStyle = '#fff';
      ctx.font = '700 16px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('0', cx, cy - 6);
      ctx.font = '10px Inter, sans-serif';
      ctx.fillStyle = '#94a3b8';
      ctx.fillText('FLOWS', cx, cy + 10);
    } else {
      let startAngle = -Math.PI / 2;
      for (let item of data) {
        if (item.val <= 0) continue;
        const sliceAngle = (item.val / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.arc(cx, cy, outerR, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, innerR, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = item.color;
        ctx.fill();
        startAngle += sliceAngle;
      }

      ctx.fillStyle = '#fff';
      ctx.font = '700 16px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(`${total.toLocaleString()}`, cx, cy - 6);
      ctx.font = '10px Inter, sans-serif';
      ctx.fillStyle = '#94a3b8';
      ctx.fillText('FLOWS', cx, cy + 10);
    }

    // Legend on right side
    const legX = w * 0.65;
    let legY = cy - 40;
    ctx.textAlign = 'left';
    for (let item of data) {
      ctx.fillStyle = item.color;
      ctx.beginPath();
      ctx.arc(legX, legY, 4, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#cbd5e1';
      ctx.font = '11px Inter, sans-serif';
      const pct = total > 0 ? Math.round((item.val / total) * 100) : 0;
      ctx.fillText(`${item.label} (${pct}%)`, legX + 10, legY + 4);
      legY += 22;
    }
  }

  renderThreatSeverityRadar(canvasId, severities) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth;
    const h = canvas.height = canvas.parentElement.clientHeight || 180;
    ctx.clearRect(0, 0, w, h);

    const c = severities?.critical ?? 0;
    const hi = severities?.high ?? 0;
    const m = severities?.medium ?? 0;
    const l = severities?.low ?? 0;
    const total = c + hi + m + l;

    const axes = [
      { label: 'Critical', count: c, color: '#ef4444' },
      { label: 'High', count: hi, color: '#f97316' },
      { label: 'Medium', count: m, color: '#f59e0b' },
      { label: 'Low', count: l, color: '#00e5ff' }
    ];

    const cx = w * 0.5;
    const cy = h * 0.5;
    const maxR = Math.min(cx, cy) * 0.75;

    // Draw concentric reference diamonds
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 1;
    for (let f of [0.33, 0.66, 1.0]) {
      ctx.beginPath();
      const r = maxR * f;
      ctx.moveTo(cx, cy - r);
      ctx.lineTo(cx + r, cy);
      ctx.lineTo(cx, cy + r);
      ctx.lineTo(cx - r, cy);
      ctx.closePath();
      ctx.stroke();
    }

    // Draw axes
    ctx.beginPath();
    ctx.moveTo(cx, cy - maxR);
    ctx.lineTo(cx, cy + maxR);
    ctx.moveTo(cx - maxR, cy);
    ctx.lineTo(cx + maxR, cy);
    ctx.stroke();

    const maxCount = Math.max(c, hi, m, l, 1);
    const getRadius = (cnt) => total === 0 ? 0 : Math.max(0.15, cnt / maxCount) * maxR;

    const points = [
      { x: cx, y: cy - getRadius(c) }, // Top: Critical
      { x: cx + getRadius(hi), y: cy }, // Right: High
      { x: cx, y: cy + getRadius(m) },  // Bottom: Medium
      { x: cx - getRadius(l), y: cy }   // Left: Low
    ];

    if (total > 0) {
      ctx.beginPath();
      ctx.moveTo(points[0].x, points[0].y);
      for (let i = 1; i < points.length; i++) {
        ctx.lineTo(points[i].x, points[i].y);
      }
      ctx.closePath();
      ctx.fillStyle = 'rgba(239, 68, 68, 0.25)';
      ctx.fill();
      ctx.strokeStyle = '#ef4444';
      ctx.lineWidth = 2;
      ctx.shadowColor = '#ef4444';
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    // Draw axis point markers and labels
    ctx.fillStyle = '#cbd5e1';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(`Critical (${c})`, cx, cy - maxR - 6);
    ctx.fillText(`Medium (${m})`, cx, cy + maxR + 12);
    ctx.textAlign = 'left';
    ctx.fillText(`High (${hi})`, cx + maxR + 6, cy + 3);
    ctx.textAlign = 'right';
    ctx.fillText(`Low (${l})`, cx - maxR - 6, cy + 3);
  }

  renderThreatBreakdownBars(canvasId, threatCounts) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth;
    const h = canvas.height = canvas.parentElement.clientHeight || 180;
    ctx.clearRect(0, 0, w, h);

    const categories = [
      { name: 'Port Scan', count: threatCounts?.['PORT_SCAN'] ?? 0, color: '#f97316' },
      { name: 'SYN Flood', count: threatCounts?.['SYN_FLOOD'] ?? 0, color: '#ef4444' },
      { name: 'UDP Flood', count: threatCounts?.['UDP_FLOOD'] ?? 0, color: '#ef4444' },
      { name: 'Exfiltration', count: threatCounts?.['DATA_EXFILTRATION'] ?? 0, color: '#a855f7' },
      { name: 'Slowloris', count: threatCounts?.['SLOWLORIS'] ?? 0, color: '#f59e0b' },
      { name: 'Anomalous', count: threatCounts?.['ANOMALOUS'] ?? 0, color: '#00e5ff' }
    ];

    const maxCount = Math.max(...categories.map(c => c.count), 1);
    const barWidth = (w - (categories.length + 1) * 14) / categories.length;

    categories.forEach((cat, idx) => {
      const x = 14 + idx * (barWidth + 14);
      const barH = cat.count > 0 ? (cat.count / maxCount) * (h - 40) : 4;
      const y = h - 22 - barH;

      ctx.fillStyle = cat.count > 0 ? cat.color : 'rgba(255, 255, 255, 0.1)';
      if (cat.count > 0) {
        ctx.shadowColor = cat.color;
        ctx.shadowBlur = 6;
      }
      ctx.fillRect(x, y, barWidth, barH);
      ctx.shadowBlur = 0;

      ctx.fillStyle = cat.count > 0 ? '#fff' : '#64748b';
      ctx.font = '600 10px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(cat.count, x + barWidth / 2, y - 5);

      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px Inter, sans-serif';
      ctx.fillText(cat.name.split(' ')[0], x + barWidth / 2, h - 6);
    });
  }
}

window.SocCharts = SocCharts;
