/**
 * UniGuard AI - Real-World Global Threat Map Engine
 * 
 * Accurately plots IP network endpoints and geographically resolved coordinates
 * (latitude/longitude) on an interactive dark cyber world map.
 * Renders glowing pulsating threat markers, animated Bezier attack arcs,
 * and comprehensive SOC threat intelligence popover cards.
 */

class GlobalThreatMap {
  constructor(canvasId, containerId) {
    this.canvas = document.getElementById(canvasId);
    this.container = document.getElementById(containerId);
    this.ctx = this.canvas.getContext('2d');

    // Pan and zoom camera state
    this.zoom = 1.0;
    this.minZoom = 0.8;
    this.maxZoom = 4.0;
    this.panX = 0;
    this.panY = 0;
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;

    // Active threats collection: array of threat objects with coordinates
    this.threats = [];
    this.hoveredMarker = null;
    this.selectedThreat = null;

    // Filter states
    this.timeFilter = 'live'; // 'live', '1h', '24h'
    this.severityFilter = 'all'; // 'all', 'high_critical', 'critical_only'

    // Local Enterprise SOC / Honeypot Gateway coordinates (Target Endpoint)
    this.localSocEndpoint = {
      latitude: 28.6139,
      longitude: 77.2090,
      label: 'Local SOC Gateway (India)',
      ip: '192.168.1.1'
    };

    // Animation loop timer
    this.animTime = 0;
    this.initWorldData();
    this.initEvents();
    this.resize();
    this.startAnimationLoop();
  }

  resize() {
    if (!this.container || !this.canvas) return;
    const rect = this.container.getBoundingClientRect();
    this.width = rect.width;
    this.height = rect.height;

    // Support Retina/HiDPI screens
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.canvas.style.width = `${this.width}px`;
    this.canvas.style.height = `${this.height}px`;
    this.ctx.scale(dpr, dpr);

    this.draw();
  }

  initWorldData() {
    // Simplified high-fidelity multi-polygon landmass approximations
    // in longitude (-180 to 180) and latitude (-90 to 90) coordinates
    this.continents = [
      // North America
      [
        [-168, 65], [-160, 71], [-130, 70], [-85, 75], [-60, 60], [-55, 48],
        [-65, 44], [-75, 38], [-80, 25], [-97, 26], [-90, 20], [-82, 9],
        [-78, 8], [-85, 14], [-105, 20], [-115, 30], [-124, 40], [-125, 49],
        [-135, 58], [-165, 60], [-168, 65]
      ],
      // South America
      [
        [-78, 8], [-72, 11], [-60, 8], [-50, -1], [-35, -5], [-35, -12],
        [-40, -22], [-48, -28], [-58, -38], [-65, -52], [-74, -53], [-75, -45],
        [-70, -30], [-80, -5], [-78, 8]
      ],
      // Europe
      [
        [-10, 36], [0, 43], [5, 43], [15, 40], [25, 36], [28, 41], [30, 47],
        [40, 55], [30, 60], [25, 70], [15, 68], [5, 62], [-5, 58], [-5, 48],
        [-9, 42], [-10, 36]
      ],
      // Asia
      [
        [30, 60], [50, 55], [60, 40], [55, 25], [60, 22], [70, 22], [78, 8],
        [85, 20], [92, 16], [100, 5], [105, 10], [108, 20], [120, 23], [122, 30],
        [128, 40], [140, 48], [142, 54], [170, 65], [180, 70], [140, 75],
        [100, 77], [75, 72], [50, 70], [30, 60]
      ],
      // Africa
      [
        [-5, 36], [10, 37], [25, 32], [32, 31], [35, 27], [43, 12], [51, 11],
        [45, 0], [40, -12], [35, -24], [32, -30], [25, -34], [18, -34],
        [12, -18], [9, -5], [3, 5], [-15, 12], [-17, 15], [-12, 28], [-5, 36]
      ],
      // Australia
      [
        [114, -22], [122, -16], [130, -12], [136, -12], [142, -10], [146, -14],
        [152, -24], [153, -30], [150, -37], [143, -39], [135, -35], [120, -35],
        [115, -32], [113, -25], [114, -22]
      ],
      // Greenland
      [
        [-45, 60], [-35, 66], [-20, 75], [-20, 82], [-60, 83], [-55, 75], [-45, 60]
      ],
      // Japan Islands
      [
        [130, 31], [133, 34], [140, 36], [142, 44], [140, 45], [137, 39], [130, 31]
      ],
      // United Kingdom & Ireland
      [
        [-10, 52], [-6, 55], [-3, 58], [-1, 52], [-5, 50], [-10, 52]
      ]
    ];
  }

  /**
   * Projects Latitude and Longitude to 2D Canvas space using Miller cylindrical projection
   */
  geoToPixel(lat, lon) {
    // Equirectangular / Miller approximation
    const x = ((lon + 180) / 360) * this.width;
    // Map latitude (-90 to 90) smoothly
    const y = ((90 - lat) / 180) * this.height;

    // Apply camera pan & zoom
    const cx = this.width / 2;
    const cy = this.height / 2;
    const px = (x - cx) * this.zoom + cx + this.panX;
    const py = (y - cy) * this.zoom + cy + this.panY;

    return { x: px, y: py };
  }

  pixelToGeo(px, py) {
    const cx = this.width / 2;
    const cy = this.height / 2;
    const x = (px - cx - this.panX) / this.zoom + cx;
    const y = (py - cy - this.panY) / this.zoom + cy;

    const lon = (x / this.width) * 360 - 180;
    const lat = 90 - (y / this.height) * 180;
    return { lat, lon };
  }

  initEvents() {
    this.canvas.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.dragStartX = e.clientX - this.panX;
      this.dragStartY = e.clientY - this.panY;
    });

    window.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        this.panX = e.clientX - this.dragStartX;
        this.panY = e.clientY - this.dragStartY;
        this.draw();
      } else {
        this.checkHover(e);
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.88;
      const newZoom = Math.min(Math.max(this.zoom * zoomFactor, this.minZoom), this.maxZoom);

      // Zoom towards mouse pointer
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      this.panX = mouseX - (mouseX - this.panX) * (newZoom / this.zoom);
      this.panY = mouseY - (mouseY - this.panY) * (newZoom / this.zoom);
      this.zoom = newZoom;

      this.draw();
    }, { passive: false });

    this.canvas.addEventListener('click', (e) => {
      if (this.hoveredMarker) {
        this.selectThreat(this.hoveredMarker);
      } else {
        this.closePopover();
      }
    });
  }

  checkHover(e) {
    const rect = this.canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    let found = null;
    const visibleThreats = this.getVisibleThreats();

    for (let t of visibleThreats) {
      const pt = this.geoToPixel(t.latitude, t.longitude);
      const dist = Math.hypot(mouseX - pt.x, mouseY - pt.y);
      if (dist <= 14 * this.zoom) {
        found = t;
        break;
      }
    }

    if (found !== this.hoveredMarker) {
      this.hoveredMarker = found;
      this.canvas.style.cursor = found ? 'pointer' : 'default';
      this.draw();
    }
  }

  addThreat(threat) {
    // Avoid duplicate IPs stacking forever, keep top 100 recent
    const existingIdx = this.threats.findIndex(t => t.src_ip === threat.src_ip && t.threat_type === threat.threat_type);
    if (existingIdx !== -1) {
      this.threats[existingIdx] = { ...this.threats[existingIdx], ...threat, timestamp: threat.timestamp || Date.now() / 1000 };
    } else {
      this.threats.unshift({
        ...threat,
        timestamp: threat.timestamp || Date.now() / 1000,
        arcProgress: Math.random() // randomized start for attack pulse
      });
    }

    if (this.threats.length > 100) {
      this.threats.pop();
    }

    this.draw();
  }

  setThreats(threatList) {
    this.threats = threatList.map(t => ({
      ...t,
      arcProgress: Math.random()
    }));
    this.draw();
  }

  getVisibleThreats() {
    const now = Date.now() / 1000;
    return this.threats.filter(t => {
      // Time filter
      if (this.timeFilter === '1h' && (now - t.timestamp) > 3600) return false;
      if (this.timeFilter === '24h' && (now - t.timestamp) > 86400) return false;

      // Severity filter
      if (this.severityFilter === 'critical_only' && t.severity !== 'CRITICAL') return false;
      if (this.severityFilter === 'high_critical' && t.severity !== 'CRITICAL' && t.severity !== 'HIGH') return false;

      return true;
    });
  }

  getSeverityColor(severity) {
    switch ((severity || '').toUpperCase()) {
      case 'CRITICAL': return '#ef4444'; // Red
      case 'HIGH': return '#f97316';     // Orange-Red
      case 'MEDIUM': return '#f59e0b';   // Amber
      case 'LOW': return '#00e5ff';      // Cyan
      case 'BENIGN': return '#10b981';   // Green
      default: return '#3b82f6';         // Blue
    }
  }

  startAnimationLoop() {
    const loop = () => {
      this.animTime += 0.02;
      this.draw();
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  draw() {
    if (!this.ctx || !this.width || !this.height) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    // 1. Draw Subtle Geo Grid lines
    this.drawGeoGrid(ctx);

    // 2. Draw World Continents
    this.drawContinents(ctx);

    // 3. Draw Local SOC Headquarters Target Node
    this.drawLocalSocNode(ctx);

    // 4. Draw Animated Attack Arcs & Particle Pulses
    const visibleThreats = this.getVisibleThreats();
    for (let t of visibleThreats) {
      this.drawAttackArc(ctx, t);
    }

    // 5. Draw Geographically Placed Threat Markers
    for (let t of visibleThreats) {
      this.drawThreatMarker(ctx, t);
    }
  }

  drawGeoGrid(ctx) {
    ctx.save();
    ctx.strokeStyle = 'rgba(30, 45, 75, 0.25)';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 4]);

    // Draw longitude lines every 30 deg
    for (let lon = -180; lon <= 180; lon += 30) {
      const top = this.geoToPixel(85, lon);
      const bottom = this.geoToPixel(-85, lon);
      ctx.beginPath();
      ctx.moveTo(top.x, top.y);
      ctx.lineTo(bottom.x, bottom.y);
      ctx.stroke();
    }

    // Draw latitude lines every 30 deg
    for (let lat = -60; lat <= 60; lat += 30) {
      const left = this.geoToPixel(lat, -180);
      const right = this.geoToPixel(lat, 180);
      ctx.beginPath();
      ctx.moveTo(left.x, left.y);
      ctx.lineTo(right.x, right.y);
      ctx.stroke();
    }

    // Equator highlight
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.15)';
    ctx.setLineDash([]);
    const eqLeft = this.geoToPixel(0, -180);
    const eqRight = this.geoToPixel(0, 180);
    ctx.beginPath();
    ctx.moveTo(eqLeft.x, eqLeft.y);
    ctx.lineTo(eqRight.x, eqRight.y);
    ctx.stroke();

    ctx.restore();
  }

  drawContinents(ctx) {
    ctx.save();
    ctx.fillStyle = '#0f1b33';
    ctx.strokeStyle = '#1e3357';
    ctx.lineWidth = 1.2 * Math.min(1.5, this.zoom);

    for (let poly of this.continents) {
      ctx.beginPath();
      for (let i = 0; i < poly.length; i++) {
        const pt = this.geoToPixel(poly[i][1], poly[i][0]);
        if (i === 0) ctx.moveTo(pt.x, pt.y);
        else ctx.lineTo(pt.x, pt.y);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
    ctx.restore();
  }

  drawLocalSocNode(ctx) {
    const pt = this.geoToPixel(this.localSocEndpoint.latitude, this.localSocEndpoint.longitude);

    ctx.save();
    // Glowing cyan base
    ctx.shadowColor = '#00e5ff';
    ctx.shadowBlur = 15;
    ctx.fillStyle = '#00e5ff';
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, 5 * Math.sqrt(this.zoom), 0, Math.PI * 2);
    ctx.fill();

    // Subtle radar pulse ring
    const pulse = (this.animTime % 2) / 2;
    ctx.strokeStyle = `rgba(0, 229, 255, ${1 - pulse})`;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, (8 + pulse * 20) * this.zoom, 0, Math.PI * 2);
    ctx.stroke();

    // Target Label
    ctx.fillStyle = '#94a3b8';
    ctx.font = `600 ${Math.max(10, 11 * this.zoom)}px Inter, sans-serif`;
    ctx.fillText('UniGuard SOC Gateway', pt.x + 10, pt.y + 4);

    ctx.restore();
  }

  drawAttackArc(ctx, threat) {
    const src = this.geoToPixel(threat.latitude, threat.longitude);
    const dst = this.geoToPixel(this.localSocEndpoint.latitude, this.localSocEndpoint.longitude);

    // Calculate curved Bezier midpoint elevated towards the poles
    const dx = dst.x - src.x;
    const dy = dst.y - src.y;
    const dist = Math.hypot(dx, dy);

    // Control point arching upwards
    const midX = (src.x + dst.x) / 2;
    const midY = (src.y + dst.y) / 2 - Math.min(120 * this.zoom, dist * 0.35);

    const color = this.getSeverityColor(threat.severity);

    ctx.save();
    // 1. Arc line
    ctx.strokeStyle = color;
    ctx.globalAlpha = threat.severity === 'CRITICAL' || threat.severity === 'HIGH' ? 0.45 : 0.25;
    ctx.lineWidth = threat.severity === 'CRITICAL' ? 2 : 1.2;
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.quadraticCurveTo(midX, midY, dst.x, dst.y);
    ctx.stroke();

    // 2. Animated light particle along curve
    threat.arcProgress = ((threat.arcProgress || 0) + 0.008) % 1.0;
    const t = threat.arcProgress;
    // Quadratic Bezier formulation: B(t) = (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
    const px = (1 - t) * (1 - t) * src.x + 2 * (1 - t) * t * midX + t * t * dst.x;
    const py = (1 - t) * (1 - t) * src.y + 2 * (1 - t) * t * midY + t * t * dst.y;

    ctx.globalAlpha = 0.95;
    ctx.shadowColor = color;
    ctx.shadowBlur = 10;
    ctx.fillStyle = '#ffffff';
    ctx.beginPath();
    ctx.arc(px, py, 2.5 * Math.sqrt(this.zoom), 0, Math.PI * 2);
    ctx.fill();

    ctx.restore();
  }

  drawThreatMarker(ctx, threat) {
    const pt = this.geoToPixel(threat.latitude, threat.longitude);
    const color = this.getSeverityColor(threat.severity);
    const isHovered = this.hoveredMarker && this.hoveredMarker.src_ip === threat.src_ip;
    const isSelected = this.selectedThreat && this.selectedThreat.src_ip === threat.src_ip;
    const isHighOrCrit = threat.severity === 'CRITICAL' || threat.severity === 'HIGH';

    ctx.save();

    // 1. Pulsating glow for High/Critical threats
    if (isHighOrCrit || isHovered || isSelected) {
      const pulsePhase = (this.animTime * 1.5 + (threat.latitude % 3)) % 1;
      ctx.strokeStyle = color;
      ctx.lineWidth = isSelected ? 2.5 : 1.5;
      ctx.globalAlpha = Math.max(0, 1 - pulsePhase);
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, (8 + pulsePhase * 18) * Math.sqrt(this.zoom), 0, Math.PI * 2);
      ctx.stroke();
    }

    // 2. Outer Halo
    ctx.shadowColor = color;
    ctx.shadowBlur = isHovered || isSelected ? 20 : 12;
    ctx.globalAlpha = 0.9;
    ctx.fillStyle = color;
    const markerRadius = (isHovered || isSelected ? 7 : (isHighOrCrit ? 5.5 : 4)) * Math.sqrt(this.zoom);
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, markerRadius, 0, Math.PI * 2);
    ctx.fill();

    // 3. Inner White Core
    ctx.fillStyle = '#ffffff';
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, markerRadius * 0.45, 0, Math.PI * 2);
    ctx.fill();

    // 4. On-map label for active/hovered threats
    if (isHovered || isSelected || isHighOrCrit) {
      ctx.globalAlpha = 1.0;
      ctx.shadowBlur = 0;
      ctx.font = `600 ${Math.max(9, 10 * this.zoom)}px Inter, sans-serif`;
      ctx.fillStyle = '#e2e8f0';
      ctx.fillText(`${threat.src_ip} (${threat.country_code || 'EXT'})`, pt.x + markerRadius + 5, pt.y + 3);
    }

    ctx.restore();
  }

  selectThreat(threat) {
    this.selectedThreat = threat;
    this.showPopover(threat);
  }

  showPopover(threat) {
    const popover = document.getElementById('map-threat-popover');
    if (!popover) return;

    const color = this.getSeverityColor(threat.severity);
    const badge = popover.querySelector('.popover-badge');
    badge.textContent = threat.severity || 'HIGH RISK';
    badge.style.backgroundColor = `${color}25`;
    badge.style.color = color;
    badge.style.border = `1px solid ${color}60`;

    popover.querySelector('.popover-ip-title').textContent = threat.src_ip;
    popover.querySelector('#pop-threat-cat').textContent = threat.threat_type || 'UNKNOWN';
    popover.querySelector('#pop-location').textContent = `${threat.city || 'Unknown'}, ${threat.country || 'External'}`;
    popover.querySelector('#pop-coords').textContent = `${threat.latitude.toFixed(4)}°, ${threat.longitude.toFixed(4)}°`;
    popover.querySelector('#pop-asn').textContent = threat.asn || 'AS Unknown';
    popover.querySelector('#pop-isp').textContent = threat.isp || 'Telecom / Hosting Provider';
    popover.querySelector('#pop-directionality').textContent = threat.directionality_state || 'UNIDIRECTIONAL_OBSERVED';
    popover.querySelector('#pop-confidence').textContent = `${(threat.confidence_pct || 85.0).toFixed(1)}%`;
    popover.querySelector('#pop-risk').textContent = `${threat.risk_score || 85}/100`;

    popover.style.display = 'block';
  }

  closePopover() {
    const popover = document.getElementById('map-threat-popover');
    if (popover) popover.style.display = 'none';
    this.selectedThreat = null;
    this.draw();
  }

  // Controls API
  zoomIn() {
    this.zoom = Math.min(this.zoom * 1.3, this.maxZoom);
    this.draw();
  }

  zoomOut() {
    this.zoom = Math.max(this.zoom * 0.75, this.minZoom);
    this.draw();
  }

  resetView() {
    this.zoom = 1.0;
    this.panX = 0;
    this.panY = 0;
    this.draw();
  }

  setTimeFilter(filter) {
    this.timeFilter = filter;
    this.draw();
  }

  setSeverityFilter(filter) {
    this.severityFilter = filter;
    this.draw();
  }
}

window.GlobalThreatMap = GlobalThreatMap;
