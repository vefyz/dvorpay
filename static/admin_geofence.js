/**
 * Карта геозоны NFC-оплаты в админ-панели (Leaflet + Leaflet.draw).
 */
(function () {
  const mapEl = document.getElementById('geofence-map');
  if (!mapEl || typeof L === 'undefined') return;

  const geofence = window.GEOFENCE_DATA || {};
  const form = document.getElementById('geofence-form');
  const modeInput = document.getElementById('gf-mode');
  const centerLatInput = document.getElementById('gf-center-lat');
  const centerLonInput = document.getElementById('gf-center-lon');
  const radiusInput = document.getElementById('gf-radius');
  const polygonInput = document.getElementById('gf-polygon-json');
  const statusEl = document.getElementById('geofence-status');

  const startLat = geofence.center_lat || 55.751244;
  const startLng = geofence.center_lon || 37.618423;

  const map = L.map('geofence-map', { zoomControl: true }).setView([startLat, startLng], 17);

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap',
    maxZoom: 19,
  }).addTo(map);

  const drawnItems = new L.FeatureGroup();
  map.addLayer(drawnItems);

  const drawControl = new L.Control.Draw({
    draw: {
      polygon: {
        allowIntersection: false,
        showArea: true,
        shapeOptions: { color: '#22c55e', fillColor: '#22c55e', fillOpacity: 0.25 },
      },
      circle: {
        shapeOptions: { color: '#22c55e', fillColor: '#22c55e', fillOpacity: 0.25 },
      },
      rectangle: false,
      polyline: false,
      marker: false,
      circlemarker: false,
    },
    edit: { featureGroup: drawnItems, remove: true },
  });
  map.addControl(drawControl);

  function latLngsToArray(latlngs) {
    return latlngs.map((p) => [p.lat, p.lng]);
  }

  function syncFromLayer(layer) {
    if (layer instanceof L.Circle) {
      const c = layer.getLatLng();
      modeInput.value = 'circle';
      centerLatInput.value = c.lat.toFixed(7);
      centerLonInput.value = c.lng.toFixed(7);
      radiusInput.value = layer.getRadius().toFixed(1);
      polygonInput.value = '[]';
      if (statusEl) {
        statusEl.textContent = `Круг: радиус ${Math.round(layer.getRadius())} м`;
      }
      return;
    }
    if (layer instanceof L.Polygon) {
      const latlngs = layer.getLatLngs()[0];
      const pts = latLngsToArray(latlngs);
      const center = layer.getBounds().getCenter();
      modeInput.value = 'polygon';
      centerLatInput.value = center.lat.toFixed(7);
      centerLonInput.value = center.lng.toFixed(7);
      radiusInput.value = '100';
      polygonInput.value = JSON.stringify(pts);
      if (statusEl) {
        statusEl.textContent = `Полигон: ${pts.length} точек`;
      }
    }
  }

  function loadExisting() {
    drawnItems.clearLayers();
    if (geofence.mode === 'polygon' && geofence.polygon && geofence.polygon.length >= 3) {
      const poly = L.polygon(
        geofence.polygon.map((p) => [p[0], p[1]]),
        { color: '#22c55e', fillColor: '#22c55e', fillOpacity: 0.25 },
      );
      drawnItems.addLayer(poly);
      map.fitBounds(poly.getBounds(), { padding: [30, 30] });
      syncFromLayer(poly);
      return;
    }
    const circle = L.circle([startLat, startLng], {
      radius: geofence.radius_meters || 100,
      color: '#22c55e',
      fillColor: '#22c55e',
      fillOpacity: 0.25,
    });
    drawnItems.addLayer(circle);
    modeInput.value = 'circle';
    centerLatInput.value = startLat.toFixed(7);
    centerLonInput.value = startLng.toFixed(7);
    radiusInput.value = String(geofence.radius_meters || 100);
    polygonInput.value = '[]';
    if (statusEl) statusEl.textContent = `Круг: радиус ${geofence.radius_meters || 100} м`;
  }

  map.on(L.Draw.Event.CREATED, (e) => {
    drawnItems.clearLayers();
    drawnItems.addLayer(e.layer);
    syncFromLayer(e.layer);
  });

  map.on(L.Draw.Event.EDITED, (e) => {
    e.layers.eachLayer((layer) => syncFromLayer(layer));
  });

  map.on(L.Draw.Event.DELETED, () => {
    if (statusEl) statusEl.textContent = 'Зона удалена. Нарисуйте новую.';
    modeInput.value = 'circle';
    polygonInput.value = '[]';
  });

  document.getElementById('geofence-locate')?.addEventListener('click', () => {
    if (!navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition((pos) => {
      map.setView([pos.coords.latitude, pos.coords.longitude], 18);
    });
  });

  form?.addEventListener('submit', (e) => {
    if (drawnItems.getLayers().length === 0) {
      e.preventDefault();
      alert('Сначала нарисуйте или отредактируйте зону на карте.');
      return;
    }
    const layer = drawnItems.getLayers()[0];
    syncFromLayer(layer);
    if (modeInput.value === 'polygon') {
      const pts = JSON.parse(polygonInput.value || '[]');
      if (pts.length < 3) {
        e.preventDefault();
        alert('Полигон должен иметь минимум 3 точки.');
      }
    }
  });

  loadExisting();
  setTimeout(() => map.invalidateSize(), 200);
})();
