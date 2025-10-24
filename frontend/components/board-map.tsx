'use client';

import { useMemo } from 'react';
import { MapContainer, TileLayer, Circle } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

interface BoardMapProps {
  latitude: number;
  longitude: number;
  radiusMeters?: number | null;
}

export default function BoardMap({ latitude, longitude, radiusMeters }: BoardMapProps) {
  const position = useMemo(() => [latitude, longitude] as [number, number], [latitude, longitude]);
  const circleRadius = typeof radiusMeters === 'number' && !Number.isNaN(radiusMeters) ? radiusMeters : 1500;

  return (
    <div className="overflow-hidden rounded-2xl border border-border/60">
      <MapContainer
        center={position}
        zoom={13}
        scrollWheelZoom={false}
        style={{ height: 260, width: '100%' }}
        className="leaflet-map"
      >
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" attribution="&copy; OpenStreetMap contributors" />
        <Circle
          center={position}
          radius={circleRadius}
          pathOptions={{ color: '#38bdf8', fillColor: '#38bdf8', fillOpacity: 0.2 }}
        />
      </MapContainer>
    </div>
  );
}
