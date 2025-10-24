'use client';

import { useEffect, useMemo, useRef } from 'react';
import { MapContainer, TileLayer, Circle, CircleMarker, useMapEvents } from 'react-leaflet';
import type { Map as LeafletMap } from 'leaflet';
import 'leaflet/dist/leaflet.css';

interface BoardLocationPickerProps {
  latitude: number | null;
  longitude: number | null;
  radiusMeters?: number | null;
  onChange: (position: { latitude: number; longitude: number }) => void;
}

const DEFAULT_POSITION = { latitude: 9.082, longitude: 8.6753 }; // Nigeria centroid

function MapClickHandler({ onSelect }: { onSelect: (lat: number, lng: number) => void }) {
  useMapEvents({
    click(event) {
      onSelect(event.latlng.lat, event.latlng.lng);
    }
  });
  return null;
}

export default function BoardLocationPicker({ latitude, longitude, radiusMeters, onChange }: BoardLocationPickerProps) {
  const mapRef = useRef<LeafletMap | null>(null);
  const position = useMemo(() => {
    if (typeof latitude === 'number' && typeof longitude === 'number') {
      return { latitude, longitude };
    }
    return DEFAULT_POSITION;
  }, [latitude, longitude]);

  const effectiveRadius = typeof radiusMeters === 'number' && radiusMeters > 0 ? radiusMeters : 1500;

  useEffect(() => {
    if (!mapRef.current) return;
    mapRef.current.setView([position.latitude, position.longitude]);
  }, [position.latitude, position.longitude]);

  return (
    <div className="overflow-hidden rounded-2xl border border-border/60">
      <MapContainer
        center={[position.latitude, position.longitude]}
        zoom={13}
        scrollWheelZoom={false}
        style={{ height: 260, width: '100%' }}
        className="leaflet-map"
        whenCreated={instance => {
          mapRef.current = instance;
        }}
      >
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" attribution="&copy; OpenStreetMap contributors" />
        <Circle
          center={[position.latitude, position.longitude]}
          radius={effectiveRadius}
          pathOptions={{ color: '#38bdf8', fillColor: '#38bdf8', fillOpacity: 0.2 }}
        />
        <CircleMarker
          center={[position.latitude, position.longitude]}
          radius={6}
          pathOptions={{ color: '#0ea5e9', fillColor: '#0ea5e9', fillOpacity: 1 }}
        />
        <MapClickHandler
          onSelect={(lat, lng) => {
            onChange({ latitude: lat, longitude: lng });
          }}
        />
      </MapContainer>
    </div>
  );
}
