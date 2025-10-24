import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(process.cwd());
const inputPath = path.join(ROOT, 'docs', 'institutions.json');
const outputPath = path.join(ROOT, 'infra', 'd1', 'migrations', '004_seed_nigeria_boards.sql');

const coordinateMap = {
  abu: { lat: 11.1528, lng: 7.6544 },
  abuja: { lat: 8.9443, lng: 7.0814 },
  bayero: { lat: 12.0463, lng: 8.5246 },
  bauchi: { lat: 10.2829, lng: 9.8430 },
  benin: { lat: 6.4040, lng: 5.6037 },
  calabar: { lat: 4.9508, lng: 8.3220 },
  'fed-dutse': { lat: 12.5152, lng: 9.2937 },
  'fed-dutsinma': { lat: 12.4520, lng: 7.4930 },
  'fed-gashua': { lat: 12.8730, lng: 11.0452 },
  'fed-gusau': { lat: 12.1707, lng: 6.6718 },
  'fed-kashere': { lat: 9.8019, lng: 11.1888 },
  'fed-kebbi': { lat: 12.5884, lng: 4.1995 },
  'fed-lafia': { lat: 8.4889, lng: 8.5356 },
  'fed-lokoja': { lat: 7.7956, lng: 6.7375 },
  aefuna: { lat: 6.4357, lng: 7.5173 },
  'fed-otuoke': { lat: 4.7870, lng: 6.0681 },
  'fed-oye-ekiti': { lat: 7.7953, lng: 5.3235 },
  'fed-wukari': { lat: 7.8617, lng: 9.7778 },
  ibadan: { lat: 7.4415, lng: 3.8873 },
  ilorin: { lat: 8.4799, lng: 4.6746 },
  jos: { lat: 9.8965, lng: 8.8590 },
  lagos: { lat: 6.5159, lng: 3.3890 },
  maiduguri: { lat: 11.8460, lng: 13.1542 },
  makurdi: { lat: 7.7033, lng: 8.5378 },
  naub: { lat: 10.6126, lng: 12.1943 },
  nda: { lat: 10.5506, lng: 7.4383 },
  oau: { lat: 7.5163, lng: 4.5223 }
};

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

const raw = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));

const federalUniversities = raw.filter(item =>
  item.sectionTitle?.toLowerCase().includes('federal universities')
);

const selected = [];
for (const item of federalUniversities) {
  const key = item.abbreviation?.toLowerCase();
  if (!key) continue;
  const coords = coordinateMap[key];
  if (!coords) continue;

  const id = slugify(item.abbreviation);
  const name = item.name?.replace(/\.$/, '') ?? item.abbreviation.toUpperCase();
  const state = item.state ? item.state.trim() : '';
  const address = item.address ? item.address.replace(/\s+/g, ' ').trim() : '';
  const description = [address, state].filter(Boolean).join(', ');

  selected.push({ id, name, description, ...coords });
}

if (!selected.length) {
  console.error('No institutions matched coordinate map.');
  process.exit(1);
}

const header = `-- Seed Nigerian federal universities (generated)
BEGIN TRANSACTION;
`;

const footer = 'COMMIT;\n';

const body = selected
  .map(inst => {
    const description = inst.description ? inst.description.replace(/'/g, "''") : '';
    return `INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('${inst.id}', '${inst.name.replace(/'/g, "''")}', '${description}', strftime('%s','now')*1000, 1500, ${inst.lat}, ${inst.lng})
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;\n`;
  })
  .join('\n');

fs.writeFileSync(outputPath, header + body + footer);
console.log(`Wrote ${selected.length} seed entries to ${outputPath}`);
