import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '../src/schema.sql');

const ALTER_STATEMENTS = [
    `ALTER TABLE posts ADD COLUMN like_count INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE posts ADD COLUMN dislike_count INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE posts ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL`,
    `ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`,
    `ALTER TABLE boards ADD COLUMN radius_meters INTEGER NOT NULL DEFAULT 1500`,
    `ALTER TABLE boards ADD COLUMN radius_state TEXT`,
    `ALTER TABLE boards ADD COLUMN radius_updated_at INTEGER`,
    `ALTER TABLE boards ADD COLUMN phase_mode TEXT NOT NULL DEFAULT 'default'`,
    `ALTER TABLE boards ADD COLUMN text_only INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE boards ADD COLUMN latitude REAL`,
    `ALTER TABLE boards ADD COLUMN longitude REAL`
];

const isLocal = process.argv.includes('--local');
const dbName = 'board-db'; // Matches wrangler.toml binding

function runCommand(command: string) {
    try {
        execSync(command, { stdio: 'inherit' });
        return true;
    } catch (error) {
        return false;
    }
}

function migrate() {
    console.log(`Migrating ${dbName} (${isLocal ? 'local' : 'remote'})...`);

    // 1. Apply schema.sql
    console.log('Applying schema.sql...');
    const schemaCmd = `npx wrangler d1 execute ${dbName} --file ${SCHEMA_PATH} ${isLocal ? '--local' : ''}`;
    if (!runCommand(schemaCmd)) {
        console.error('Failed to apply schema.sql');
        process.exit(1);
    }

    // 2. Apply ALTER statements
    console.log('Applying ALTER statements...');
    for (const sql of ALTER_STATEMENTS) {
        console.log(`Executing: ${sql}`);
        // Escape double quotes in SQL if any (none in current statements)
        const cmd = `npx wrangler d1 execute ${dbName} --command "${sql}" ${isLocal ? '--local' : ''}`;
        // We ignore errors for ALTER statements as they might already exist
        runCommand(cmd);
    }

    console.log('Migration complete.');
}

migrate();
