// Creates a transactionally consistent SQLite snapshot while NexPOS is running.
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const destination = process.argv[2];
if (!destination) {
    console.error('Usage: node backup-sqlite.js <destination.db>');
    process.exit(1);
}

const db = new DatabaseSync(path.join(__dirname, 'nexpos.db'));
const target = path.resolve(destination).replace(/\\/g, '/').replace(/'/g, "''");
try {
    db.exec(`VACUUM INTO '${target}'`);
    console.log(`SQLite snapshot dibuat: ${target}`);
} finally {
    db.close();
}
