// tsc writes "use strict" above 'use client'; Next.js wants 'use client' first.
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'dist', 'react');
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
  const p = path.join(dir, f);
  const src = fs.readFileSync(p, 'utf8');
  if (!/^['"]use client['"];?$/m.test(src)) continue;
  fs.writeFileSync(p, `'use client';\n` + src.replace(/^['"]use client['"];?\n/m, ''));
}
