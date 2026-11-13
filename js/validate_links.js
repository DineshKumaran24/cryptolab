import fs from 'node:fs';
import path from 'node:path';

const htmlFiles = fs.readdirSync('.').filter(f => f.endsWith('.html'));
console.log(`Found ${htmlFiles.length} HTML files to validate:`, htmlFiles);

let errors = 0;

for (const file of htmlFiles) {
  const content = fs.readFileSync(file, 'utf8');
  // Check href and src
  const hrefRegex = /href="([^"#:]+)(#[^"]*)?"/g;
  const srcRegex = /src="([^":]+)"/g;

  let match;
  while ((match = hrefRegex.exec(content)) !== null) {
    const target = match[1];
    if (target.startsWith('http') || target.startsWith('data:')) continue;
    if (!fs.existsSync(target)) {
      console.error(`✗ Dead link in ${file}: href="${target}" does not exist`);
      errors++;
    }
  }

  while ((match = srcRegex.exec(content)) !== null) {
    const target = match[1];
    if (target.startsWith('http') || target.startsWith('data:')) continue;
    if (!fs.existsSync(target)) {
      console.error(`✗ Missing asset in ${file}: src="${target}" does not exist`);
      errors++;
    }
  }
}

console.log(`\nLink Validation Completed. Total Dead Links/Missing Assets: ${errors}`);
if (errors > 0) process.exit(1);
