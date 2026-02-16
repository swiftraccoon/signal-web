const esbuild = require('esbuild');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const isWatch = process.argv.includes('--watch');
const isDev = isWatch || process.env.NODE_ENV !== 'production';

const buildOptions = {
  entryPoints: [path.join(__dirname, 'client/src/main.ts')],
  bundle: true,
  outfile: path.join(__dirname, 'client/dist/bundle.js'),
  platform: 'browser',
  format: 'iife',
  sourcemap: isDev, // Source maps only in development
  minify: !isDev,
  target: ['es2020'],
  define: {
    'global': 'window',
  },
};

/**
 * Generate SRI (Subresource Integrity) hash for the client bundle and inject
 * it into client/index.html. Only runs for production builds.
 */
function generateSRI() {
  const bundlePath = path.join(__dirname, 'client/dist/bundle.js');
  const htmlPath = path.join(__dirname, 'client/index.html');

  const bundleContents = fs.readFileSync(bundlePath);
  const hash = crypto.createHash('sha384').update(bundleContents).digest('base64');
  const sriHash = `sha384-${hash}`;

  const html = fs.readFileSync(htmlPath, 'utf8');
  const updatedHtml = html.replace(
    /<script src="\/dist\/bundle\.js"><\/script>/,
    `<script src="/dist/bundle.js" integrity="${sriHash}" crossorigin="anonymous"></script>`
  );

  if (updatedHtml === html) {
    console.warn('Warning: SRI injection did not match the expected <script> tag in index.html.');
    return;
  }

  fs.writeFileSync(htmlPath, updatedHtml, 'utf8');
  console.log(`SRI hash: ${sriHash}`);
  console.log(`Injected integrity attribute into ${htmlPath}`);
  console.log('Note: client/index.html has been modified in-place. Run "git checkout client/index.html" to restore the template.');
}

async function build() {
  if (isWatch) {
    const ctx = await esbuild.context(buildOptions);
    await ctx.watch();
    console.log('Watching for changes...');
  } else {
    await esbuild.build(buildOptions);
    console.log(`Build complete (${isDev ? 'development' : 'production'}).`);

    if (!isDev) {
      generateSRI();
    }
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
