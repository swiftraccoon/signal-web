const esbuild = require('esbuild');
const path = require('path');

const isWatch = process.argv.includes('--watch');
const isDev = isWatch || process.env.NODE_ENV !== 'production';

const buildOptions = {
  entryPoints: [path.join(__dirname, 'client/src/main.js')],
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

async function build() {
  if (isWatch) {
    const ctx = await esbuild.context(buildOptions);
    await ctx.watch();
    console.log('Watching for changes...');
  } else {
    await esbuild.build(buildOptions);
    console.log(`Build complete (${isDev ? 'development' : 'production'}).`);
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
