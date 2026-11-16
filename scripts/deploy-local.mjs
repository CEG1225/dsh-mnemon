// Deploy this workspace's build output into the DSH profile that loads it.
//
// The profile installs `dsh-mnemon` and its sub-packages from the registry, so a rebuild in this
// checkout changes nothing until the built `lib/` directories are copied over the installed ones.
// That is the whole local-development loop: edit `src/`, `pnpm run build`, then this script, then
// restart DSH Desktop.
//
//   node scripts/deploy-local.mjs            # deploy to the default profile
//   node scripts/deploy-local.mjs --profile desktop
//   node scripts/deploy-local.mjs --dry-run
import { cpSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'

const args = process.argv.slice(2)
const dryRun = args.includes('--dry-run')
const profileFlag = args.indexOf('--profile')
const profile = profileFlag >= 0 ? args[profileFlag + 1] : 'desktop'
const dshHome = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const profileDir = join(dshHome, 'profiles', profile)
const modulesDir = join(profileDir, 'node_modules')
const root = resolve(import.meta.dirname, '..')

if (!existsSync(modulesDir)) {
  console.error(`profile not found: ${modulesDir}`)
  process.exit(1)
}

/** Every package this workspace builds: the root plus one entry per plugins/* directory. */
function packages() {
  const found = [{ name: 'dsh-mnemon', dir: root }]
  for (const entry of readdirSync(join(root, 'plugins'), { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const dir = join(root, 'plugins', entry.name)
    const manifest = join(dir, 'package.json')
    if (!existsSync(manifest)) continue
    found.push({ name: JSON.parse(readFileSync(manifest, 'utf8')).name, dir })
  }
  return found
}

let copied = 0
let missing = 0
for (const pkg of packages()) {
  const from = join(pkg.dir, 'lib')
  const to = join(modulesDir, pkg.name, 'lib')
  if (!existsSync(from)) {
    console.warn(`skip ${pkg.name}: no build output at ${from} (run pnpm run build first)`)
    missing += 1
    continue
  }
  if (!existsSync(join(modulesDir, pkg.name))) {
    console.warn(`skip ${pkg.name}: not installed in ${modulesDir}`)
    missing += 1
    continue
  }
  const files = readdirSync(from).length
  console.log(`${dryRun ? 'would copy' : 'copy'} ${pkg.name}: ${files} files -> ${to}`)
  if (!dryRun) cpSync(from, to, { recursive: true, force: true })
  copied += 1
}

// The installed root package resolves its own version at runtime; keep it in step with the build.
const builtManifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const installedManifest = join(modulesDir, 'dsh-mnemon', 'package.json')
if (existsSync(installedManifest)) {
  const installed = JSON.parse(readFileSync(installedManifest, 'utf8'))
  if (installed.version !== builtManifest.version) {
    console.log(`version: installed ${installed.version} vs built ${builtManifest.version} (left as installed)`)
  }
}

console.log(`\n${dryRun ? 'dry run: ' : ''}${copied} package(s) deployed, ${missing} skipped.`)
console.log('Restart DSH Desktop completely for the new build to load.')
