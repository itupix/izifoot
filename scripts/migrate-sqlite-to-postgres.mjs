import 'dotenv/config'
import path from 'node:path'
import { existsSync } from 'node:fs'
import Database from 'better-sqlite3'
import pg from 'pg'

const { Client } = pg

const TABLE_ORDER = [
  'User',
  'Planning',
  'ShareToken',
  'Player',
  'Training',
  'Plateau',
  'Attendance',
  'Match',
  'MatchTeam',
  'Scorer',
  'MatchTeamPlayer',
  'TrainingDrill',
  'Diagram',
]

function quoteIdent(identifier) {
  return `"${String(identifier).replace(/"/g, '""')}"`
}

function resolveSqliteFile(sqliteUrl) {
  if (!sqliteUrl?.startsWith('file:')) return null
  const raw = sqliteUrl.slice('file:'.length)
  if (!raw) return null

  if (raw.startsWith('/')) return raw
  if (raw.startsWith('./') || raw.startsWith('../')) return path.resolve(process.cwd(), 'prisma', raw)
  return path.resolve(process.cwd(), raw)
}

function isPostgresUrl(url) {
  return typeof url === 'string' && (url.startsWith('postgres://') || url.startsWith('postgresql://'))
}

function pickUrls() {
  const databaseUrl = process.env.DATABASE_URL
  const sqliteFromEnv = process.env.SQLITE_DATABASE_URL
  const pgFromEnv = process.env.POSTGRES_DATABASE_URL

  const sqliteUrl = sqliteFromEnv || (databaseUrl?.startsWith('file:') ? databaseUrl : null)
  const pgUrl = pgFromEnv || (isPostgresUrl(databaseUrl) ? databaseUrl : null)

  if (!sqliteUrl) {
    throw new Error('Missing SQLite URL. Set SQLITE_DATABASE_URL (ex: file:./dev.db).')
  }
  if (!pgUrl) {
    throw new Error('Missing PostgreSQL URL. Set POSTGRES_DATABASE_URL (or DATABASE_URL if it is postgresql://...).')
  }

  return { sqliteUrl, pgUrl }
}

async function loadPostgresColumns(client) {
  const res = await client.query(`
    SELECT table_name, column_name, udt_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
  `)
  const map = new Map()
  for (const row of res.rows) {
    const key = `${row.table_name}.${row.column_name}`
    map.set(key, row.udt_name)
  }
  return map
}

function normalizeValue(value, udtName) {
  if (value === null || value === undefined) return null
  if (udtName === 'bool') {
    if (typeof value === 'number') return value !== 0
    if (typeof value === 'string') return value === '1' || value.toLowerCase() === 'true'
  }
  if (udtName === 'timestamp' || udtName === 'timestamptz' || udtName === 'date') {
    if (typeof value === 'number' && Number.isFinite(value)) {
      const ms = value > 1e12 ? value : value * 1000
      return new Date(ms)
    }
    if (typeof value === 'string' && /^\d+$/.test(value)) {
      const n = Number(value)
      if (Number.isFinite(n)) {
        const ms = n > 1e12 ? n : n * 1000
        return new Date(ms)
      }
    }
  }
  return value
}

async function main() {
  const { sqliteUrl, pgUrl } = pickUrls()
  const sqliteFile = resolveSqliteFile(sqliteUrl)
  if (!sqliteFile || !existsSync(sqliteFile)) {
    throw new Error(`SQLite file not found: ${sqliteFile || sqliteUrl}`)
  }

  console.log(`[migrate] SQLite source: ${sqliteFile}`)
  console.log('[migrate] PostgreSQL target: configured')

  const sqlite = new Database(sqliteFile, { readonly: true })
  const pgClient = new Client({ connectionString: pgUrl })

  await pgClient.connect()
  const pgColumns = await loadPostgresColumns(pgClient)

  const pgTablesRes = await pgClient.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
  `)
  const pgTables = new Set(pgTablesRes.rows.map((r) => r.tablename))

  const sqliteTables = sqlite
    .prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        AND name <> '_prisma_migrations'
    `)
    .all()
    .map((r) => r.name)

  const orderedTables = [
    ...TABLE_ORDER.filter((t) => sqliteTables.includes(t) && pgTables.has(t)),
    ...sqliteTables.filter((t) => !TABLE_ORDER.includes(t) && pgTables.has(t)),
  ]

  if (orderedTables.length === 0) {
    throw new Error('No shared tables found between SQLite and PostgreSQL.')
  }

  try {
    await pgClient.query('BEGIN')
    await pgClient.query(`TRUNCATE TABLE ${orderedTables.map(quoteIdent).join(', ')} CASCADE`)

    for (const table of orderedTables) {
      const rows = sqlite.prepare(`SELECT * FROM ${quoteIdent(table)}`).all()
      if (!rows.length) {
        console.log(`[migrate] ${table}: 0 rows`)
        continue
      }

      const columns = Object.keys(rows[0])
      const columnSql = columns.map(quoteIdent).join(', ')
      const batchSize = 250
      let inserted = 0

      for (let i = 0; i < rows.length; i += batchSize) {
        const batch = rows.slice(i, i + batchSize)
        const params = []
        const valuesSql = batch
          .map((row, rowIndex) => {
            const placeholders = columns.map((column, colIndex) => {
              const paramIndex = rowIndex * columns.length + colIndex + 1
              const udtName = pgColumns.get(`${table}.${column}`)
              params.push(normalizeValue(row[column], udtName))
              return `$${paramIndex}`
            })
            return `(${placeholders.join(', ')})`
          })
          .join(', ')

        const sql = `INSERT INTO ${quoteIdent(table)} (${columnSql}) VALUES ${valuesSql}`
        await pgClient.query(sql, params)
        inserted += batch.length
      }

      console.log(`[migrate] ${table}: ${inserted} rows`)
    }

    await pgClient.query('COMMIT')
    console.log('[migrate] Done.')
  } catch (error) {
    await pgClient.query('ROLLBACK')
    throw error
  } finally {
    sqlite.close()
    await pgClient.end()
  }
}

main().catch((error) => {
  console.error('[migrate] Failed:', error.message)
  process.exit(1)
})
