require('dotenv').config()

const express = require('express')
const compression = require('compression')
const multer = require('multer')
const { MongoClient } = require('mongodb')
const crypto = require('crypto')
const path = require('path')
const Memcached = require('memcached')
const fs = require('fs')
const Redis = require('ioredis')
const Metrics = require('trk2')

const app = express()
const upload = multer()
const memcached = new Memcached(process.env.MEMCACHED_URI.split('memcached://').join(''))
const redis = new Redis(process.env.REDIS_URI)
let db

// Initialize metrics
const metrics = new Metrics({
  redis,
  key: 'imgr',
  map: {
    bmp: ['ip'], // track unique visitors
    add: [
      'event',                    // track all events
      'event~shortcode',          // track events per shortcode
      'event~type',               // track events by file type
      'event~shortcode~type'      // track events by shortcode and type
    ],
    addv: [
      { key: 'shortcode~event', addKey: 'size' }  // track total size per shortcode
    ],
    top: [
      'shortcode',                // most used shortcodes
      'type',                     // most uploaded file types
      'shortcode~type'            // most used shortcode+type combinations
    ]
  }
})

app.disable('x-powered-by')
app.use(compression())

// Add conditional bot protection middleware
const CLOAK_ENABLED = process.env.CLOAK_ROBOTS === 'true'

if (CLOAK_ENABLED) {
  const allowedUserAgents = [
    // Real browsers
    'mozilla', 'chrome', 'safari', 'opera', 'edge', 'firefox',
    // Curl and wget
    'curl', 'wget'
  ]

  const botProtection = (req, res, next) => {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase()
    
    // Always add noindex headers when cloaking is enabled
    res.setHeader('X-Robots-Tag', 'noindex, nofollow')
    
    // Skip check for homepage and robots.txt
    if (req.path === '/' || req.path === '/robots.txt') {
      return next()
    }
    
    // Block if user agent looks like a bot
    const isAllowed = allowedUserAgents.some(agent => userAgent.includes(agent))
    if (!isAllowed) {
      return res.status(403).send('forbidden')
    }
    
    next()
  }

  app.use(botProtection)

  // Serve restrictive robots.txt when cloaking
  app.get('/robots.txt', (req, res) => {
    res.type('text/plain')
    res.send('User-agent: *\nDisallow: /')
  })

  // Add noindex meta tag to HTML when cloaking
  app.get('/', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=86400')
    res.setHeader('Content-Type', 'text/html')
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="robots" content="noindex, nofollow">
        ${fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8')
          .replace('<head>', '')
          .replace('</head>', '')
          .replace('<!DOCTYPE html>', '')
          .replace('<html lang="en">', '')
          .trim()}
      </html>
    `.trim())
  })
} else {
  // Default permissive robots.txt when not cloaking
  app.get('/robots.txt', (req, res) => {
    res.type('text/plain')
    res.send('User-agent: *\nAllow: /')
  })

  // Serve HTML without noindex when not cloaking
  app.get('/', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=86400')
    res.sendFile(path.join(__dirname, 'index.html'))
  })
}

const CACHE_DURATION = 60 * 60 * 24 // 24 hours
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
const EXPIRY_DAYS = 30 // 30 days
const EXPIRY_SECONDS = EXPIRY_DAYS * 24 * 60 * 60
const GRACE_PERIOD = 30 // 30 seconds grace period

const CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'
const MIN_LENGTH = 3
const MAX_ATTEMPTS = 300

const getLastCode = async () => {
  return new Promise((resolve) => {
    memcached.get('last_code', (err, data) => {
      if (err || !data) resolve(null)
      else resolve(data)
    })
  })
}

const setLastCode = async (code) => {
  return new Promise((resolve) => {
    memcached.set('last_code', code, EXPIRY_SECONDS + GRACE_PERIOD, (err) => {
      resolve()
    })
  })
}

const generateShortCode = async () => {
  let length = MIN_LENGTH
  let attempts = MAX_ATTEMPTS
  let startIndex = 0
  
  // Try to get the last successful code
  const lastCode = await getLastCode()
  if (lastCode) {
    length = lastCode.length
    // Convert the last code back to its numeric index
    startIndex = 0
    for (let i = 0; i < lastCode.length; i++) {
      startIndex = startIndex * CHARS.length + CHARS.indexOf(lastCode[i])
    }
    startIndex++ // Start from the next possible code
  }
  
  while (attempts > 0) {
    // Generate all possible codes of current length
    const maxIndex = Math.pow(CHARS.length, length)
    for (let i = startIndex; i < maxIndex; i++) {
      let code = ''
      let num = i
      
      // Convert number to base-36 representation using our charset
      for (let j = 0; j < length; j++) {
        code = CHARS[num % CHARS.length] + code
        num = Math.floor(num / CHARS.length)
      }
      
      // Check if code is available in both memcached and db
      try {
        // Check memcached first (faster)
        const exists = await new Promise((resolve) => {
          memcached.get(`code:${code}`, (err, data) => {
            resolve(!!data)
          })
        })
        
        if (!exists) {
          // Check database
          const dbExists = await db.collection('files').findOne({ short_code: code })
          
          if (!dbExists) {
            // Reserve the code in memcached
            await new Promise((resolve, reject) => {
              memcached.set(`code:${code}`, '1', EXPIRY_SECONDS, (err) => {
                if (err) reject(err)
                else resolve()
              })
            })
            
            // Store this as the last successful code
            await setLastCode(code)
            
            return code
          }
        }
      } catch (err) {
        console.warn('Error checking code availability:', err)
        // On error, generate a random fallback code of MIN_LENGTH
        const fallback = crypto.randomBytes(MIN_LENGTH).toString('hex').slice(0, MIN_LENGTH).toLowerCase()
        await setLastCode(fallback)
        return fallback
      }
      
      attempts--
      if (attempts <= 0) break
    }
    
    // If we get here, all codes of current length are taken
    length++
    startIndex = 0 // Reset start index for new length
  }
  
  // Fallback to random hex if we couldn't find a short code
  const fallback = crypto.randomBytes(MIN_LENGTH).toString('hex').slice(0, MIN_LENGTH).toLowerCase()
  await setLastCode(fallback)
  return fallback
}

const getFromCache = (key) => {
  return new Promise((resolve, reject) => {
    memcached.get(key, (err, data) => {
      if (err) return reject(err)
      if (!data) return resolve(null)
      
      try {
        data.data = Buffer.from(data.data_base64, 'base64')
        delete data.data_base64
        resolve(data)
      } catch (err) {
        reject(err)
      }
    })
  })
}

const setCache = (key, value) => {
  return new Promise((resolve, reject) => {
    if (!value || !value.data) return resolve()
    
    const cacheValue = {
      short_code: value.short_code,
      content_type: value.content_type,
      data_base64: value.data.toString('base64'),
      created_at: value.created_at
    }
    
    memcached.set(key, cacheValue, EXPIRY_SECONDS, (err) => {
      if (err) {
        console.warn('Cache set failed:', err.message)
        resolve() // Continue without caching
      } else {
        resolve()
      }
    })
  })
}

const connectDb = async () => {
  const client = await MongoClient.connect(process.env.MONGO_URI)
  db = client.db()
  
  await db.collection('files').createIndex({ short_code: 1 }, { unique: true })
  await db.collection('files').createIndex({ created_at: 1 }, { 
    expireAfterSeconds: EXPIRY_SECONDS
  })
}

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file provided' })
    if (req.file.size > MAX_FILE_SIZE) return res.status(413).json({ error: 'file too large' })
    
    const shortCode = await generateShortCode()
    
    const fileData = {
      short_code: shortCode,
      content_type: req.file.mimetype,
      data: req.file.buffer,
      created_at: new Date()
    }
    
    try {
      await db.collection('files').insertOne(fileData)
      // Track upload
      await metrics.record({
        ip: req.ip,
        event: 'upload',
        shortcode: shortCode,
        type: req.file.mimetype,
        size: req.file.size,
        ua: req.headers['user-agent']
      })
    } catch (err) {
      console.error('Database insert failed:', err)
      return res.status(500).json({ error: 'failed to store file' })
    }

    try {
      await setCache(shortCode, fileData)
    } catch (err) {
      console.warn('Cache set failed:', err)
      // Continue without caching
    }
    
    res.json({ 
      url: `${req.protocol}://${req.get('host')}/${shortCode}`,
      short_code: shortCode 
    })
  } catch (err) {
    console.error('Upload error:', err)
    res.status(500).json({ error: 'internal server error' })
  }
})

// Serve favicon
app.get('/favicon.svg', (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml')
  res.setHeader('Cache-Control', 'public, max-age=31536000') // 1 year
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="200.01 99.98 799.97 1000.04">
    <path d="m324.98 99.984c-68.719 0-124.97 56.297-124.97 125.02v750c0 68.719 56.25 125.02 124.97 125.02h550.03c68.719 0 124.97-56.297 124.97-125.02v-549.98c0-38.672-15.328-75.703-42.656-103.03l-179.29-179.29c-27.328-27.328-64.406-42.703-103.03-42.703z" fill="#ffb258"></path>
  </svg>`)
})

// Also serve as .ico for legacy support
app.get('/favicon.ico', (req, res) => {
  res.redirect(301, '/favicon.svg')
})

app.get('/:shortCode', async (req, res) => {
  const shortCode = req.params.shortCode.toLowerCase()
  
  try {
    let file = null
    
    try {
      // try cache first
      const cachedFile = await getFromCache(shortCode)
      if (cachedFile) {
        file = cachedFile
        res.setHeader('X-Cache', 'HIT')
      }
    } catch (err) {
      console.warn('Cache get failed:', err)
      // Continue without cache
    }
    
    if (!file) {
      // fallback to db
      file = await db.collection('files').findOne({ 
        short_code: shortCode 
      })
      
      if (!file) return res.status(404).send('not found')
      
      try {
        await setCache(shortCode, file)
      } catch (err) {
        console.warn('Cache set failed:', err)
        // Continue without caching
      }
      
      res.setHeader('X-Cache', 'MISS')
    }

    // Record valid view
    await metrics.record({
      ip: req.ip,
      event: 'view',
      shortcode: shortCode,
      type: file.content_type,
      ua: req.headers['user-agent']
    })
    
    res.setHeader('Content-Type', file.content_type)
    
    // Handle both Buffer and Binary data types
    if (file.data instanceof Buffer) {
      res.send(file.data)
    } else if (file.data.buffer) {
      res.send(file.data.buffer)
    } else {
      res.send(file.data)
    }
  } catch (err) {
    console.error('Error serving file:', err)
    res.status(500).send('internal server error')
  }
})

// Admin stats route
app.get('/admin/stats', async (req, res) => {
  try {
    // Basic auth check
    const auth = req.headers.authorization
    if (!auth || auth !== `Bearer ${process.env.ADMIN_TOKEN}`) {
      return res.status(401).json({ error: 'unauthorized' })
    }

    // Get query parameters with defaults
    let days = parseInt(req.query.days) || 15
    const merged = req.query.merged === '1'

    if (isNaN(days) || days < 1 || days > 28) {
      days = 15
    }

    // Query stats for requested days
    const results = await metrics.queryDays(days * -1)
    
    // Get unique visitors
    let unique = results.find({
      type: 'bmp',
      key: 'ip',
      merge: false // daily breakdown
    })

    if (merged) {
      // Sum up all unique visitors
      unique = Object.values(unique).reduce((acc, curr) => acc + curr, 0)
    }

    // Get event counts with filters
    const allEvents = results.find({
      type: 'add',
      key: 'event',
      merge: merged,
    })

    // Get top files
    const topFiles = results.find({
      type: 'top',
      key: 'shortcode',
      merge: merged
    })
    
    // Get top file types
    const topTypes = results.find({
      type: 'top',
      key: 'type',
      merge: merged
    })

    // Get total size per shortcode
    const sizeByFile = results.find({
      type: 'addv',
      key: 'shortcode~event',
      addKey: 'size',
      merge: merged
    })

    res.setHeader('Content-Type', 'application/json')

    res.send(JSON.stringify({
      params: {
        days,
        merged
      },
      unique_visitors: unique,
      events: allEvents,
      top_files: topFiles,
      top_types: topTypes,
      size_by_file: sizeByFile,
    }, null, 2))
  } catch (err) {
    console.error('Stats error:', err)
    res.status(500).json({ error: 'failed to get stats' })
  }
})

const port = process.env.PORT || 3000

connectDb().then(() => {
  app.listen(port, () => {
    console.log(`server running on port ${port}`)
    console.log(`robot cloaking: ${CLOAK_ENABLED ? 'enabled' : 'disabled'}`)
  })
})
