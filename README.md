# imgur-clone

minimal file sharing service with short urls

## install

ensure mongodb, memcached, and redis are installed and running somewhere.

```bash
# install dependencies
npm install
```

## environment

create `.env` file:

```env
# required
MONGO_URI=mongodb://localhost:27017/imgur-clone
MEMCACHED_URL=localhost:11211
REDIS_URL=redis://localhost:6379

# optional
PORT=3000                  # default: 3000
ADMIN_TOKEN=your-token     # for /admin/stats
CLOAK_ROBOTS=true          # hide from search engines
```

## run

```bash
node server.js
```

## api

- `GET /` - upload page
- `POST /upload` - upload file
- `GET /:shortcode` - view file
- `GET /admin/stats` - view stats (requires auth)
  - `?days=7` - number of days (default: 7)
  - `?merged=1` - merge stats into totals
