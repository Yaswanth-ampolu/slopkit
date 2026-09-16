/* ps5-relay/static/neon_client.js
 *
 * Write to Neon straight from the PS5 browser: plain XHR to Neon's HTTP SQL
 * endpoint, authenticated by the database connection string. No PC, no LAN, no
 * Python, no Data API, no JWT, no Neon console access.
 *
 *   POST https://<endpoint>/sql
 *   Neon-Connection-String: postgresql://user:pass@<endpoint>/neondb?sslmode=require
 *   {"query": "select public.put_chunks_b64($1, $2::jsonb)", "params": [...]}
 *
 * CORS is open on that endpoint (verified):
 *   access-control-allow-origin: *
 *   access-control-allow-headers: ..., Neon-Connection-String, ...
 * so a page served over HTTPS can call it directly with no mixed-content and
 * no preflight problem.
 *
 * Why batch: a bare request costs ~800 ms of handshake before payload moves.
 * put_chunks_b64 takes an ARRAY, so N chunks cost one handshake, not N.
 *
 * Why base64: the endpoint takes JSON, so there is no binary body. base64 is
 * +33% on the wire, and the server decodes it with decode(...,'base64') before
 * insert -- so the 500 MiB free-tier budget is charged for RAW bytes only.
 *
 * ES5/XHR deliberately: the PS5's WebKit predates fetch and arrow functions.
 *
 * Usage:
 *   var r = new NeonRelay(NEON_HOST, NEON_DSN);
 *   r.headroom(function (h) {
 *     r.begin('libSceNKWebKit.sprx', {fw:'13.60'}, function (id) {
 *       r.pushBytes(bytes, onProgress, function (n, total, reqs) {
 *         r.finalize(sha256, function (info) { ... });
 *       }, onError);
 *     }, onError);
 *   }, onError);
 */

function NeonRelay(host, dsn) {
    this.host = host;
    this.dsn = dsn;
    this.url = 'https://' + host + '/sql';
    this.dumpId = null;
    this.chunkSize = 262144;   // 256 KiB -- small enough that a batch of them
                               // fits in console memory mid-exploit
    this.batchSize = 8;        // -> 2 MiB per request
    this.seq = 0;
    this.requests = 0;
}

/* ------------------------------------------------------------------ core -- */

/* One SQL round trip. `query` may use $1..$n bound by `params`.
   onOk receives the parsed {fields, rows, command, rowCount}. */
NeonRelay.prototype.sql = function (query, params, onOk, onErr) {
    var x = new XMLHttpRequest();
    var self = this;
    x.open('POST', this.url, true);
    x.timeout = 180000;
    /* Do NOT set Content-Type: application/json here.
       `application/json` is not a CORS-safelisted content type, so sending it
       forces a preflight, and the preflight then has to ask Neon's permission
       for a `content-type` request header. Neon's response is static and does
       NOT list content-type among the headers it allows:

           access-control-allow-headers: Authorization, Neon-Connection-String,
             Neon-Raw-Text-Output, Neon-Array-Mode, Neon-Pool-Opt-In,
             Neon-Batch-Read-Only, Neon-Batch-Isolation-Level, Neon-Client-Info

       So the browser refuses the request and the console sees status 0 --
       measured exactly that way: a plain POST to /sql returns 400 (reached the
       server), while the same POST plus these headers returns 0 (blocked).
       Neon parses the JSON body fine without any Content-Type at all
       (verified: HTTP 200), and Neon-Connection-String IS on the allow list,
       so dropping this one line is the whole fix. */
    x.setRequestHeader('Neon-Connection-String', this.dsn);
    x.onreadystatechange = function () {
        if (x.readyState !== 4) return;
        self.requests++;
        if (x.status >= 200 && x.status < 300) {
            var out;
            try { out = JSON.parse(x.responseText); } catch (e) {
                if (onErr) onErr({ status: x.status, body: x.responseText });
                return;
            }
            if (onOk) onOk(out);
        } else if (onErr) {
            onErr({ status: x.status, body: x.responseText });
        }
    };
    x.onerror = function () { if (onErr) onErr({ status: 0, body: 'network error' }); };
    x.ontimeout = function () { if (onErr) onErr({ status: 0, body: 'timeout' }); };
    x.send(JSON.stringify({ query: query, params: params || [] }));
};

/* Convenience: run a query whose single value comes back under `as`. */
NeonRelay.prototype._scalar = function (query, params, key, onOk, onErr) {
    this.sql(query, params, function (res) {
        if (onOk) onOk(res.rows && res.rows[0] ? res.rows[0][key] : null, res);
    }, onErr);
};

/* ------------------------------------------------------------------ b64 --- */

/* Chunked so a multi-megabyte array never hits the argument-count limit that
   String.fromCharCode.apply() enforces. Verified round-trip identical. */
function _b64(bytes) {
    var CHUNK = 0x8000, out = '';
    for (var i = 0; i < bytes.length; i += CHUNK) {
        out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(out);
}

/* ----------------------------------------------------------------- verbs -- */

/* Check the free-tier budget before filling it.
   -> {db_bytes, chunk_bytes, open_dumps, budget} */
NeonRelay.prototype.headroom = function (onOk, onErr) {
    this._scalar('select public.relay_headroom() as h', [], 'h', onOk, onErr);
};

/* Reserve a dump. -> uuid string */
NeonRelay.prototype.begin = function (name, opts, onOk, onErr) {
    opts = opts || {};
    var self = this;
    this._scalar(
        'select public.begin_dump($1,$2,$3,$4,$5) as id',
        [name, opts.kind || 'binary', opts.chunkSize || this.chunkSize,
         opts.label || null, opts.fw || null],
        'id',
        function (id) { self.dumpId = id; if (onOk) onOk(id); },
        onErr);
};

/* Continue an interrupted upload. -> chunk index to resume at */
NeonRelay.prototype.resume = function (dumpId, onOk, onErr) {
    var self = this;
    this._scalar('select public.resume_point($1) as r', [dumpId], 'r',
        function (n) {
            self.dumpId = dumpId;
            self.seq = n || 0;
            if (onOk) onOk(dumpId, self.seq);
        }, onErr);
};

/* BATCH: write many chunks in ONE request.
   items = [{s: seq, d: "<base64>"}, ...] -> number of rows written */
NeonRelay.prototype.pushBatch = function (items, onOk, onErr) {
    var self = this;
    this._scalar('select public.put_chunks_b64($1, $2::jsonb) as n',
        [this.dumpId, JSON.stringify(items)], 'n',
        function (n) {
            self.seq = items[items.length - 1].s + 1;
            if (onOk) onOk(n);
        }, onErr);
};

/* Push a whole buffer, batchSize chunks per request, sequentially so memory
   stays flat and ordering is never in question. Resumes from this.seq. */
NeonRelay.prototype.pushBytes = function (buf, onProgress, onDone, onErr) {
    var u8 = (buf instanceof Uint8Array) ? buf : new Uint8Array(buf);
    var self = this;
    var total = Math.ceil(u8.length / this.chunkSize);
    var start = this.seq;
    var t0 = Date.now();
    var sent = start * this.chunkSize;

    function batch(from) {
        if (from >= total) {
            if (onDone) onDone(total, u8.length, self.requests);
            return;
        }
        var items = [];
        for (var i = from; i < Math.min(from + self.batchSize, total); i++) {
            var slice = u8.subarray(i * self.chunkSize,
                                    Math.min((i + 1) * self.chunkSize, u8.length));
            items.push({ s: i, d: _b64(slice) });
        }
        self.pushBatch(items, function () {
            sent += items.length * self.chunkSize;
            if (onProgress) {
                onProgress(items[items.length - 1].s + 1, total,
                           Math.min(sent, u8.length), Date.now() - t0);
            }
            batch(from + items.length);
        }, onErr);
    }
    batch(start);
};

/* Ship a memory region through an existing read primitive.
   readFn(addr, len) -> Uint8Array */
NeonRelay.prototype.pushMemory = function (readFn, addr, size, opts,
                                           onProgress, onDone, onErr) {
    opts = opts || {};
    var cs = opts.chunkSize || this.chunkSize;
    var self = this;
    var total = Math.ceil(size / cs);

    function batch(from) {
        if (from >= total) {
            if (onDone) onDone(total, size, self.requests);
            return;
        }
        var items = [];
        for (var i = from; i < Math.min(from + self.batchSize, total); i++) {
            var n = Math.min(cs, size - i * cs);
            var a = addr.add32 ? addr.add32(i * cs) : addr + i * cs;
            items.push({ s: i, d: _b64(readFn(a, n)) });
        }
        self.pushBatch(items, function () {
            if (onProgress) onProgress(items[items.length - 1].s + 1, total);
            batch(from + items.length);
        }, onErr);
    }
    batch(self.seq);
};

/* Seal the dump: stamp size + sha256 so the drain side can verify it. */
NeonRelay.prototype.finalize = function (sha256, onOk, onErr) {
    this._scalar('select public.finalize_dump($1,$2) as f',
        [this.dumpId, sha256 || null], 'f', onOk, onErr);
};

/* Batched status lines -- one request, so SCAN-GADGET results survive even if
   the page dies a moment later. */
NeonRelay.prototype.beacons = function (lines, onOk, onErr) {
    this._scalar('select public.put_beacons($1::jsonb,$2) as n',
        [JSON.stringify(lines), 'notify'], 'n', onOk, onErr);
};
