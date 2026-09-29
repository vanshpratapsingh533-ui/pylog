const { useMemo, useState } = React;

const SAMPLE = `192.168.1.10 - - [03/Sep/2026:10:15:22 +0530] "GET /index.html HTTP/1.1" 200 1024
10.0.0.25 - - [03/Sep/2026:10:16:10 +0530] "GET /missing-page HTTP/1.1" 404 512
192.168.1.10 - - [03/Sep/2026:10:17:02 +0530] "POST /api/login HTTP/1.1" 500 245
172.16.0.4 - - [03/Sep/2026:10:18:55 +0530] "GET /admin HTTP/1.1" 403 321
malformed log row`;

function Metric({ label, value, detail, tone }) {
  return (
    <article className={`metric ${tone || ''}`}>
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{detail}</span>
    </article>
  );
}

function RankedList({ title, items, suffix = 'requests' }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {items.length ? (
        <ol className="ranked">
          {items.map((x, i) => (
            <li key={x.label}>
              <b>{i + 1}</b>
              <span title={x.label}>{x.label}</span>
              <em>
                {x.count.toLocaleString()} {suffix}
              </em>
            </li>
          ))}
        </ol>
      ) : (
        <p className="empty">No data available.</p>
      )}
    </section>
  );
}

function StatusChart({ items }) {
  const max = Math.max(...items.map((x) => x.count), 1);

  return (
    <section className="panel">
      <h2>Status code distribution</h2>
      {items.length ? (
        <div className="bars">
          {items.map((x) => (
            <div className="bar-row" key={x.label}>
              <span>{x.label}</span>
              <i>
                <b style={{ width: `${(x.count / max) * 100}%` }} />
              </i>
              <em>{x.count}</em>
            </div>
          ))}
        </div>
      ) : (
        <p className="empty">No valid log entries found.</p>
      )}
    </section>
  );
}

function downloadReport(data) {
  const s = data.summary;
  const lines = [
    `PYLOG ANALYZER REPORT`,
    `File: ${data.fileName}`,
    '',
    `Total lines processed: ${s.totalLines}`,
    `Malformed entries: ${s.malformedCount}`,
    `HTTP errors (4xx + 5xx): ${s.httpErrors}`,
    `Overall error rate: ${s.errorRate}%`,
    '',
    'Top active client IPs:',
    ...data.topIps.map((x, i) => `${i + 1}. ${x.label} - ${x.count} requests`),
    '',
    'Error entries:',
    ...data.errors.map(
      (x) =>
        `Line ${x.lineNumber} | ${x.status}: ${x.description} | Suggested action: ${x.suggestion}\n${x.raw}`
    ),
  ];

  const a = document.createElement('a');
  a.href = URL.createObjectURL(
    new Blob([lines.join('\n')], { type: 'text/plain' })
  );
  a.download = 'pylog-report.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}

function App() {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(
    'Upload a Common Log Format file to begin.'
  );
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');

  async function analyze(file) {
    if (!file) return;
    setBusy(true);
    setMessage('Analyzing log file…');

    try {
      const content = await file.text();
      const r = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, fileName: file.name }),
      });

      const json = await r.json();
      if (!r.ok) throw new Error(json.error || 'Analysis failed');

      setData(json);
      setMessage(
        `Analysis complete: ${json.summary.totalLines.toLocaleString()} log entries processed.`
      );
    } catch (e) {
      setMessage(e.message);
    } finally {
      setBusy(false);
    }
  }

  function loadSample() {
    analyze(new File([SAMPLE], 'sample-access.log', { type: 'text/plain' }));
  }

  const errors = useMemo(
    () =>
      (data?.errors || []).filter(
        (x) =>
          (filter === 'all' || String(x.status) === filter) &&
          Object.values(x)
            .join(' ')
            .toLowerCase()
            .includes(search.toLowerCase())
      ),
    [data, filter, search]
  );

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">WEB SERVER LOG INSIGHTS</p>
          <h1>Pylog Analyzer</h1>
          <p className="lead">
            Turn raw access logs into clear traffic insights, error details, and
            practical fixes.
          </p>
        </div>
        <button
          className="secondary"
          onClick={loadSample}
          disabled={busy}
        >
          Try sample data
        </button>
      </header>

      <section className="upload">
        <input
          id="file"
          type="file"
          accept=".log,.txt,text/plain"
          onChange={(e) => analyze(e.target.files[0])}
        />
        <label htmlFor="file">
          {busy ? 'Analyzing…' : 'Choose a log file'}
        </label>
        <p>{message}</p>
      </section>

      {data && (
        <>
          <section className="metrics">
            <Metric
              label="Lines processed"
              value={data.summary.totalLines.toLocaleString()}
              detail={`${data.summary.uniqueIps} unique client IPs`}
            />
            <Metric
              tone="danger"
              label="HTTP errors"
              value={data.summary.httpErrors.toLocaleString()}
              detail="4xx and 5xx responses"
            />
            <Metric
              tone="warn"
              label="Error rate"
              value={`${data.summary.errorRate}%`}
              detail="Errors plus malformed rows"
            />
            <Metric
              label="Malformed rows"
              value={data.summary.malformedCount.toLocaleString()}
              detail="Could not be parsed"
            />
          </section>

          <section className="grid">
            <StatusChart items={data.statusCodes} />
            <RankedList title="Top client IPs" items={data.topIps} />
            <RankedList title="Most requested paths" items={data.topPaths} />
            <RankedList title="HTTP methods" items={data.topMethods} />
          </section>

          <section className="panel alert">
            <div>
              <h2>Attention needed</h2>
              {data.suspiciousIps.length ? (
                <p>
                  High-volume IPs:{' '}
                  {data.suspiciousIps
                    .map((x) => `${x.ip} (${x.requests})`)
                    .join(', ')}
                  . Review these requests for bots or abuse.
                </p>
              ) : (
                <p>No unusually high-volume client IP was detected.</p>
              )}
            </div>
            <button
              className="download"
              onClick={() => downloadReport(data)}
            >
              Download report
            </button>
          </section>

          <section className="panel errors">
            <div className="section-head">
              <div>
                <h2>Error entries and suggested fixes</h2>
                <p>{errors.length} matching entries</p>
              </div>
              <div className="controls">
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search IP, path, or message"
                />
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                >
                  <option value="all">All errors</option>
                  {[
                    ...new Set(data.errors.map((x) => String(x.status))),
                  ].map((x) => (
                    <option key={x} value={x}>
                      {x}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Line</th>
                    <th>Status</th>
                    <th>Request</th>
                    <th>Description</th>
                    <th>Suggested action</th>
                  </tr>
                </thead>
                <tbody>
                  {errors.length ? (
                    errors.map((x) => (
                      <tr key={x.lineNumber}>
                        <td>{x.lineNumber}</td>
                        <td>
                          <span className="badge">{x.status}</span>
                        </td>
                        <td>
                          {x.method ? (
                            <>
                              <b>{x.method}</b> {x.path}
                              <small>
                                {x.ip} · {x.timestamp}
                              </small>
                            </>
                          ) : (
                            <code>{x.raw}</code>
                          )}
                        </td>
                        <td>{x.description}</td>
                        <td>{x.suggestion}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" className="empty">
                        No errors match the selected filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </main>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);