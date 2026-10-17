const { useMemo, useState, useEffect, memo } = React;

const PAGE_SIZE = 100;

const SAMPLE = `192.168.1.10 - - [03/Sep/2026:10:15:22 +0530] "GET /index.html HTTP/1.1" 200 1024
10.0.0.25 - - [03/Sep/2026:10:16:10 +0530] "GET /missing-page HTTP/1.1" 404 512
192.168.1.10 - - [03/Sep/2026:10:17:02 +0530] "POST /api/login HTTP/1.1" 500 245
172.16.0.4 - - [03/Sep/2026:10:18:55 +0530] "GET /admin HTTP/1.1" 403 321
malformed log row`;

const Metric = memo(function Metric({ label, value, detail, tone }) {
  return (
    <article className={`metric ${tone || ''}`}>
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{detail}</span>
    </article>
  );
});

const RankedList = memo(function RankedList({ title, items = [], suffix = 'requests', headerControls = null }) {
  const safeItems = items || [];
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
        {headerControls}
      </div>
      {safeItems.length ? (
        <ol className="ranked">
          {safeItems.map((x, i) => (
            <li key={x.label || i}>
              <b>{i + 1}</b>
              <span title={x.label}>{x.label}</span>
              <em>
                {(x.count || 0).toLocaleString()} {suffix}
              </em>
            </li>
          ))}
        </ol>
      ) : (
        <p className="empty">No data available.</p>
      )}
    </section>
  );
});

const StatusChart = memo(function StatusChart({ items }) {
  const safeItems = items || [];
  const max = useMemo(() => {
    if (!safeItems || !safeItems.length) return 1;
    return safeItems.reduce((acc, x) => Math.max(acc, x.count || 0), 1);
  }, [safeItems]);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Status code distribution</h2>
      </div>
      {safeItems.length ? (
        <div className="bars">
          {safeItems.map((x) => (
            <div className="bar-row" key={x.label}>
              <span>{x.label}</span>
              <i>
                <b style={{ width: `${((x.count || 0) / max) * 100}%` }} />
              </i>
              <em>{(x.count || 0).toLocaleString()}</em>
            </div>
          ))}
        </div>
      ) : (
        <p className="empty">No valid log entries found.</p>
      )}
    </section>
  );
});

const TimelineChart = memo(function TimelineChart({ rawData, items }) {
  const [unit, setUnit] = useState('hour');
  const [limit, setLimit] = useState(10);
  const [limitCustom, setLimitCustom] = useState(false);
  const [limitInput, setLimitInput] = useState('10');
  const [sortBy, setSortBy] = useState('chronological');

  const dataSrc = rawData !== undefined ? rawData : items;

  const availableData = useMemo(() => {
    if (!dataSrc) return [];
    if (Array.isArray(dataSrc)) return dataSrc;
    if (typeof dataSrc === 'object' && dataSrc !== null) {
      const arr = dataSrc[unit];
      if (Array.isArray(arr)) return arr;
    }
    return [];
  }, [dataSrc, unit]);

  const displayedItems = useMemo(() => {
    if (!Array.isArray(availableData)) return [];
    let list = [...availableData];
    if (sortBy === 'busiest') {
      list.sort((a, b) => (b.count || 0) - (a.count || 0));
    }
    if (limit === 'all') return list;
    const n = typeof limit === 'number' ? limit : parseInt(limit, 10) || 10;
    return list.slice(0, n);
  }, [availableData, sortBy, limit]);

  const max = useMemo(() => {
    if (!displayedItems || !displayedItems.length) return 1;
    return displayedItems.reduce((acc, x) => Math.max(acc, x.count || 0), 1);
  }, [displayedItems]);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Requests over time</h2>
        <div className="panel-controls">
          <label htmlFor="timeUnitSelect">Group by:</label>
          <select
            id="timeUnitSelect"
            value={unit}
            onChange={(e) => setUnit(e.target.value)}
          >
            <option value="second">Seconds</option>
            <option value="minute">Minutes</option>
            <option value="hour">Hours</option>
            <option value="day">Days</option>
            <option value="week">Weeks</option>
            <option value="month">Months</option>
          </select>

          <label htmlFor="timeLimitSelect" style={{ marginLeft: '4px' }}>
            Show:
          </label>
          <select
            id="timeLimitSelect"
            value={limitCustom ? 'custom' : limit}
            onChange={(e) => {
              if (e.target.value === 'custom') {
                setLimitCustom(true);
                setLimitInput(String(limit === 'all' ? 10 : limit));
              } else if (e.target.value === 'all') {
                setLimitCustom(false);
                setLimit('all');
              } else {
                setLimitCustom(false);
                setLimit(parseInt(e.target.value, 10));
              }
            }}
          >
            <option value={5}>Top 5</option>
            <option value={10}>Top 10</option>
            <option value={24}>Top 24</option>
            <option value={50}>Top 50</option>
            <option value="all">All</option>
            <option value="custom">Custom…</option>
          </select>

          {limitCustom && (
            <input
              type="number"
              min="1"
              max="5000"
              value={limitInput}
              style={{ width: '4rem' }}
              onChange={(e) => setLimitInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') e.target.blur();
              }}
              onBlur={() => {
                const n = Math.max(1, parseInt(limitInput, 10) || 10);
                setLimit(n);
                setLimitInput(String(n));
              }}
              autoFocus
            />
          )}

          <label htmlFor="timeSortSelect" style={{ marginLeft: '4px' }}>
            Order:
          </label>
          <select
            id="timeSortSelect"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="chronological">Timeline</option>
            <option value="busiest">Busiest</option>
          </select>
        </div>
      </div>

      {displayedItems && displayedItems.length ? (
        <div className="bars">
          {displayedItems.map((x) => (
            <div className="timeline-bar-row" key={x.label}>
              <span title={x.label}>{x.label}</span>
              <i>
                <b style={{ width: `${((x.count || 0) / max) * 100}%` }} />
              </i>
              <em>{(x.count || 0).toLocaleString()}</em>
            </div>
          ))}
        </div>
      ) : (
        <p className="empty">No timestamp data found in log.</p>
      )}
    </section>
  );
});

const ErrorRow = memo(function ErrorRow({ x }) {
  return (
    <tr>
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
  );
});

function ThemeToggle() {
  const [theme, setTheme] = useState(
    () => document.documentElement.getAttribute('data-theme') || 'dark'
  );

  function toggle() {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try {
      localStorage.setItem('pylog-theme', next);
    } catch (e) {}
    setTheme(next);
  }

  return (
    <button className="secondary" onClick={toggle}>
      {theme === 'dark' ? '☀️ Light Theme' : '🌙 Dark Theme'}
    </button>
  );
}

function downloadReport(data, topLimit) {
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
    `Top ${topLimit} active client IPs:`,
    ...data.topIps
      .slice(0, topLimit)
      .map((x, i) => `${i + 1}. ${x.label} - ${x.count} requests`),
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
  const [message, setMessage] = useState('Upload a Common Log Format file to begin.');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [topLimit, setTopLimit] = useState(5);
  const [topLimitCustom, setTopLimitCustom] = useState(false);
  const [topLimitInput, setTopLimitInput] = useState('');
  const [everExpanded, setEverExpanded] = useState(false);

  useEffect(() => {
    const handler = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(handler);
  }, [search]);

  useEffect(() => {
    setVisible(PAGE_SIZE);
  }, [debouncedSearch, filter]);

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
      setSearch('');
      setDebouncedSearch('');
      setFilter('all');
      setVisible(PAGE_SIZE);
      setEverExpanded(false);
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

  const searchable = useMemo(
    () =>
      (data ? data.errors : []).map((x) => ({
        x,
        text: [x.ip, x.path, x.method, x.status, x.timestamp, x.raw, x.description, x.suggestion]
          .join(' ')
          .toLowerCase(),
      })),
    [data]
  );

  const statusOptions = useMemo(
    () => [...new Set((data ? data.errors : []).map((x) => String(x.status)))].sort(),
    [data]
  );

  const errors = useMemo(() => {
    const q = debouncedSearch.trim().toLowerCase();
    return searchable
      .filter(
        (r) =>
          (filter === 'all' || String(r.x.status) === filter) &&
          (!q || r.text.includes(q))
      )
      .map((r) => r.x);
  }, [searchable, filter, debouncedSearch]);

  const shown = errors.slice(0, visible);

  const topIps = useMemo(() => (data ? data.topIps.slice(0, topLimit) : []), [data, topLimit]);
  const topPaths = useMemo(() => (data ? data.topPaths.slice(0, topLimit) : []), [data, topLimit]);
  const topMethods = useMemo(() => (data ? data.topMethods.slice(0, topLimit) : []), [data, topLimit]);

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">WEB SERVER LOG INSIGHTS</p>
          <h1>Pylog Analyzer</h1>
          <p className="lead">
            Turn raw access logs into clear traffic insights, error details, and practical fixes.
          </p>
        </div>
        <div className="header-actions">
          <ThemeToggle />
          <button className="secondary" onClick={loadSample} disabled={busy}>
            Try sample data
          </button>
        </div>
      </header>

      <section className="upload">
        <input
          id="file"
          type="file"
          accept=".log,.txt,text/plain"
          onChange={(e) => {
            const file = e.target.files[0];
            e.target.value = '';
            analyze(file);
          }}
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
              detail={`${data.summary.uniqueIps.toLocaleString()} unique client IPs`}
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
            <StatusChart items={data.statusCodes || []} />
            <TimelineChart rawData={data.requestsOverTime} />
            <RankedList
              title="Top client IPs"
              items={topIps}
              headerControls={
                <div className="panel-controls">
                  <label htmlFor="topLimitSelect">Top client IPs:</label>
                  <select
                    id="topLimitSelect"
                    value={topLimitCustom ? 'custom' : topLimit}
                    onChange={(e) => {
                      if (e.target.value === 'custom') {
                        setTopLimitCustom(true);
                        setTopLimitInput(String(topLimit));
                      } else {
                        setTopLimitCustom(false);
                        setTopLimit(parseInt(e.target.value, 10));
                      }
                    }}
                  >
                    {[3, 5, 10, 15, 20, 50, 100].map((n) => (
                      <option key={n} value={n}>
                        Top {n}
                      </option>
                    ))}
                    <option value="custom">Custom…</option>
                  </select>
                  {topLimitCustom && (
                    <input
                      type="number"
                      min="1"
                      max="100"
                      value={topLimitInput}
                      placeholder="1–100"
                      style={{ width: '4.5rem' }}
                      onChange={(e) => setTopLimitInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') e.target.blur();
                      }}
                      onBlur={() => {
                        const n = Math.min(100, Math.max(1, parseInt(topLimitInput, 10) || topLimit));
                        setTopLimit(n);
                        setTopLimitInput(String(n));
                      }}
                      autoFocus
                    />
                  )}
                </div>
              }
            />
            <RankedList title="Most requested paths" items={topPaths} />
            <RankedList title="HTTP methods" items={topMethods} />
          </section>

          <section className="panel alert">
            <div>
              <h2>Attention needed</h2>
              {(data.suspiciousIps || []).length ? (
                <p>
                  High-volume IPs:{' '}
                  {data.suspiciousIps
                    .map((x) => `${x.ip} (${x.requests.toLocaleString()})`)
                    .join(', ')}
                  . Review these requests for bots or abuse.
                </p>
              ) : (
                <p>No unusually high-volume client IP was detected.</p>
              )}
              {(data.errorSpikes || []).length > 0 && (
                <p>
                  Error-rate spikes in{' '}
                  {data.errorSpikes.length === 1 ? 'this hour' : `${data.errorSpikes.length} hours`}:{' '}
                  {data.errorSpikes
                    .map((x) => `${x.hour} (${x.errorRate}% error rate)`)
                    .join(', ')}
                  . Investigate these time windows for incidents.
                </p>
              )}
            </div>
            <button className="download" onClick={() => downloadReport(data, topLimit)}>
              Download report
            </button>
          </section>

          <section className="panel errors">
            <div className="section-head">
              <div>
                <h2>Error entries and suggested fixes</h2>
                <p>
                  Showing {shown.length.toLocaleString()} of{' '}
                  {errors.length.toLocaleString()} matching entries
                </p>
              </div>
              <div className="controls">
                <input
                  type="text"
                  name="log-search"
                  autoComplete="off"
                  spellCheck={false}
                  data-gramm="false"
                  data-lpignore="true"
                  data-1p-ignore="true"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search IP, path, or message..."
                />
                <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                  <option value="all">All errors</option>
                  {statusOptions.map((x) => (
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
                    shown.map((x) => <ErrorRow key={x.lineNumber} x={x} />)
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

            {(errors.length > shown.length || everExpanded) && (
              <div className="more">
                {errors.length > shown.length && (
                  <button
                    className="secondary"
                    onClick={() => {
                      setVisible((v) => v + PAGE_SIZE);
                      setEverExpanded(true);
                    }}
                  >
                    Show {Math.min(PAGE_SIZE, errors.length - shown.length)} more (
                    {(errors.length - shown.length).toLocaleString()} remaining)
                  </button>
                )}
                {everExpanded && visible > PAGE_SIZE && (
                  <button
                    className="secondary"
                    onClick={() => {
                      setVisible(PAGE_SIZE);
                      setEverExpanded(false);
                    }}
                  >
                    Show less
                  </button>
                )}
                <button
                  className="secondary"
                  onClick={() => {
                    const raw = window.prompt(
                      `Show how many error rows? (1–${errors.length.toLocaleString()})`,
                      String(visible)
                    );
                    if (raw === null) return;
                    const n = Math.min(errors.length, Math.max(1, parseInt(raw, 10) || visible));
                    setVisible(n);
                    if (n > PAGE_SIZE) setEverExpanded(true);
                  }}
                >
                  Custom…
                </button>
              </div>
            )}
          </section>
        </>
      )}
    </main>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
