import { useEffect, useState } from "react"


const API = "http://127.0.0.1:8000"


/* ============================================================
   LOGIN
============================================================ */

function Login({ onLogin }) {

  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")


  const handleLogin = async (event) => {

    event.preventDefault()

    setError("")


    if (!username.trim() || !password) {

      setError("Enter username and password")
      return

    }


    setLoading(true)


    try {

      const response = await fetch(
        `${API}/api/auth/login`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json"
          },

          body: JSON.stringify({
            username: username.trim(),
            password
          })
        }
      )


      const data = await response.json()


      if (!response.ok) {

        setError(
          data.detail ||
          "Invalid username or password"
        )

        return

      }


      localStorage.setItem(
        "sentinel_token",
        data.access_token
      )


      localStorage.setItem(
        "sentinel_user",
        JSON.stringify(data.user)
      )


      onLogin(data.user)

    } catch (error) {

      console.error(error)

      setError(
        "Unable to connect to Sentinel backend"
      )

    } finally {

      setLoading(false)

    }

  }


  return (

    <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center px-6">

      <div className="w-full max-w-md">

        <div className="text-center mb-8">

          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-500/10">

            <span className="text-3xl">
              🛡️
            </span>

          </div>


          <h1 className="text-3xl font-bold">
            SENTINEL
          </h1>


          <p className="mt-2 text-sm text-slate-400">
            Security Operations & Threat Detection Platform
          </p>

        </div>


        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-7 shadow-2xl">

          <div className="mb-6">

            <h2 className="text-xl font-semibold">
              Analyst Login
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Authenticate to access the security dashboard.
            </p>

          </div>


          <form
            onSubmit={handleLogin}
            className="space-y-5"
          >

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Username
              </label>


              <input
                type="text"
                value={username}
                onChange={(event) =>
                  setUsername(event.target.value)
                }
                placeholder="Enter username"
                autoComplete="username"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400"
              />

            </div>


            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Password
              </label>


              <input
                type="password"
                value={password}
                onChange={(event) =>
                  setPassword(event.target.value)
                }
                placeholder="Enter password"
                autoComplete="current-password"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400"
              />

            </div>


            {error && (

              <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {error}
              </div>

            )}


            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-xl bg-cyan-500 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
            >

              {loading
                ? "AUTHENTICATING..."
                : "SIGN IN"
              }

            </button>

          </form>


          <div className="mt-6 border-t border-slate-800 pt-5">

            <p className="text-center text-xs text-slate-600">
              Authorized Sentinel Security Personnel
            </p>

          </div>

        </div>

      </div>

    </div>

  )

}


/* ============================================================
   MAIN APP
============================================================ */

function App() {

  const [authenticated, setAuthenticated] = useState(
    Boolean(
      localStorage.getItem("sentinel_token")
    )
  )


  const [currentUser, setCurrentUser] = useState(() => {

    try {

      const savedUser =
        localStorage.getItem("sentinel_user")

      return savedUser
        ? JSON.parse(savedUser)
        : null

    } catch {

      return null

    }

  })


  const [alerts, setAlerts] = useState([])
  const [events, setEvents] = useState([])


  const [stats, setStats] = useState({
    total_alerts: 0,
    active_alerts: 0,
    investigating: 0,
    resolved: 0,
    high_severity: 0,
    medium_severity: 0,
    total_events: 0
  })


  const [loading, setLoading] = useState(true)
  const [selectedAlert, setSelectedAlert] = useState(null)

  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState("ALL")

  const [selectedFile, setSelectedFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadMessage, setUploadMessage] = useState("")

  const [threatSummary, setThreatSummary] = useState(null)

  const [websocketConnected, setWebsocketConnected] =
    useState(false)


  /* ============================================================
     AUTHENTICATED FETCH
  ============================================================ */

  const authenticatedFetch = async (
    url,
    options = {}
  ) => {

    const token =
      localStorage.getItem("sentinel_token")


    if (!token) {

      setAuthenticated(false)

      throw new Error(
        "Authentication token missing"
      )

    }


    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`
    }


    const response = await fetch(
      url,
      {
        ...options,
        headers
      }
    )


    if (response.status === 401) {

      localStorage.removeItem(
        "sentinel_token"
      )

      localStorage.removeItem(
        "sentinel_user"
      )

      setAuthenticated(false)
      setCurrentUser(null)

      throw new Error(
        "Authentication expired"
      )

    }


    return response

  }


  /* ============================================================
     LOGIN
  ============================================================ */

  const handleLogin = (user) => {

    setCurrentUser(user)
    setAuthenticated(true)

  }


  /* ============================================================
     LOGOUT
  ============================================================ */

  const handleLogout = () => {

    localStorage.removeItem(
      "sentinel_token"
    )

    localStorage.removeItem(
      "sentinel_user"
    )

    setAuthenticated(false)
    setCurrentUser(null)

    setAlerts([])
    setEvents([])
    setThreatSummary(null)

    setWebsocketConnected(false)

  }


  /* ============================================================
     FETCH DASHBOARD DATA
  ============================================================ */

  const fetchDashboardData = async () => {

    try {

      const [
        alertsResponse,
        statsResponse,
        eventsResponse,
        threatSummaryResponse
      ] = await Promise.all([

        authenticatedFetch(
          `${API}/api/alerts`
        ),

        authenticatedFetch(
          `${API}/api/stats`
        ),

        authenticatedFetch(
          `${API}/api/events`
        ),

        authenticatedFetch(
          `${API}/api/threat-summary`
        )

      ])


      const alertsData =
        await alertsResponse.json()

      const statsData =
        await statsResponse.json()

      const eventsData =
        await eventsResponse.json()

      const threatSummaryData =
        await threatSummaryResponse.json()


      setAlerts(
        alertsData.alerts || []
      )


      setStats(
        statsData
      )


      setEvents(
        eventsData.events || []
      )


      setThreatSummary(
        threatSummaryData.threat_summary || null
      )

    } catch (error) {

      console.error(
        "Failed to fetch Sentinel data:",
        error
      )

    } finally {

      setLoading(false)

    }

  }


  /* ============================================================
     POLLING
  ============================================================ */

  useEffect(() => {

    if (!authenticated) {
      return
    }


    fetchDashboardData()


    const interval = setInterval(
      () => {
        fetchDashboardData()
      },
      5000
    )


    return () => {
      clearInterval(interval)
    }

  }, [authenticated])


  /* ============================================================
     WEBSOCKET - REAL TIME ALERTS
  ============================================================ */

  useEffect(() => {

    if (!authenticated) {
      return
    }


    const websocket =
      new WebSocket(
        "ws://127.0.0.1:8000/ws"
      )


    websocket.onopen = () => {

      console.log(
        "Sentinel WebSocket connected"
      )

      setWebsocketConnected(true)

    }


    websocket.onmessage = (event) => {

      try {

        const data =
          JSON.parse(event.data)


        if (
          data.type === "NEW_ALERT" &&
          data.alert
        ) {

          const newAlert = {
            ...data.alert,

            _id:
              data.alert._id ||
              `live-${Date.now()}`
          }


          setAlerts(
            (currentAlerts) => {

              const exists =
                currentAlerts.some(
                  (alert) =>
                    alert._id === newAlert._id
                )


              if (exists) {
                return currentAlerts
              }


              return [
                newAlert,
                ...currentAlerts
              ]

            }
          )


          setStats(
            (currentStats) => ({

              ...currentStats,

              total_alerts:
                currentStats.total_alerts + 1,

              active_alerts:
                newAlert.status === "DETECTED"
                  ? currentStats.active_alerts + 1
                  : currentStats.active_alerts,

              high_severity:
                newAlert.severity === "HIGH"
                  ? currentStats.high_severity + 1
                  : currentStats.high_severity,

              medium_severity:
                newAlert.severity === "MEDIUM"
                  ? currentStats.medium_severity + 1
                  : currentStats.medium_severity

            })
          )


          console.log(
            "🚨 New Sentinel alert:",
            newAlert
          )

        }

      } catch (error) {

        console.error(
          "WebSocket message error:",
          error
        )

      }

    }


    websocket.onerror = (error) => {

      console.error(
        "Sentinel WebSocket error:",
        error
      )

      setWebsocketConnected(false)

    }


    websocket.onclose = () => {

      console.log(
        "Sentinel WebSocket disconnected"
      )

      setWebsocketConnected(false)

    }


    return () => {

      websocket.close()

    }

  }, [authenticated])


  /* ============================================================
     FILTER ALERTS
  ============================================================ */

  const filteredAlerts =
    alerts.filter(
      (alert) => {

        const searchText =
          search.toLowerCase()


        const matchesSearch =
          alert.alert_type
            ?.toLowerCase()
            .includes(searchText) ||

          alert.source_ip
            ?.toLowerCase()
            .includes(searchText) ||

          alert.username
            ?.toLowerCase()
            .includes(searchText)


        const matchesSeverity =
          severityFilter === "ALL" ||
          alert.severity === severityFilter


        return (
          matchesSearch &&
          matchesSeverity
        )

      }
    )


  /* ============================================================
     FORMAT TIMESTAMP
  ============================================================ */

  const formatTimestamp = (
    timestamp
  ) => {

    if (!timestamp) {
      return "Unknown"
    }


    const date =
      new Date(timestamp)


    if (isNaN(date.getTime())) {
      return timestamp
    }


    return date.toLocaleString()

  }


  /* ============================================================
     ANALYTICS
  ============================================================ */

  const highCount =
    alerts.filter(
      (alert) =>
        alert.severity === "HIGH"
    ).length


  const mediumCount =
    alerts.filter(
      (alert) =>
        alert.severity === "MEDIUM"
    ).length


  const maxSeverity =
    Math.max(
      highCount,
      mediumCount,
      1
    )


  const alertTypeCounts =
    alerts.reduce(
      (counts, alert) => {

        const type =
          alert.alert_type ||
          "Unknown"


        counts[type] =
          (counts[type] || 0) + 1


        return counts

      },
      {}
    )


  const sortedAlertTypes =
    Object.entries(
      alertTypeCounts
    ).sort(
      (a, b) =>
        b[1] - a[1]
    )


  /* ============================================================
     EVENT HELPERS
  ============================================================ */

  const getEventLabel = (
    event
  ) => {

    if (
      event.event_type ===
      "authentication_failure"
    ) {
      return "Authentication Failure"
    }


    if (
      event.event_type ===
      "authentication_success"
    ) {
      return "Authentication Success"
    }


    if (
      event.event_type ===
      "network_connection"
    ) {
      return "Network Connection"
    }


    return (
      event.event_type ||
      "Unknown Event"
    )

  }


  const getEventStatusStyle = (
    event
  ) => {

    if (
      event.event_type ===
      "authentication_failure"
    ) {
      return "bg-red-500/10 text-red-400"
    }


    if (
      event.event_type ===
      "authentication_success"
    ) {
      return "bg-green-500/10 text-green-400"
    }


    if (
      event.event_type ===
      "network_connection"
    ) {
      return "bg-cyan-500/10 text-cyan-400"
    }


    return "bg-slate-500/10 text-slate-400"

  }


  const getAlertStatusStyle = (
    status
  ) => {

    if (status === "DETECTED") {
      return "bg-red-500/10 text-red-400"
    }


    if (status === "INVESTIGATING") {
      return "bg-blue-500/10 text-blue-400"
    }


    if (status === "RESOLVED") {
      return "bg-green-500/10 text-green-400"
    }


    return "bg-slate-500/10 text-slate-400"

  }


  /* ============================================================
     UPDATE ALERT STATUS
  ============================================================ */

  const updateAlertStatus = async (
    alertId,
    newStatus
  ) => {

    if (!alertId) {
      return
    }


    try {

      const response =
        await authenticatedFetch(
          `${API}/api/alerts/${alertId}`,
          {
            method: "PATCH",

            headers: {
              "Content-Type":
                "application/json"
            },

            body: JSON.stringify({
              status: newStatus
            })

          }
        )


      if (!response.ok) {

        throw new Error(
          "Failed to update alert"
        )

      }


      const data =
        await response.json()


      const updatedAlert =
        data.alert


      setAlerts(
        (currentAlerts) =>
          currentAlerts.map(
            (alert) =>
              alert._id === alertId
                ? {
                    ...alert,
                    ...updatedAlert,
                    _id: alertId
                  }
                : alert
          )
      )


      setSelectedAlert(
        (currentAlert) => {

          if (!currentAlert) {
            return null
          }


          if (
            currentAlert._id !==
            alertId
          ) {
            return currentAlert
          }


          return {
            ...currentAlert,
            ...updatedAlert,
            _id: alertId
          }

        }
      )


      fetchDashboardData()

    } catch (error) {

      console.error(
        "Failed to update alert status:",
        error
      )

    }

  }


  /* ============================================================
     LOG ANALYZER
  ============================================================ */

  const analyzeLogFile = async () => {

    if (!selectedFile) {

      setUploadMessage(
        "Please select a log file first."
      )

      return

    }


    setUploading(true)

    setUploadMessage(
      "Analyzing log file..."
    )


    try {

      const fileContent =
        await selectedFile.text()


      const logs =
        fileContent
          .split("\n")
          .map(
            (line) =>
              line.trim()
          )
          .filter(
            (line) =>
              line.length > 0
          )


      const response =
        await authenticatedFetch(
          `${API}/api/analyze`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json"
            },

            body: JSON.stringify({
              logs
            })

          }
        )


      if (!response.ok) {

        throw new Error(
          "Analysis failed"
        )

      }


      const data =
        await response.json()


      setThreatSummary(
        data.threat_summary ||
        null
      )


      setUploadMessage(
        `Analysis complete: ${data.events_processed} events processed, ${data.alerts_detected} alerts detected.`
      )


      setSelectedFile(null)


      setTimeout(
        () => {
          fetchDashboardData()
        },
        500
      )

    } catch (error) {

      console.error(
        "Log analysis failed:",
        error
      )


      setUploadMessage(
        "Failed to analyze log file."
      )

    } finally {

      setUploading(false)

    }

  }


  /* ============================================================
     LOGIN SCREEN
  ============================================================ */

  if (!authenticated) {

    return (
      <Login
        onLogin={handleLogin}
      />
    )

  }


  /* ============================================================
     DASHBOARD
  ============================================================ */

  return (

    <div className="min-h-screen bg-slate-950 text-white">


      {/* ======================================================
          HEADER
      ====================================================== */}

      <header className="border-b border-slate-800 px-8 py-5">

        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">

          <div>

            <h1 className="text-2xl font-bold">
              SENTINEL
            </h1>

            <p className="text-sm text-slate-400">
              Security Operations & Threat Detection Platform
            </p>

          </div>


          <div className="flex items-center gap-5">

            <div className="flex items-center gap-2 text-sm">

              <span
                className={`h-2 w-2 rounded-full ${
                  websocketConnected
                    ? "bg-green-400"
                    : "bg-yellow-400"
                }`}
              />

              <span
                className={
                  websocketConnected
                    ? "text-green-400"
                    : "text-yellow-400"
                }
              >

                {websocketConnected
                  ? "LIVE MONITORING"
                  : "CONNECTING..."
                }

              </span>

            </div>


            <div className="flex items-center gap-3">

              <div className="text-right">

                <p className="text-sm font-medium text-white">
                  {currentUser?.username || "Analyst"}
                </p>

                <p className="text-xs text-slate-500">
                  {currentUser?.role || "analyst"}
                </p>

              </div>


              <button
                onClick={handleLogout}
                className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-medium text-slate-300 transition hover:border-red-900 hover:bg-red-500/10 hover:text-red-400"
              >
                LOGOUT
              </button>

            </div>

          </div>

        </div>

      </header>


      <main className="p-8">


        {/* ====================================================
            SECURITY OVERVIEW
        ==================================================== */}

        <h2 className="mb-6 text-xl font-semibold">
          Security Overview
        </h2>


        <div className="grid grid-cols-1 gap-5 md:grid-cols-4">


          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

            <p className="text-sm text-slate-400">
              Total Alerts
            </p>

            <p className="mt-2 text-3xl font-bold">
              {stats.total_alerts}
            </p>

          </div>


          <div className="rounded-xl border border-red-900 bg-slate-900 p-6">

            <p className="text-sm text-slate-400">
              Active Alerts
            </p>

            <p className="mt-2 text-3xl font-bold text-red-400">
              {stats.active_alerts}
            </p>

          </div>


          <div className="rounded-xl border border-blue-900 bg-slate-900 p-6">

            <p className="text-sm text-slate-400">
              Investigating
            </p>

            <p className="mt-2 text-3xl font-bold text-blue-400">
              {stats.investigating}
            </p>

          </div>


          <div className="rounded-xl border border-green-900 bg-slate-900 p-6">

            <p className="text-sm text-slate-400">
              Resolved
            </p>

            <p className="mt-2 text-3xl font-bold text-green-400">
              {stats.resolved}
            </p>

          </div>

        </div>


        {/* ====================================================
            SECURITY ANALYTICS
        ==================================================== */}

        <section className="mt-8">

          <h2 className="mb-5 text-xl font-semibold">
            Security Analytics
          </h2>


          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">


            {/* ALERT SEVERITY */}

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

              <h3 className="text-lg font-semibold">
                Alert Severity
              </h3>

              <p className="mt-1 text-sm text-slate-400">
                Distribution of detected alert severity
              </p>


              <div className="mt-8 space-y-6">

                <div>

                  <div className="mb-2 flex justify-between text-sm">

                    <span className="text-slate-300">
                      HIGH
                    </span>

                    <span className="text-red-400">
                      {highCount}
                    </span>

                  </div>


                  <div className="h-3 overflow-hidden rounded-full bg-slate-800">

                    <div
                      className="h-full rounded-full bg-red-500 transition-all duration-500"
                      style={{
                        width:
                          `${(highCount / maxSeverity) * 100}%`
                      }}
                    />

                  </div>

                </div>


                <div>

                  <div className="mb-2 flex justify-between text-sm">

                    <span className="text-slate-300">
                      MEDIUM
                    </span>

                    <span className="text-yellow-400">
                      {mediumCount}
                    </span>

                  </div>


                  <div className="h-3 overflow-hidden rounded-full bg-slate-800">

                    <div
                      className="h-full rounded-full bg-yellow-500 transition-all duration-500"
                      style={{
                        width:
                          `${(mediumCount / maxSeverity) * 100}%`
                      }}
                    />

                  </div>

                </div>

              </div>

            </div>


            {/* ALERT TYPES */}

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

              <h3 className="text-lg font-semibold">
                Alert Types
              </h3>

              <p className="mt-1 text-sm text-slate-400">
                Detected threat categories
              </p>


              {sortedAlertTypes.length === 0 ? (

                <div className="mt-8 text-sm text-slate-500">
                  No alert data available.
                </div>

              ) : (

                <div className="mt-6 space-y-4">

                  {sortedAlertTypes.map(
                    ([type, count]) => {

                      const maximum =
                        sortedAlertTypes[0][1]


                      return (

                        <div key={type}>

                          <div className="mb-2 flex items-center justify-between">

                            <span className="text-sm text-slate-300">
                              {type}
                            </span>

                            <span className="text-sm font-medium text-cyan-400">
                              {count}
                            </span>

                          </div>


                          <div className="h-2 overflow-hidden rounded-full bg-slate-800">

                            <div
                              className="h-full rounded-full bg-cyan-500 transition-all duration-500"
                              style={{
                                width:
                                  `${(count / maximum) * 100}%`
                              }}
                            />

                          </div>

                        </div>

                      )

                    }
                  )}

                </div>

              )}

            </div>

          </div>

        </section>


        {/* ====================================================
            LOG ANALYZER
        ==================================================== */}

        <section className="mt-8">

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-6">

              <h2 className="text-lg font-semibold">
                Log Analyzer
              </h2>

              <p className="mt-1 text-sm text-slate-400">
                Upload security logs and run them through the Sentinel detection engine.
              </p>

            </div>


            <div className="flex flex-col gap-4 md:flex-row md:items-center">

              <label className="flex-1 cursor-pointer rounded-lg border border-dashed border-slate-700 bg-slate-950 px-4 py-4 transition hover:border-slate-500">

                <input
                  type="file"
                  accept=".log,.txt"
                  className="hidden"
                  onChange={(event) => {

                    setSelectedFile(
                      event.target.files[0] ||
                      null
                    )

                    setUploadMessage("")

                  }}
                />


                <div className="text-sm">

                  {selectedFile ? (

                    <span className="text-white">
                      {selectedFile.name}
                    </span>

                  ) : (

                    <span className="text-slate-500">
                      Click to choose a .log or .txt file
                    </span>

                  )}

                </div>

              </label>


              <button
                onClick={analyzeLogFile}
                disabled={uploading}
                className="rounded-lg bg-cyan-500 px-6 py-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
              >

                {uploading
                  ? "ANALYZING..."
                  : "ANALYZE LOG"
                }

              </button>

            </div>


            {uploadMessage && (

              <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-400">
                {uploadMessage}
              </div>

            )}

          </div>

        </section>


        {/* ====================================================
            THREAT ANALYSIS
        ==================================================== */}

        {threatSummary && (

          <section className="mt-8">

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">

                <div>

                  <h2 className="text-lg font-semibold">
                    Threat Analysis
                  </h2>

                  <p className="mt-1 text-sm text-slate-400">
                    Automated security analysis generated by Sentinel
                  </p>

                </div>


                <span
                  className={`rounded-lg px-4 py-2 text-sm font-semibold ${
                    threatSummary.threat_level === "HIGH"
                      ? "bg-red-500/10 text-red-400"
                      : threatSummary.threat_level === "MEDIUM"
                      ? "bg-yellow-500/10 text-yellow-400"
                      : "bg-green-500/10 text-green-400"
                  }`}
                >

                  THREAT LEVEL:{" "}
                  {threatSummary.threat_level}

                </span>

              </div>


              <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950 p-5">

                <p className="text-sm font-medium text-slate-300">
                  Analyst Summary
                </p>

                <p className="mt-2 text-sm leading-6 text-slate-400">
                  {threatSummary.summary}
                </p>


                {threatSummary.generated_at && (

                  <p className="mt-3 text-xs text-slate-600">

                    Generated:{" "}

                    {formatTimestamp(
                      threatSummary.generated_at
                    )}

                  </p>

                )}

              </div>


              <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-2">


                {/* DETECTED THREATS */}

                <div className="rounded-lg border border-slate-800 bg-slate-950 p-5">

                  <h3 className="font-medium">
                    Detected Threats
                  </h3>


                  <div className="mt-4 space-y-3">

                    {threatSummary.detected_threats?.length > 0 ? (

                      threatSummary.detected_threats.map(
                        (threat, index) => (

                          <div
                            key={index}
                            className="flex gap-3 rounded-lg border border-red-900/50 bg-red-500/5 p-3"
                          >

                            <span className="mt-1 h-2 w-2 shrink-0 rounded-full bg-red-400"></span>

                            <p className="text-sm text-slate-300">
                              {threat}
                            </p>

                          </div>

                        )
                      )

                    ) : (

                      <p className="text-sm text-slate-500">
                        No specific threats detected.
                      </p>

                    )}

                  </div>

                </div>


                {/* RECOMMENDED ACTIONS */}

                <div className="rounded-lg border border-slate-800 bg-slate-950 p-5">

                  <h3 className="font-medium">
                    Recommended Actions
                  </h3>


                  <div className="mt-4 space-y-3">

                    {threatSummary.recommended_actions?.length > 0 ? (

                      threatSummary.recommended_actions.map(
                        (action, index) => (

                          <div
                            key={index}
                            className="flex gap-3 rounded-lg border border-cyan-900/50 bg-cyan-500/5 p-3"
                          >

                            <span className="mt-1 text-cyan-400">
                              →
                            </span>

                            <p className="text-sm text-slate-300">
                              {action}
                            </p>

                          </div>

                        )
                      )

                    ) : (

                      <p className="text-sm text-slate-500">
                        No recommended actions available.
                      </p>

                    )}

                  </div>

                </div>

              </div>

            </div>

          </section>

        )}


        {/* ====================================================
            EVENT TIMELINE
        ==================================================== */}

        <section className="mt-8">

          <div className="rounded-xl border border-slate-800 bg-slate-900">

            <div className="border-b border-slate-800 p-6">

              <div className="flex items-center justify-between">

                <div>

                  <h2 className="text-lg font-semibold">
                    Event Timeline
                  </h2>

                  <p className="mt-1 text-sm text-slate-400">
                    Recent security events collected by Sentinel
                  </p>

                </div>


                <span
                  className={`rounded-md px-3 py-1 text-xs ${
                    websocketConnected
                      ? "bg-green-500/10 text-green-400"
                      : "bg-yellow-500/10 text-yellow-400"
                  }`}
                >

                  {websocketConnected
                    ? "LIVE"
                    : "CONNECTING"
                  }

                </span>

              </div>

            </div>


            {events.length === 0 ? (

              <div className="p-8 text-center text-slate-400">
                No events available.
              </div>

            ) : (

              <div className="relative p-6">

                <div className="absolute bottom-6 left-10 top-6 w-px bg-slate-800"></div>


                <div className="space-y-7">

                  {events.map(
                    (event, index) => (

                      <div
                        key={index}
                        className="relative flex gap-5"
                      >

                        <div className="relative z-10 mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-900">

                          <span
                            className={`h-2 w-2 rounded-full ${
                              event.event_type ===
                              "authentication_failure"
                                ? "bg-red-400"
                                : event.event_type ===
                                  "authentication_success"
                                ? "bg-green-400"
                                : "bg-cyan-400"
                            }`}
                          />

                        </div>


                        <div className="flex-1 rounded-lg border border-slate-800 bg-slate-950 p-4">

                          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">

                            <div>

                              <div className="flex flex-wrap items-center gap-3">

                                <p className="font-medium">
                                  {getEventLabel(event)}
                                </p>


                                <span
                                  className={`rounded-md px-2 py-1 text-xs ${getEventStatusStyle(event)}`}
                                >
                                  {event.status || "EVENT"}
                                </span>

                              </div>


                              <div className="mt-2 flex flex-wrap gap-4 text-sm text-slate-400">

                                {event.source_ip && (

                                  <span>
                                    Source:{" "}
                                    {event.source_ip}
                                  </span>

                                )}


                                {event.username && (

                                  <span>
                                    User:{" "}
                                    {event.username}
                                  </span>

                                )}


                                {event.destination_port && (

                                  <span>
                                    Port:{" "}
                                    {event.destination_port}
                                  </span>

                                )}

                              </div>

                            </div>


                            <div className="text-xs text-slate-500">

                              {formatTimestamp(
                                event.timestamp
                              )}

                            </div>

                          </div>


                          {event.message && (

                            <div className="mt-3 rounded-md bg-slate-900 px-3 py-2">

                              <p className="font-mono text-xs text-slate-500">
                                {event.message}
                              </p>

                            </div>

                          )}

                        </div>

                      </div>

                    )
                  )}

                </div>

              </div>

            )}

          </div>

        </section>


        {/* ====================================================
            SECURITY ALERTS
        ==================================================== */}

        <section className="mt-8">

          <div className="rounded-xl border border-slate-800 bg-slate-900">

            <div className="border-b border-slate-800 p-6">

              <h2 className="text-lg font-semibold">
                Security Alerts
              </h2>

              <p className="mt-1 text-sm text-slate-400">
                Detected threats from the Sentinel detection engine
              </p>

            </div>


            {/* SEARCH + FILTER */}

            <div className="flex flex-col gap-4 border-b border-slate-800 p-6 md:flex-row">

              <input
                type="text"
                placeholder="Search IP, alert type or username..."
                value={search}
                onChange={(event) =>
                  setSearch(event.target.value)
                }
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-slate-500"
              />


              <select
                value={severityFilter}
                onChange={(event) =>
                  setSeverityFilter(event.target.value)
                }
                className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none"
              >

                <option value="ALL">
                  All Severities
                </option>

                <option value="HIGH">
                  High
                </option>

                <option value="MEDIUM">
                  Medium
                </option>

              </select>

            </div>


            {/* ALERT LIST */}

            {loading ? (

              <div className="p-6 text-slate-400">
                Loading alerts...
              </div>

            ) : filteredAlerts.length === 0 ? (

              <div className="p-8 text-center text-slate-400">
                No alerts match your search or filter.
              </div>

            ) : (

              <div className="divide-y divide-slate-800">

                {filteredAlerts.map(
                  (alert, index) => (

                    <button
                      key={
                        alert._id ||
                        index
                      }
                      onClick={() =>
                        setSelectedAlert(alert)
                      }
                      className="flex w-full items-center justify-between p-6 text-left transition hover:bg-slate-800/50"
                    >

                      <div>

                        <div className="flex flex-wrap items-center gap-3">

                          <p className="font-medium">
                            {alert.alert_type}
                          </p>


                          <span
                            className={`rounded-md px-2 py-1 text-xs ${
                              alert.severity === "HIGH"
                                ? "bg-red-500/10 text-red-400"
                                : "bg-yellow-500/10 text-yellow-400"
                            }`}
                          >
                            {alert.severity}
                          </span>


                          <span
                            className={`rounded-md px-2 py-1 text-xs ${getAlertStatusStyle(
                              alert.status
                            )}`}
                          >
                            {alert.status ||
                              "DETECTED"}
                          </span>

                        </div>


                        <p className="mt-2 text-sm text-slate-400">
                          Source:{" "}
                          {alert.source_ip}
                        </p>


                        <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-500">

                          {alert.username && (

                            <span>
                              User:{" "}
                              {alert.username}
                            </span>

                          )}


                          <span>
                            Detected:{" "}
                            {formatTimestamp(
                              alert.detected_at
                            )}
                          </span>

                        </div>

                      </div>


                      <span className="text-slate-500">
                        →
                      </span>

                    </button>

                  )
                )}

              </div>

            )}

          </div>

        </section>


        {/* ====================================================
            ALERT DETAILS MODAL
        ==================================================== */}

        {selectedAlert && (

          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
            onClick={() =>
              setSelectedAlert(null)
            }
          >

            <div
              className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900"
              onClick={(event) =>
                event.stopPropagation()
              }
            >


              {/* MODAL HEADER */}

              <div className="flex items-center justify-between border-b border-slate-800 p-6">

                <div>

                  <div className="flex flex-wrap items-center gap-3">

                    <h2 className="text-xl font-semibold">
                      {selectedAlert.alert_type}
                    </h2>


                    <span
                      className={`rounded-md px-2 py-1 text-xs ${getAlertStatusStyle(
                        selectedAlert.status
                      )}`}
                    >
                      {selectedAlert.status ||
                        "DETECTED"}
                    </span>

                  </div>


                  <p className="mt-1 text-sm text-slate-400">
                    Security Alert Details
                  </p>

                </div>


                <button
                  onClick={() =>
                    setSelectedAlert(null)
                  }
                  className="text-slate-400 hover:text-white"
                >
                  ✕
                </button>

              </div>


              {/* MODAL CONTENT */}

              <div className="max-h-[80vh] space-y-5 overflow-y-auto p-6">


                <div>

                  <p className="text-sm text-slate-400">
                    Severity
                  </p>

                  <p
                    className={`mt-1 font-medium ${
                      selectedAlert.severity ===
                      "HIGH"
                        ? "text-red-400"
                        : "text-yellow-400"
                    }`}
                  >
                    {selectedAlert.severity}
                  </p>

                </div>


                <div>

                  <p className="text-sm text-slate-400">
                    Source IP
                  </p>

                  <p className="mt-1 font-medium">
                    {selectedAlert.source_ip}
                  </p>

                </div>


                {selectedAlert.username && (

                  <div>

                    <p className="text-sm text-slate-400">
                      Username
                    </p>

                    <p className="mt-1 font-medium">
                      {selectedAlert.username}
                    </p>

                  </div>

                )}


                {selectedAlert.failed_attempts && (

                  <div>

                    <p className="text-sm text-slate-400">
                      Failed Attempts
                    </p>

                    <p className="mt-1 font-medium">
                      {selectedAlert.failed_attempts}
                    </p>

                  </div>

                )}


                {selectedAlert.window_minutes && (

                  <div>

                    <p className="text-sm text-slate-400">
                      Detection Window
                    </p>

                    <p className="mt-1 font-medium">
                      {selectedAlert.window_minutes} minutes
                    </p>

                  </div>

                )}


                {selectedAlert.ports_scanned && (

                  <div>

                    <p className="text-sm text-slate-400">
                      Ports Scanned
                    </p>

                    <p className="mt-1 font-medium">
                      {selectedAlert.ports_scanned}
                    </p>

                  </div>

                )}


                {selectedAlert.first_seen && (

                  <div>

                    <p className="text-sm text-slate-400">
                      First Seen
                    </p>

                    <p className="mt-1 font-medium">
                      {formatTimestamp(
                        selectedAlert.first_seen
                      )}
                    </p>

                  </div>

                )}


                {selectedAlert.last_seen && (

                  <div>

                    <p className="text-sm text-slate-400">
                      Last Seen
                    </p>

                    <p className="mt-1 font-medium">
                      {formatTimestamp(
                        selectedAlert.last_seen
                      )}
                    </p>

                  </div>

                )}


                {selectedAlert.timestamp && (

                  <div>

                    <p className="text-sm text-slate-400">
                      Event Timestamp
                    </p>

                    <p className="mt-1 font-medium">
                      {formatTimestamp(
                        selectedAlert.timestamp
                      )}
                    </p>

                  </div>

                )}


                <div>

                  <p className="text-sm text-slate-400">
                    Detected At
                  </p>

                  <p className="mt-1 font-medium text-cyan-400">
                    {formatTimestamp(
                      selectedAlert.detected_at
                    )}
                  </p>

                </div>


                <div>

                  <p className="text-sm text-slate-400">
                    Current Status
                  </p>

                  <p
                    className={`mt-1 font-medium ${
                      selectedAlert.status ===
                      "RESOLVED"
                        ? "text-green-400"
                        : selectedAlert.status ===
                          "INVESTIGATING"
                        ? "text-blue-400"
                        : "text-red-400"
                    }`}
                  >
                    {selectedAlert.status ||
                      "DETECTED"}
                  </p>

                </div>


                {/* ACTIONS */}

                <div className="border-t border-slate-800 pt-5">

                  <p className="mb-3 text-sm text-slate-400">
                    Investigation Actions
                  </p>


                  <div className="flex flex-col gap-3 sm:flex-row">

                    <button
                      onClick={() =>
                        updateAlertStatus(
                          selectedAlert._id,
                          "INVESTIGATING"
                        )
                      }
                      disabled={
                        selectedAlert.status ===
                        "INVESTIGATING"
                      }
                      className="flex-1 rounded-lg border border-blue-900 bg-blue-500/10 px-4 py-3 text-sm font-medium text-blue-400 transition hover:bg-blue-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      START INVESTIGATION
                    </button>


                    <button
                      onClick={() =>
                        updateAlertStatus(
                          selectedAlert._id,
                          "RESOLVED"
                        )
                      }
                      disabled={
                        selectedAlert.status ===
                        "RESOLVED"
                      }
                      className="flex-1 rounded-lg border border-green-900 bg-green-500/10 px-4 py-3 text-sm font-medium text-green-400 transition hover:bg-green-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      RESOLVE ALERT
                    </button>

                  </div>

                </div>

              </div>

            </div>

          </div>

        )}

      </main>

    </div>

  )

}


export default App