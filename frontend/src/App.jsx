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
  const [alertActivity, setAlertActivity] = useState([])
  const [activityLoading, setActivityLoading] = useState(false)
  const [analystNote, setAnalystNote] = useState("")
  const [noteSubmitting, setNoteSubmitting] = useState(false)
  const [noteMessage, setNoteMessage] = useState("")
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState("ALL")
  const [statusFilter, setStatusFilter] = useState("ALL")

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
   WEBSOCKET - JWT AUTHENTICATED REAL TIME ALERTS
   AUTO RECONNECT
============================================================ */

useEffect(() => {

  if (!authenticated) {

    setWebsocketConnected(false)

    return

  }


  const token =
    localStorage.getItem(
      "sentinel_token"
    )


  if (!token) {

    console.error(
      "WebSocket authentication token missing"
    )

    setWebsocketConnected(false)

    return

  }


  let websocket = null
  let reconnectTimer = null
  let reconnectAttempts = 0
  let isClosing = false


  const connectWebSocket = () => {

    if (isClosing) {
      return
    }


    console.log(
      `Connecting to Sentinel WebSocket... attempt ${
        reconnectAttempts + 1
      }`
    )


    websocket =
      new WebSocket(
        "ws://127.0.0.1:8000/ws"
      )


    /* ========================================================
       CONNECTION OPEN
    ======================================================== */

    websocket.onopen = () => {

      console.log(
        "WebSocket connection established"
      )


      /*
      Send JWT to the backend.

      The backend will validate this token
      before allowing live alert traffic.
      */

      websocket.send(
        JSON.stringify({
          type: "AUTH",
          token: token
        })
      )

    }


    /* ========================================================
       MESSAGE HANDLER
    ======================================================== */

    websocket.onmessage = (event) => {

      try {

        const data =
          JSON.parse(
            event.data
          )


        /* ==================================================
           AUTHENTICATION SUCCESS
        ================================================== */

        if (
          data.type ===
          "AUTHENTICATED"
        ) {

          console.log(
            `Sentinel WebSocket authenticated as ${data.username}`
          )


          reconnectAttempts = 0


          setWebsocketConnected(
            true
          )


          return

        }


        /* ==================================================
           NEW SECURITY ALERT
        ================================================== */

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


          /*
          Prevent duplicate live alerts.
          */

          setAlerts(
            (currentAlerts) => {

              const exists =
                currentAlerts.some(
                  (alert) =>
                    alert._id ===
                    newAlert._id
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


          /*
          Update dashboard statistics
          immediately without waiting
          for the polling request.
          */

          setStats(
            (currentStats) => ({

              ...currentStats,

              total_alerts:
                currentStats.total_alerts + 1,


              active_alerts:
                newAlert.status ===
                "DETECTED"

                  ? currentStats.active_alerts + 1

                  : currentStats.active_alerts,


              high_severity:
                newAlert.severity ===
                "HIGH"

                  ? currentStats.high_severity + 1

                  : currentStats.high_severity,


              medium_severity:
                newAlert.severity ===
                "MEDIUM"

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


    /* ========================================================
       WEBSOCKET ERROR
    ======================================================== */

    websocket.onerror = (
      error
    ) => {

      console.error(
        "Sentinel WebSocket error:",
        error
      )


      setWebsocketConnected(
        false
      )

    }


    /* ========================================================
       WEBSOCKET CLOSED
    ======================================================== */

    websocket.onclose = (
  event
) => {

  console.log(
    "Sentinel WebSocket disconnected",
    event.code,
    event.reason
  )

  setWebsocketConnected(false)

  if (isClosing) {
    return
  }

  if (
    event.code === 1008 &&
    event.reason ===
      "Invalid or expired token"
  ) {

    console.warn(
      "Sentinel session expired. Returning to login."
    )

    localStorage.removeItem(
      "sentinel_token"
    )

    localStorage.removeItem(
      "sentinel_user"
    )

    setAuthenticated(false)
    setCurrentUser(null)

    return
  }

  reconnectAttempts += 1

  const delay =
    Math.min(
      1000 *
        2 **
          (reconnectAttempts - 1),
      30000
    )

  console.log(
    `Reconnecting to Sentinel WebSocket in ${
      delay / 1000
    }s...`
  )

  reconnectTimer =
    setTimeout(
      connectWebSocket,
      delay
    )
}

  }


  /* ============================================================
     START CONNECTION
  ============================================================ */

  connectWebSocket()


  /* ============================================================
     CLEANUP
  ============================================================ */

  return () => {

    isClosing = true


    setWebsocketConnected(
      false
    )


    if (reconnectTimer) {

      clearTimeout(
        reconnectTimer
      )

    }


    if (websocket) {

      websocket.onclose = null

      websocket.onerror = null

      websocket.close()

    }

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


      const matchesStatus =
        statusFilter === "ALL" ||
        alert.status === statusFilter


      return (
        matchesSearch &&
        matchesSeverity &&
        matchesStatus
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

  let normalizedTimestamp = timestamp

  if (
    typeof timestamp === "object" &&
    timestamp !== null
  ) {
    if (timestamp.$date) {
      normalizedTimestamp =
        timestamp.$date
    } else {
      return "Unknown"
    }
  }

  const date =
    new Date(normalizedTimestamp)

  if (isNaN(date.getTime())) {
    return "Unknown"
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

    /*
     * Refresh the investigation timeline
     * after the status has been changed.
     */
    await fetchAlertActivity(
      alertId
    )

    await fetchDashboardData()

  } catch (error) {

    console.error(
      "Failed to update alert status:",
      error
    )

  }
}
/* ============================================================
   FETCH ALERT ACTIVITY
============================================================ */

const fetchAlertActivity = async (
  alertId
) => {
  if (!alertId) {
    return
  }

  setActivityLoading(true)
  setAlertActivity([])

  try {
    const response =
      await authenticatedFetch(
        `${API}/api/alerts/${alertId}/activity`
      )

    if (!response.ok) {
      throw new Error(
        "Failed to fetch alert activity"
      )
    }

    const data =
      await response.json()

    setAlertActivity(
      data.activity || []
    )

  } catch (error) {

    console.error(
      "Failed to fetch alert activity:",
      error
    )

    setAlertActivity([])

  } finally {

    setActivityLoading(false)

  }
}
/* ============================================================
   ADD ANALYST NOTE
============================================================ */

const addAnalystNote = async () => {
  if (!selectedAlert?._id) {
    return
  }

  const note = analystNote.trim()

  if (!note) {
    setNoteMessage("Enter a note first.")
    return
  }

  if (note.length > 1000) {
    setNoteMessage(
      "Note cannot exceed 1000 characters."
    )
    return
  }

  setNoteSubmitting(true)
  setNoteMessage("")

  try {
    const response =
      await authenticatedFetch(
        `${API}/api/alerts/${selectedAlert._id}/notes`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify({
            note
          })
        }
      )

    const data =
      await response.json()

    if (!response.ok) {
      throw new Error(
        data.detail ||
        "Failed to add note"
      )
    }

    setAnalystNote("")
    setNoteMessage(
      "Investigation note added."
    )

    await fetchAlertActivity(
      selectedAlert._id
    )

  } catch (error) {

    console.error(
      "Failed to add analyst note:",
      error
    )

    setNoteMessage(
      error.message ||
      "Failed to add investigation note."
    )

  } finally {

    setNoteSubmitting(false)

  }
}
{/* ============================================================
   LOG ANALYZER
============================================================ */}

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


          {/* ==================================================
              WEBSOCKET STATUS
          ================================================== */}

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
                : "RECONNECTING..."
              }

            </span>

          </div>


          {/* ==================================================
              USER
          ================================================== */}

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


        {/* TOTAL ALERTS */}

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

          <p className="text-sm text-slate-400">
            Total Alerts
          </p>

          <p className="mt-2 text-3xl font-bold">
            {stats.total_alerts}
          </p>

        </div>


        {/* ACTIVE ALERTS */}

        <div className="rounded-xl border border-red-900 bg-slate-900 p-6">

          <p className="text-sm text-slate-400">
            Active Alerts
          </p>

          <p className="mt-2 text-3xl font-bold text-red-400">
            {stats.active_alerts}
          </p>

        </div>


        {/* INVESTIGATING */}

        <div className="rounded-xl border border-blue-900 bg-slate-900 p-6">

          <p className="text-sm text-slate-400">
            Investigating
          </p>

          <p className="mt-2 text-3xl font-bold text-blue-400">
            {stats.investigating}
          </p>

        </div>


        {/* RESOLVED */}

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


          {/* ==================================================
              ALERT SEVERITY
          ================================================== */}

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

            <h3 className="text-lg font-semibold">
              Alert Severity
            </h3>

            <p className="mt-1 text-sm text-slate-400">
              Distribution of detected alert severity
            </p>


            <div className="mt-8 space-y-6">


              {/* HIGH */}

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


              {/* MEDIUM */}

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


          {/* ==================================================
              ALERT TYPES
          ================================================== */}

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

{/* ============================================================
   THREAT SUMMARY
============================================================ */}

<section className="mt-8">
  <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

    <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">

      <div>

        <h2 className="text-xl font-semibold">
          Threat Intelligence Summary
        </h2>

        <p className="mt-1 text-sm text-slate-400">
          Automated analysis of detected security activity
        </p>

      </div>


      {threatSummary && (

        <div
          className={`rounded-lg border px-4 py-2 text-sm font-semibold ${
            threatSummary.threat_level === "HIGH"
              ? "border-red-500/30 bg-red-500/10 text-red-400"
              : threatSummary.threat_level === "MEDIUM"
                ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
                : "border-green-500/30 bg-green-500/10 text-green-400"
          }`}
        >

          THREAT LEVEL:{" "}
          {threatSummary.threat_level}

        </div>

      )}

    </div>


    {!threatSummary ? (

      <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950 p-5 text-sm text-slate-500">

        No threat summary available yet.

      </div>

    ) : (

      <div className="mt-6 space-y-6">


        {/* SUMMARY */}

        <div>

          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
            Summary
          </p>

          <p className="text-sm leading-6 text-slate-300">
            {threatSummary.summary}
          </p>

        </div>


        {/* DETECTED THREATS */}

        {threatSummary.detected_threats?.length > 0 && (

          <div>

            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Detected Threats
            </p>


            <div className="space-y-2">

              {threatSummary.detected_threats.map(
                (threat, index) => (

                  <div
                    key={index}
                    className="rounded-lg border border-red-500/10 bg-red-500/5 px-4 py-3 text-sm text-slate-300"
                  >

                    <span className="mr-2 text-red-400">
                      ●
                    </span>

                    {threat}

                  </div>

                )
              )}

            </div>

          </div>

        )}


        {/* RECOMMENDED ACTIONS */}

        {threatSummary.recommended_actions?.length > 0 && (

          <div>

            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Recommended Actions
            </p>


            <div className="space-y-2">

              {threatSummary.recommended_actions.map(
                (action, index) => (

                  <div
                    key={index}
                    className="rounded-lg border border-cyan-500/10 bg-cyan-500/5 px-4 py-3 text-sm text-slate-300"
                  >

                    <span className="mr-2 text-cyan-400">
                      →
                    </span>

                    {action}

                  </div>

                )
              )}

            </div>

          </div>

        )}

      </div>

    )}

  </div>

</section>


{/* ============================================================
   LOG ANALYZER
============================================================ */}

<section className="mt-8">

  <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

    <div className="mb-6">

      <h2 className="text-xl font-semibold">
        Security Log Analyzer
      </h2>

      <p className="mt-1 text-sm text-slate-400">
        Upload a security log file for threat detection
        and automated analysis.
      </p>

    </div>


    <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950 p-8">

      <div className="text-center">

        <div className="mb-4 text-4xl">
          📄
        </div>


        <p className="text-sm font-medium text-slate-300">
          Select Security Log File
        </p>


        <p className="mt-1 text-xs text-slate-500">
          Supported format: plain text log files
        </p>


        <div className="mt-6 flex flex-col items-center gap-4">


          <label className="cursor-pointer rounded-lg border border-slate-700 bg-slate-900 px-5 py-3 text-sm font-medium text-slate-300 transition hover:border-cyan-500 hover:text-cyan-400">

            SELECT LOG FILE

            <input
              type="file"
              accept=".log,.txt"
              className="hidden"
              onChange={(event) => {

                const file =
                  event.target.files?.[0]

                setSelectedFile(
                  file || null
                )

                setUploadMessage("")

              }}
            />

          </label>


          {selectedFile && (

            <div className="text-sm text-cyan-400">

              Selected:
              {" "}
              {selectedFile.name}

            </div>

          )}


          <button
            type="button"
            onClick={analyzeLogFile}
            disabled={
              !selectedFile ||
              uploading
            }
            className="rounded-lg bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
          >

            {uploading
              ? "ANALYZING..."
              : "ANALYZE LOG"
            }

          </button>


          {uploadMessage && (

            <div
              className={`rounded-lg border px-4 py-3 text-sm ${
                uploadMessage.startsWith(
                  "Analysis complete"
                )
                  ? "border-green-500/20 bg-green-500/10 text-green-400"
                  : uploadMessage.startsWith(
                      "Analyzing"
                    )
                    ? "border-cyan-500/20 bg-cyan-500/10 text-cyan-400"
                    : "border-red-500/20 bg-red-500/10 text-red-400"
              }`}
            >

              {uploadMessage}

            </div>

          )}

        </div>

      </div>

    </div>

  </div>

</section>


{/* ============================================================
   ALERTS
============================================================ */}

<section className="mt-8">

  <div className="rounded-xl border border-slate-800 bg-slate-900">


    {/* ALERT HEADER */}

    <div className="border-b border-slate-800 p-6">

      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">

        <div>

          <h2 className="text-xl font-semibold">
            Security Alerts
          </h2>

          <p className="mt-1 text-sm text-slate-400">
            Detected security incidents and threat activity
          </p>

        </div>


        {/* FILTERS */}

        <div className="flex flex-col gap-3 sm:flex-row">


          {/* SEARCH */}

          <input
            type="text"
            value={search}
            onChange={(event) =>
              setSearch(
                event.target.value
              )
            }
            placeholder="Search alerts..."
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-400"
          />


          {/* SEVERITY */}

          <select
            value={severityFilter}
            onChange={(event) =>
              setSeverityFilter(
                event.target.value
              )
            }
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm text-slate-300 outline-none focus:border-cyan-400"
          >

            <option value="ALL">
              ALL SEVERITIES
            </option>

            <option value="HIGH">
              HIGH
            </option>

            <option value="MEDIUM">
              MEDIUM
            </option>

            <option value="LOW">
              LOW
            </option>

          </select>
          {/* STATUS */}

<select
  value={statusFilter}
  onChange={(event) =>
    setStatusFilter(
      event.target.value
    )
  }
  className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm text-slate-300 outline-none focus:border-cyan-400"
>

  <option value="ALL">
    ALL STATUS
  </option>

  <option value="DETECTED">
    DETECTED
  </option>

  <option value="INVESTIGATING">
    INVESTIGATING
  </option>

  <option value="RESOLVED">
    RESOLVED
  </option>

</select>

        </div>

      </div>

    </div>


    {/* ALERT LIST */}

    <div className="divide-y divide-slate-800">

      {filteredAlerts.length === 0 ? (

        <div className="p-8 text-center text-sm text-slate-500">

          No alerts match the current filters.

        </div>

      ) : (

        filteredAlerts.map(
          (alert) => (

            <div
              key={alert._id}
              className="p-6 transition hover:bg-slate-950/50"
            >

              <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">


                {/* ALERT INFORMATION */}

                <div className="min-w-0 flex-1">

                  <div className="flex flex-wrap items-center gap-3">

                    <h3 className="font-semibold text-white">

                      {alert.alert_type ||
                        "Unknown Alert"}

                    </h3>


                    <span
                      className={`rounded-full px-3 py-1 text-xs font-semibold ${
                        alert.severity === "HIGH"
                          ? "bg-red-500/10 text-red-400"
                          : alert.severity === "MEDIUM"
                            ? "bg-yellow-500/10 text-yellow-400"
                            : "bg-green-500/10 text-green-400"
                      }`}
                    >

                      {alert.severity}

                    </span>


                    <span
                      className={`rounded-full px-3 py-1 text-xs font-semibold ${getAlertStatusStyle(
                        alert.status
                      )}`}
                    >

                      {alert.status}

                    </span>

                  </div>


                  <div className="mt-4 grid grid-cols-1 gap-3 text-sm md:grid-cols-3">

                    <div>

                      <p className="text-xs text-slate-600">
                        SOURCE IP
                      </p>

                      <p className="mt-1 font-mono text-slate-300">
                        {alert.source_ip ||
                          "Unknown"}
                      </p>

                    </div>


                    <div>

                      <p className="text-xs text-slate-600">
                        DETECTED
                      </p>

                      <p className="mt-1 text-slate-300">
                        {formatTimestamp(
                          alert.detected_at ||
                          alert.timestamp
                        )}
                      </p>

                    </div>


                    <div>

                      <p className="text-xs text-slate-600">
                        ALERT ID
                      </p>

                      <p className="mt-1 truncate font-mono text-xs text-slate-500">
                        {alert._id}
                      </p>

                    </div>

                  </div>

                </div>


                {/* ACTIONS */}

                <div className="flex flex-wrap gap-2">


                  <button
                    type="button"
                    onClick={() => {
                       setSelectedAlert(alert)
                       fetchAlertActivity(alert._id)
                    }}
                    className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-xs font-medium text-slate-300 transition hover:border-cyan-500 hover:text-cyan-400"
                  >
                    VIEW
                  </button>


                 {alert.status === "DETECTED" && (

  <button
    type="button"
    onClick={() =>
      updateAlertStatus(
        alert._id,
        "INVESTIGATING"
      )
    }
    className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-xs font-medium text-yellow-400 transition hover:bg-yellow-500/20"
  >
    START INVESTIGATION
  </button>

)}


{alert.status === "INVESTIGATING" && (

  <button
    type="button"
    onClick={() =>
      updateAlertStatus(
        alert._id,
        "RESOLVED"
      )
    }
    className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-2 text-xs font-medium text-green-400 transition hover:bg-green-500/20"
  >
    MARK AS RESOLVED
  </button>

)}


{alert.status === "RESOLVED" && (

  <button
    type="button"
    onClick={() =>
      updateAlertStatus(
        alert._id,
        "INVESTIGATING"
      )
    }
    className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-xs font-medium text-yellow-400 transition hover:bg-yellow-500/20"
  >
    REOPEN INVESTIGATION
  </button>

)}
                </div>

              </div>

            </div>

          )
        )

      )}

    </div>

  </div>

</section>
{/* ============================================================
   EVENT TIMELINE
============================================================ */}

<section className="mt-8">

  <div className="rounded-xl border border-slate-800 bg-slate-900">


    {/* EVENT HEADER */}

    <div className="border-b border-slate-800 p-6">

      <div className="flex items-center justify-between">

        <div>

          <h2 className="text-xl font-semibold">
            Event Timeline
          </h2>

          <p className="mt-1 text-sm text-slate-400">
            Recent security events processed by Sentinel
          </p>

        </div>


        <div className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-500">

          {events.length} EVENTS

        </div>

      </div>

    </div>


    {/* EVENT LIST */}

    <div className="divide-y divide-slate-800">

      {events.length === 0 ? (

        <div className="p-8 text-center text-sm text-slate-500">

          No security events available.

        </div>

      ) : (

        events.map(
          (event, index) => (

            <div
              key={
                event._id ||
                `${event.timestamp}-${index}`
              }
              className="p-6 transition hover:bg-slate-950/50"
            >

              <div className="flex items-start gap-4">


                {/* EVENT INDICATOR */}

                <div
                  className={`mt-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${
                    event.event_type ===
                    "authentication_failure"

                      ? "bg-red-500/10"

                      : event.event_type ===
                        "authentication_success"

                        ? "bg-green-500/10"

                        : event.event_type ===
                          "network_connection"

                          ? "bg-cyan-500/10"

                          : "bg-slate-500/10"
                  }`}
                >

                  <span
                    className={`text-sm ${
                      event.event_type ===
                      "authentication_failure"

                        ? "text-red-400"

                        : event.event_type ===
                          "authentication_success"

                          ? "text-green-400"

                          : event.event_type ===
                            "network_connection"

                            ? "text-cyan-400"

                            : "text-slate-400"
                    }`}
                  >

                    {event.event_type ===
                    "authentication_failure"

                      ? "!"

                      : event.event_type ===
                        "authentication_success"

                        ? "✓"

                        : event.event_type ===
                          "network_connection"

                          ? "↔"

                          : "•"}

                  </span>

                </div>


                {/* EVENT CONTENT */}

                <div className="min-w-0 flex-1">

                  <div className="flex flex-wrap items-center gap-3">

                    <h3 className="text-sm font-semibold text-slate-200">

                      {getEventLabel(event)}

                    </h3>


                    <span
                      className={`rounded-full px-2.5 py-1 text-xs font-medium ${getEventStatusStyle(
                        event
                      )}`}
                    >

                      {event.status ||
                        "EVENT"}

                    </span>

                  </div>


                  <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">


                    {/* SOURCE IP */}

                    {event.source_ip && (

                      <div>

                        <p className="text-xs text-slate-600">
                          SOURCE IP
                        </p>

                        <p className="mt-1 font-mono text-sm text-slate-400">
                          {event.source_ip}
                        </p>

                      </div>

                    )}


                    {/* USERNAME */}

                    {event.username && (

                      <div>

                        <p className="text-xs text-slate-600">
                          USERNAME
                        </p>

                        <p className="mt-1 text-sm text-slate-400">
                          {event.username}
                        </p>

                      </div>

                    )}


                    {/* DESTINATION PORT */}

                    {event.destination_port && (

                      <div>

                        <p className="text-xs text-slate-600">
                          DESTINATION PORT
                        </p>

                        <p className="mt-1 font-mono text-sm text-slate-400">
                          {event.destination_port}
                        </p>

                      </div>

                    )}

                  </div>


                  {/* RAW MESSAGE */}

                  {event.message && (

                    <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 px-4 py-3">

                      <p className="font-mono text-xs leading-5 text-slate-500 break-all">

                        {event.message}

                      </p>

                    </div>

                  )}


                  {/* TIMESTAMP */}

                  <p className="mt-3 text-xs text-slate-600">

                    {formatTimestamp(
                      event.timestamp
                    )}

                  </p>

                </div>

              </div>

            </div>

          )
        )

      )}

    </div>

  </div>

</section>


{/* ============================================================
   ALERT DETAILS MODAL
============================================================ */}

{selectedAlert && (

  <div
    className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-6 backdrop-blur-sm"
    onClick={() =>
      setSelectedAlert(null)
    }
  >

    <div
      className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl"
      onClick={(event) =>
        event.stopPropagation()
      }
    >


      {/* ======================================================
          MODAL HEADER
      ====================================================== */}

      <div className="flex items-center justify-between border-b border-slate-800 p-6">

        <div>

          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Security Alert
          </p>

          <h2 className="mt-1 text-xl font-semibold text-white">

            {selectedAlert.alert_type ||
              "Unknown Alert"}

          </h2>

        </div>


        <button
          type="button"
          onClick={() =>
            setSelectedAlert(null)
          }
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-700 text-slate-400 transition hover:border-slate-500 hover:text-white"
        >

          ✕

        </button>

      </div>


      {/* ======================================================
          MODAL BODY
      ====================================================== */}

      <div className="space-y-6 p-6">


        {/* SEVERITY + STATUS */}

        <div className="flex flex-wrap gap-3">

          <span
            className={`rounded-full px-3 py-1.5 text-xs font-semibold ${
              selectedAlert.severity === "HIGH"
                ? "bg-red-500/10 text-red-400"
                : selectedAlert.severity === "MEDIUM"
                  ? "bg-yellow-500/10 text-yellow-400"
                  : "bg-green-500/10 text-green-400"
            }`}
          >

            SEVERITY:
            {" "}
            {selectedAlert.severity}

          </span>


          <span
            className={`rounded-full px-3 py-1.5 text-xs font-semibold ${getAlertStatusStyle(
              selectedAlert.status
            )}`}
          >

            STATUS:
            {" "}
            {selectedAlert.status}

          </span>

        </div>


        {/* DETAILS GRID */}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">


          {/* SOURCE IP */}

          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

            <p className="text-xs uppercase tracking-wider text-slate-600">
              Source IP
            </p>

            <p className="mt-2 font-mono text-sm text-slate-300">

              {selectedAlert.source_ip ||
                "Unknown"}

            </p>

          </div>


          {/* USERNAME */}

          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

            <p className="text-xs uppercase tracking-wider text-slate-600">
              Username
            </p>

            <p className="mt-2 text-sm text-slate-300">

              {selectedAlert.username ||
                "N/A"}

            </p>

          </div>


          {/* FAILED ATTEMPTS */}

          {selectedAlert.failed_attempts !==
            undefined && (

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-xs uppercase tracking-wider text-slate-600">
                Failed Attempts
              </p>

              <p className="mt-2 text-sm text-slate-300">

                {selectedAlert.failed_attempts}

              </p>

            </div>

          )}


          {/* PORTS SCANNED */}

          {selectedAlert.ports_scanned !==
            undefined && (

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-xs uppercase tracking-wider text-slate-600">
                Ports Scanned
              </p>

              <p className="mt-2 text-sm text-slate-300">

                {selectedAlert.ports_scanned}

              </p>

            </div>

          )}


          {/* WINDOW */}

          {selectedAlert.window_minutes !==
            undefined && (

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-xs uppercase tracking-wider text-slate-600">
                Detection Window
              </p>

              <p className="mt-2 text-sm text-slate-300">

                {selectedAlert.window_minutes}
                {" "}
                minutes

              </p>

            </div>

          )}


          {/* DETECTED AT */}

          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

            <p className="text-xs uppercase tracking-wider text-slate-600">
              Detected At
            </p>

            <p className="mt-2 text-sm text-slate-300">

              {formatTimestamp(
                selectedAlert.detected_at ||
                selectedAlert.timestamp
              )}

            </p>

          </div>

        </div>


        {/* FIRST / LAST SEEN */}

        {(selectedAlert.first_seen ||
          selectedAlert.last_seen) && (

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">

            {selectedAlert.first_seen && (

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

                <p className="text-xs uppercase tracking-wider text-slate-600">
                  First Seen
                </p>

                <p className="mt-2 text-sm text-slate-300">

                  {formatTimestamp(
                    selectedAlert.first_seen
                  )}

                </p>

              </div>

            )}


            {selectedAlert.last_seen && (

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

                <p className="text-xs uppercase tracking-wider text-slate-600">
                  Last Seen
                </p>

                <p className="mt-2 text-sm text-slate-300">

                  {formatTimestamp(
                    selectedAlert.last_seen
                  )}

                </p>

              </div>

            )}

          </div>

        )}


        {/* ALERT ID */}

        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

          <p className="text-xs uppercase tracking-wider text-slate-600">
            Alert ID
          </p>

          <p className="mt-2 break-all font-mono text-xs text-slate-500">

            {selectedAlert._id}

          </p>

        </div>
{/* ==================================================
    THREAT CONTEXT
================================================== */}

<div className="rounded-xl border border-cyan-500/10 bg-cyan-500/[0.03] p-5">

  <div className="mb-4">

    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
      Threat Context
    </p>

    <p className="mt-1 text-xs text-slate-600">
      Security indicators associated with this alert.
    </p>

  </div>


  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">


    {/* SOURCE */}

    <div>

      <p className="text-[11px] uppercase tracking-wider text-slate-600">
        Source
      </p>

      <p className="mt-1 font-mono text-sm text-slate-300">
        {selectedAlert.source_ip ||
          "Unknown"}
      </p>

    </div>


    {/* EVENT TYPE */}

    <div>

      <p className="text-[11px] uppercase tracking-wider text-slate-600">
        Event Type
      </p>

      <p className="mt-1 text-sm text-slate-300">
        {selectedAlert.alert_type ||
          "Unknown"}
      </p>

    </div>


    {/* SEVERITY */}

    <div>

      <p className="text-[11px] uppercase tracking-wider text-slate-600">
        Severity
      </p>

      <p className="mt-1 text-sm font-semibold text-slate-300">
        {selectedAlert.severity ||
          "UNKNOWN"}
      </p>

    </div>

  </div>

</div>
        {/* ==================================================
    INVESTIGATION ACTIVITY
================================================== */}

<div className="border-t border-slate-800 pt-5">

  <div className="mb-4 flex items-center justify-between">

    <div>

      <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
        Investigation Activity
      </p>

      <p className="mt-1 text-xs text-slate-600">
        Analyst actions recorded for this alert
      </p>

    </div>

    {alertActivity.length > 0 && (

      <span className="rounded-full bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-400">

        {alertActivity.length}
        {" "}
        {alertActivity.length === 1
          ? "EVENT"
          : "EVENTS"}

      </span>

    )}

  </div>


  {activityLoading ? (

    <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

      <div className="flex items-center gap-3">

        <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

        <span className="text-sm text-slate-500">
          Loading investigation activity...
        </span>

      </div>

    </div>

  ) : alertActivity.length === 0 ? (

    <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

      <p className="text-sm text-slate-500">
        No investigation activity recorded yet.
      </p>

      <p className="mt-1 text-xs text-slate-600">
        Status changes will appear here.
      </p>

    </div>

  ) : (

    <div className="space-y-3">

      {alertActivity.map(
        (activity, index) => (

          <div
            key={`${activity.timestamp}-${index}`}
            className="relative rounded-xl border border-slate-800 bg-slate-950 p-4"
          >

            <div className="flex gap-4">


              {/* ACTIVITY INDICATOR */}

              <div className="flex shrink-0 flex-col items-center">

                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400">

                  {activity.action?.includes(
                    "RESOLVED"
                  )
                    ? "✓"
                    : activity.action?.includes(
                        "INVESTIGATING"
                      )
                      ? "→"
                      : "•"}

                </div>

                {index <
                  alertActivity.length - 1 && (

                  <div className="mt-2 h-full w-px bg-slate-800" />

                )}

              </div>


              {/* ACTIVITY CONTENT */}

              <div className="min-w-0 flex-1">

                <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">

                  <p className="text-sm font-medium text-slate-300">

                    {activity.action}

                  </p>

                  <span className="text-xs text-slate-600">

                    {formatTimestamp(
                      activity.timestamp
                    )}

                  </span>

                </div>


                <div className="mt-2 flex flex-wrap items-center gap-3">

                  <span className="text-xs text-slate-500">

                    Analyst:
                    {" "}

                    <span className="text-slate-400">

                      {activity.username ||
                        "unknown"}

                    </span>

                  </span>

                </div>


                {activity.note && (

                  <div className="mt-3 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2">

                    <p className="text-xs leading-5 text-slate-500">

                      {activity.note}

                    </p>

                  </div>

                )}

              </div>

            </div>

          </div>

        )
      )}

    </div>

  )}

</div>
{/* ==================================================
    ANALYST NOTES
================================================== */}

<div className="border-t border-slate-800 pt-5">

  <div className="mb-4">

    <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
      Analyst Notes
    </p>

    <p className="mt-1 text-xs text-slate-600">
      Add investigation findings or observations.
    </p>

  </div>


  <textarea
    value={analystNote}
    onChange={(event) => {
      setAnalystNote(
        event.target.value
      )
      setNoteMessage("")
    }}
    placeholder="Enter investigation notes..."
    maxLength={1000}
    rows={4}
    className="w-full resize-none rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm leading-6 text-slate-300 outline-none placeholder:text-slate-600 focus:border-cyan-400"
  />


  <div className="mt-2 flex items-center justify-between">

    <span className="text-xs text-slate-600">
      {analystNote.length}/1000 characters
    </span>


    <button
      type="button"
      onClick={addAnalystNote}
      disabled={
        noteSubmitting ||
        !analystNote.trim()
      }
      className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
    >

      {noteSubmitting
        ? "ADDING..."
        : "ADD NOTE"
      }

    </button>

  </div>


  {noteMessage && (

    <div
      className={`mt-3 rounded-lg border px-3 py-2 text-xs ${
        noteMessage ===
        "Investigation note added."
          ? "border-green-500/20 bg-green-500/10 text-green-400"
          : "border-red-500/20 bg-red-500/10 text-red-400"
      }`}
    >

      {noteMessage}

    </div>

  )}

</div>
        {/* ==================================================
    STATUS ACTIONS
================================================== */}

<div className="border-t border-slate-800 pt-5">

  <div className="mb-4">

    <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
      Investigation Status
    </p>

    <p className="mt-1 text-xs text-slate-600">
      Update the current state of this security alert.
    </p>

  </div>


  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">


    {/* DETECTED */}

    <button
      type="button"
      onClick={() =>
        updateAlertStatus(
          selectedAlert._id,
          "DETECTED"
        )
      }
      disabled={
        selectedAlert.status ===
        "DETECTED"
      }
      className="rounded-xl border border-red-500/20 bg-red-500/[0.06] px-4 py-3 text-left transition hover:border-red-500/40 hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-30"
    >

      <p className="text-xs font-semibold text-red-400">
        DETECTED
      </p>

      <p className="mt-1 text-[11px] text-slate-600">
        Mark as newly detected
      </p>

    </button>


    {/* INVESTIGATING */}

    <button
      type="button"
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
      className="rounded-xl border border-blue-500/20 bg-blue-500/[0.06] px-4 py-3 text-left transition hover:border-blue-500/40 hover:bg-blue-500/10 disabled:cursor-not-allowed disabled:opacity-30"
    >

      <p className="text-xs font-semibold text-blue-400">
        INVESTIGATING
      </p>

      <p className="mt-1 text-[11px] text-slate-600">
        Begin investigation
      </p>

    </button>


    {/* RESOLVED */}

    <button
      type="button"
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
      className="rounded-xl border border-green-500/20 bg-green-500/[0.06] px-4 py-3 text-left transition hover:border-green-500/40 hover:bg-green-500/10 disabled:cursor-not-allowed disabled:opacity-30"
    >

      <p className="text-xs font-semibold text-green-400">
        RESOLVED
      </p>

      <p className="mt-1 text-[11px] text-slate-600">
        Close the investigation
      </p>

    </button>

  </div>

</div>

      {/* ======================================================
          MODAL FOOTER
      ====================================================== */}

      <div className="border-t border-slate-800 px-6 py-4">

        <button
          type="button"
          onClick={() =>
            setSelectedAlert(null)
          }
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
        >

          CLOSE

        </button>

      </div>

    </div>
  </div>
</div>

)

/* ============================================================
   FOOTER
============================================================ */}

<footer className="border-t border-slate-800 px-8 py-6">

  <div className="flex flex-col gap-2 text-center text-xs text-slate-600 md:flex-row md:items-center md:justify-between md:text-left">

    <p>
      SENTINEL Security Operations Platform
    </p>

    <p>
      JWT Protected • MongoDB Atlas • Real-Time WebSocket Monitoring
    </p>

  </div>

</footer>


</main>

</div>

)


}


/* ============================================================
   EXPORT
============================================================ */

export default App
