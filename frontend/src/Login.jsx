import { useState } from "react"


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
                "http://127.0.0.1:8000/api/auth/login",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        username: username.trim(),
                        password: password
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

            setError(
                "Unable to connect to Sentinel backend"
            )

        } finally {

            setLoading(false)
        }
    }


    return (

        <div className="min-h-screen bg-slate-950 flex items-center justify-center px-6">

            <div className="w-full max-w-md">

                <div className="mb-8 text-center">

                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-400/20 mb-5">

                        <span className="text-3xl">
                            🛡️
                        </span>

                    </div>


                    <h1 className="text-3xl font-bold text-white">
                        Sentinel
                    </h1>


                    <p className="mt-2 text-slate-400">
                        Security Operations & Threat Detection
                    </p>

                </div>


                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-7 shadow-2xl">

                    <div className="mb-6">

                        <h2 className="text-xl font-semibold text-white">
                            Analyst Login
                        </h2>

                        <p className="text-sm text-slate-500 mt-1">
                            Authenticate to access the security dashboard.
                        </p>

                    </div>


                    <form
                        onSubmit={handleLogin}
                        className="space-y-5"
                    >

                        <div>

                            <label className="block text-sm font-medium text-slate-300 mb-2">
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
                                className="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-700 text-white placeholder-slate-600 outline-none focus:border-cyan-400 transition"
                            />

                        </div>


                        <div>

                            <label className="block text-sm font-medium text-slate-300 mb-2">
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
                                className="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-700 text-white placeholder-slate-600 outline-none focus:border-cyan-400 transition"
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
                            className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 font-semibold transition"
                        >

                            {loading
                                ? "Authenticating..."
                                : "Sign In"
                            }

                        </button>

                    </form>


                    <div className="mt-6 pt-5 border-t border-slate-800">

                        <p className="text-xs text-center text-slate-600">
                            Sentinel Security Operations Platform
                        </p>

                    </div>

                </div>

            </div>

        </div>

    )
}


export default Login
