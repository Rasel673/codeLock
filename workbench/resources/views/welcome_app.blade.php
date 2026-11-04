<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acme Enterprise CRM - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white min-h-screen p-8">
    <div class="max-w-4xl mx-auto">
        <header class="flex justify-between items-center border-b border-slate-800 pb-6 mb-8">
            <div>
                <h1 class="text-3xl font-bold text-white">Acme Enterprise CRM</h1>
                <p class="text-slate-400 text-sm mt-1">Commercial Edition &bull; Production Environment</p>
            </div>
            <div class="flex items-center gap-3">
                <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span>
                    License Active &amp; Valid
                </span>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-6">
                <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Active Accounts</h3>
                <p class="text-3xl font-bold text-white">1,250</p>
            </div>
            <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-6">
                <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Monthly Recurring Revenue</h3>
                <p class="text-3xl font-bold text-white">$45,000</p>
            </div>
            <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-6">
                <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">System Health</h3>
                <p class="text-3xl font-bold text-emerald-400">100% Operational</p>
            </div>
        </div>

        <div class="bg-slate-800/40 border border-slate-700/40 rounded-xl p-6">
            <h2 class="text-lg font-semibold text-white mb-2">Welcome to Your Application</h2>
            <p class="text-slate-300 text-sm leading-relaxed">
                All commercial license verifications passed successfully. Cryptographic Ed25519 signature, domain authorization, and integrity verification are verified.
            </p>
        </div>
    </div>
</body>
</html>

