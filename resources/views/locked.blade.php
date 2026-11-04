<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software License Restricted &bull; Access Restricted | {{ config('app.name', 'Software Application') }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
        body { font-family: 'Plus Jakarta Sans', sans-serif; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-6 selection:bg-purple-500 selection:text-white">

    <div class="max-w-lg w-full bg-slate-900/90 border border-slate-800 rounded-2xl shadow-2xl p-8 sm:p-10 relative overflow-hidden backdrop-blur-xl">
        
        <!-- Subtle Purple Radial Glow -->
        <div class="absolute -top-24 -left-24 w-72 h-72 bg-purple-600/15 rounded-full blur-3xl pointer-events-none"></div>
        <div class="absolute -bottom-24 -right-24 w-72 h-72 bg-violet-600/10 rounded-full blur-3xl pointer-events-none"></div>

        <!-- Session Flash Alerts -->
        @if(session('codelock_error'))
            <div class="mb-6 p-4 rounded-xl bg-purple-950/60 border border-purple-800/80 text-purple-200 text-xs sm:text-sm flex items-center gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 flex-shrink-0 text-purple-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                </svg>
                <span>{{ session('codelock_error') }}</span>
            </div>
        @endif

        @if(session('codelock_success'))
            <div class="mb-6 p-4 rounded-xl bg-emerald-950/60 border border-emerald-800/80 text-emerald-300 text-xs sm:text-sm flex items-center gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 flex-shrink-0 text-emerald-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                </svg>
                <span>{{ session('codelock_success') }}</span>
            </div>
        @endif

        <!-- Header: Lock Icon & Software Branding -->
        <div class="flex items-center justify-between mb-8">
            <div class="w-12 h-12 rounded-2xl bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center shadow-inner shadow-purple-500/10">
                <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
            </div>
            <div class="flex flex-col items-end">
                <span class="text-xs font-semibold uppercase tracking-wider text-purple-400 font-mono">
                    {{ config('app.name', 'Software Application') }} &bull; Access Restricted
                </span>
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-purple-950/80 text-purple-300 border border-purple-800/60 uppercase tracking-widest mt-1">
                    {{ $statusInfo['status_label'] ?? 'License Restricted' }}
                </span>
            </div>
        </div>

        <!-- Title & Standard Message -->
        <h1 class="text-2xl sm:text-3xl font-bold tracking-tight text-white mb-3">
            Software License Restricted
        </h1>
        <p class="text-slate-300 text-sm sm:text-base leading-relaxed mb-2">
            This application is currently unavailable because its software license requires attention.
        </p>
        <p class="text-slate-400 text-xs sm:text-sm leading-relaxed mb-6">
            Please contact your software provider to restore access.
        </p>

        @if(!empty($reason) && $reason !== 'Installation is not licensed.')
        <!-- Contextual Reason Note if provided -->
        <div class="mb-6 p-3 rounded-xl bg-purple-950/30 border border-purple-800/40 text-purple-300 text-xs">
            <span class="font-semibold">Notice:</span> {{ $reason }}
            @if(!empty($statusInfo['reason_code']))
                <span class="block text-purple-400 font-mono text-[10px] mt-1 uppercase tracking-wider">Reason Code: {{ $statusInfo['reason_code'] }}</span>
            @endif
        </div>
        @endif

        <!-- Customer Support Reference Box (Zero Leakage) -->
        <div class="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 mb-6 space-y-2 text-xs">
            <div class="flex justify-between items-center text-slate-400">
                <span>Customer Reference:</span>
                <span class="font-mono text-purple-300 select-all font-semibold">
                    {{ !empty($statusInfo['instance_id']) && $statusInfo['instance_id'] !== 'N/A' ? 'REF-' . strtoupper(substr(hash('crc32b', $statusInfo['instance_id']), 0, 8)) . '-' . strtoupper(substr($statusInfo['instance_id'], -8)) : 'REF-GENERAL' }}
                </span>
            </div>
            <div class="flex justify-between items-center text-slate-400">
                <span>Application Domain:</span>
                <span class="font-mono text-slate-300">{{ $statusInfo['domain'] ?? request()->getHost() }}</span>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="space-y-3 mb-6">
            @if(!empty($statusInfo['action_url']))
                <a href="{{ $statusInfo['action_url'] }}" target="_blank" rel="noopener noreferrer"
                   class="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-500 text-white font-medium px-5 py-3 rounded-xl transition duration-150 shadow-lg shadow-purple-950/50">
                    <span>Resolve Payment / View Invoice &rarr;</span>
                </a>
            @endif

            <!-- Verify & Restore Access Button -->
            <form method="POST" action="{{ url('codelock/recover') }}">
                @csrf
                <button type="submit"
                        class="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-500 text-white font-medium px-5 py-3 rounded-xl transition duration-150 shadow-lg shadow-purple-950/60 active:scale-[0.99]">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-purple-200" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    <span>Verify &amp; Restore Access</span>
                </button>
            </form>

            <!-- Support Links -->
            <div class="flex flex-col sm:flex-row items-center gap-3">
                @if(!empty($statusInfo['contact_email']))
                    <a href="mailto:{{ $statusInfo['contact_email'] }}?subject=License%20Activation%20Assistance%20[{{ !empty($statusInfo['instance_id']) ? $statusInfo['instance_id'] : 'UNKNOWN' }}]" 
                       class="w-full sm:w-auto flex-1 text-center border border-slate-700 hover:border-purple-500/50 hover:bg-slate-800/60 text-slate-200 font-medium px-4 py-2.5 rounded-xl transition duration-150 text-xs sm:text-sm">
                        Contact Licensing Support
                    </a>
                @endif
                @if(!empty($statusInfo['contact_url']))
                    <a href="{{ $statusInfo['contact_url'] }}" target="_blank" rel="noopener noreferrer"
                       class="w-full sm:w-auto flex-1 text-center border border-slate-700 hover:border-purple-500/50 hover:bg-slate-800/60 text-slate-200 font-medium px-4 py-2.5 rounded-xl transition duration-150 text-xs sm:text-sm">
                        Support Website &rarr;
                    </a>
                @endif
            </div>
        </div>

        <!-- Footer / Support instructions -->
        <div class="pt-4 border-t border-slate-800/80 text-center">
            <p class="text-[11px] text-slate-500 leading-normal">
                If you are an administrator, verify your commercial license key or run <code class="text-purple-300 font-mono bg-purple-950/50 border border-purple-800/40 px-1.5 py-0.5 rounded">php artisan codelock:status</code>.
            </p>
        </div>

    </div>

</body>
</html>
