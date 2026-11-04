<?php

use Illuminate\Support\Facades\Route;

// Health check route (unprotected / excluded)
Route::get('/up', function () {
    return response('OK', 200);
});

// Protected web routes (middleware: codelock)
Route::middleware(['web', 'codelock'])->group(function () {
    Route::get('/', function () {
        return view('welcome_app');
    });

    Route::get('/dashboard', function () {
        return view('welcome_app');
    });
});

// Protected API routes
Route::middleware(['api', 'codelock'])->group(function () {
    Route::get('/api/data', function () {
        return response()->json([
            'status' => 'success',
            'data' => [
                'users' => 1250,
                'revenue' => 450000,
                'metrics' => 'Normal Operation',
            ],
        ]);
    });
});

