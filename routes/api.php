<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

//Route::get('/user', function (Request $request) {
//    return $request->user();
//})->middleware('auth:sanctum');

Route::get('users',[\App\Http\Controllers\AuthController::class,'index']);
Route::post('/register',[\App\Http\Controllers\AuthController::class,'register']);
Route::post('/login',[\App\Http\Controllers\AuthController::class,'login']);
Route::get('/email/verify/{id}/{hash}', [\App\Http\Controllers\AuthController::class, 'verify'])
    ->name('verification.verify');
Route::post('/email/resend', [\App\Http\Controllers\AuthController::class, 'resend'])
    ->name('verification.resend');
Route::post('/password/reset-request', [\App\Http\Controllers\AuthController::class, 'sendResetLinkEmail']);
Route::post('/password/reset', [\App\Http\Controllers\AuthController::class, 'reset']);

