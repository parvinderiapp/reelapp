<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
Route::post('/api/registeruser', 'ApiController@registerUser');
Route::post('/api/loginuser', 'ApiController@loginuser');
Route::post('/api/forgetpassword', 'ApiController@forgetpassword');
Route::post('/api/resetpassword', 'ApiController@resetpassword');
Route::get('/emailverification/{user_id}/{verification_code}','ApiController@emailverification');