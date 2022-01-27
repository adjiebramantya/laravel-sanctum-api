<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function Register(Request $request)
    {
        $field = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $field['name'],
            'email' => $field['email'],
            'password' => Hash::make($field['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'users' => $user,
            'token' => $token
        ];

        return response($response,201);
    }

    public function login(Request $request)
    {
        $field = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        $user = User::where('email',$field['email'])->first();

        if(!$user || !Auth::attempt($field)){
            return response([
                'message' => 'Bad Creds'
            ],401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'users' => $user,
            'token' => $token
        ];

        return response($response,201);
    }

    public function logout(Request $request)
    {
        // auth()->user()->tokens()->delete();
        $user = Auth::user();
        $user->tokens()->delete();

        return [
            'message'=>'Logged Out'
        ];
    }
}
