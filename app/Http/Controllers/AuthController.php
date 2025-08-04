<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request) {
        $validated = $request->validate([
            'first_name' => 'required|string|max:255',
            'last_name' => 'required|string|max:255',
            'address' => 'required|string|max:255',
            'phone' => 'required|string|max:11',
            'email' => 'required|email|max:30|unique:users,data->email',
            'password' => 'required|string|min:3',
        ]);
        $validated['password'] = Hash::make($validated['password']);

        $user = User::create([
            'data' => $validated,
        ]);

        if(!$user){
                return response()->json(['message' => 'something went wrong'], 401);
        }
        $token = $user->createToken('Auth-token')->plainTextToken;
            return response()->json([
                'message' => 'Registered Successfully',
                'token' => $token
            ], 200);

    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
        'email' => 'required|email',
        'password' => 'required|string'
        ]);

        // Find user by email in JSON data
        $user = User::where('data->email', $credentials['email'])->first();

        // Proper Hash::check() usage
        if(!$user){
            return response()->json(['message' => 'Invalid Credential'], 401);
        }
        if (!Hash::check($credentials['password'], $user->data['password'])) {
            return response()->json([
            'message' => 'Invalid Credentials'
            ], 401);
        }

        $token = $user->createToken('auth-Token')->plainTextToken;
        return response()->json([
        'message' => 'Login Successful',
        'user' => $user,
        'token' => $token
        ]);
    }

    public function update(Request $request) {
        $request->validate([
            'first_name',
        ]);

        db::update('first_name', $request->first_name);
    }
}
