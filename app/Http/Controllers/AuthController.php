<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request) {
        $validated = $request->validate([
            'first_name' => 'required|string|max:255',
            'last_name' => 'required|string|max:255',
            'address' => 'required|string|max:255',
            'phone' => 'required|string|max:11',
            'email' => 'required|email|unique:users,data->email|max:30,',
            'password' => 'required|string|min:3',
        ]);

        $user = User::create([
            'data' => $validated,
        ]);

        if(!$user){
                return response()->json(['message' => 'something went wrong'], 401);
        }
        $token = $user->createToken('Auth-token')->plainTextToken;
            return response()->json([
                'message' => 'Registered Successfully',
                'user' => $user,
                'token' => $token
            ], 200);

    }

    public function login(Request $request){
        $user = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        $user = User::where('data->email', $request->email)->first();
        if(!$user || !Auth::check(['data->email' => $request->email, 'data->password' => $request['password']]))
            return response()->json([
                'message' => 'Invalid Credentials'
            ], 401);

            $token = $user->createToken('auth-Token')->plainTextToken;
            return response()->json([
                'message' => 'Login Successful',
                'user' => $user,
                'token' => $token
            ]);
    }
}
