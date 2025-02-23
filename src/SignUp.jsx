import React from "react";
import Nav from "./Navbar/nav";
import Footer from "./Navbar/footer";
import { useForm } from "react-hook-form";
import { Link, Navigate } from "react-router-dom";
import axios from "axios";
import './Contact.css';

function SignUp() {
    const { register, handleSubmit, formState: { errors }, getValues } = useForm();

    const handleGoogleLogin = async () => {
        window.location.href = "http://localhost:3000/auth/google";
    };

    const onSubmit = async (data) => {
        console.log(data);
        try {
            const response = await axios.post("http://localhost:3000/register", {
                name: data.name,
                email: data.email,
                password: data.password
            });

            if (response.data.token) {
                localStorage.setItem("token", response.data.token);
                alert("Registration successful!");
                <Navigate to='/dashboard' />;
            }
        } catch (error) {
            console.error("Registration failed:", error.response?.data || error.message);
            alert("Error during registration.");
        }
    };

    return (
        <div className="bg-gray-900 text-white min-h-screen">
            <Nav />
            <div className="flex flex-col items-center justify-center py-20">
                <div className="w-full max-w-md bg-gray-800 rounded-lg p-8 shadow-lg">
                    <h1 className="text-4xl font-bold text-center text-cyan-400 mb-6">Sign Up</h1>
                    <form className="space-y-5" onSubmit={handleSubmit(onSubmit)}>
                        <div>
                            <label className="block text-lg mb-1">Name</label>
                            <input 
                                type="text" 
                                {...register('name', { required: "Name is required", maxLength: 150 })} 
                                className="w-full p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-400" 
                                placeholder="Enter your name"
                            />
                            {errors.name && <span className="text-red-500 text-sm">{errors.name.message}</span>}
                        </div>
                        
                        <div>
                            <label className="block text-lg mb-1">Email</label>
                            <input 
                                type="email" 
                                {...register('email', { required: "Email is required", maxLength: 100 })} 
                                className="w-full p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-400" 
                                placeholder="Enter your email"
                            />
                            {errors.email && <span className="text-red-500 text-sm">{errors.email.message}</span>}
                        </div>

                        <div>
                            <label className="block text-lg mb-1">Password</label>
                            <input 
                                type="password" 
                                {...register('password', { required: "Password is required" })}  
                                className="w-full p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-400" 
                                placeholder="Enter your password"
                            />
                            {errors.password && <span className="text-red-500 text-sm">{errors.password.message}</span>}
                        </div>

                        <div>
                            <label className="block text-lg mb-1">Confirm Password</label>
                            <input 
                                type="password" 
                                {...register('confirmpassword', { 
                                    required: "Confirm Password is required", 
                                    validate: value => value === getValues("password") || "Passwords do not match" 
                                })}  
                                className="w-full p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-400" 
                                placeholder="Confirm your password"
                            />
                            {errors.confirmpassword && <span className="text-red-500 text-sm">{errors.confirmpassword.message}</span>}
                        </div>

                        <button 
                            className="w-full bg-cyan-400 text-gray-900 py-2 rounded-lg text-lg font-semibold hover:bg-cyan-500 transition duration-300"
                            type="submit"
                        >
                            Sign Up
                        </button>
                    </form>
                    
                    <div className="flex items-center my-5">
                        <div className="flex-grow border-t border-gray-600"></div>
                        <span className="mx-3 text-gray-400">OR</span>
                        <div className="flex-grow border-t border-gray-600"></div>
                    </div>

                    <button 
                        onClick={handleGoogleLogin} 
                        className="w-full flex items-center justify-center gap-2 bg-white text-gray-900 py-2 rounded-lg text-lg font-semibold hover:bg-gray-200 transition duration-300"
                    >
                        <svg className="w-5 h-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 488 512">
                            <path d="M488 261.8C488 403.3 391.1 504 248 504 110.8 504 0 393.2 0 256S110.8 8 248 8c66.8 0 123 24.5 166.3 64.9l-67.5 64.9C258.5 52.6 94.3 116.6 94.3 256c0 86.5 69.1 156.6 153.7 156.6 98.2 0 135-70.4 140.8-106.9H248v-85.3h236.1c2.3 12.7 3.9 24.9 3.9 41.4z"/>
                        </svg>
                        Sign Up with Google
                    </button>
                </div>
                <p className="text-gray-400 mt-4">Already have an account? <Link to='/login' className="text-cyan-400 hover:underline">Login</Link></p>
            </div>
            <Footer />
        </div>
    );
}

export default SignUp;
