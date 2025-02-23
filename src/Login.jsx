import React from "react";
import Nav from "./Navbar/nav";
import Footer from "./Navbar/footer";
import { Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import "./Contact.css";

function Login() {
    const { register, handleSubmit, formState: { errors } } = useForm();
    const navigate = useNavigate();

    const handleGoogleLogin = async () => {
        window.location.href = "http://localhost:3000/auth/google";
    };

    const onSubmit = async (data) => {
        try {
            const response = await axios.post("http://localhost:3000/login", data);
            localStorage.setItem("token", response.data.token);
            navigate("/dashboard");
        } catch (error) {
            alert(error.response?.data?.message || "Login failed. Please try again.");
        }
    };

    return (
        <div>
            <Nav />
            <div className="flex flex-col items-center justify-center min-h-screen bg-[#1E293B] py-10 px-5 mt-20">
                <div className="w-full max-w-md bg-[#2D3748] p-8 rounded-3xl shadow-xl transform transition duration-500 hover:scale-105">
                    <h1 className="text-4xl text-[#4DE4EC] text-center font-bold mb-6">Login</h1>
                    
                    <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-6">
                        
                        {/* Name Field */}
                        <label className="flex flex-col">
                            <span className="text-[#4DE4EC] text-lg font-semibold">Name</span>
                            <input 
                                type="text" 
                                {...register('name', { required: true, maxLength: 150 })} 
                                className="border-b bg-transparent text-white p-2 focus:outline-none focus:border-[#4DE4EC] transition duration-300 focus:ring-2 focus:ring-[#4DE4EC] rounded-md"
                                placeholder="Enter your name" 
                            />
                            {errors.name && <span className="text-red-400 text-sm">Name is required</span>}
                        </label>

                        {/* Email Field */}
                        <label className="flex flex-col">
                            <span className="text-[#4DE4EC] text-lg font-semibold">Email</span>
                            <input 
                                type="email" 
                                {...register('email', { required: true, maxLength: 100 })} 
                                className="border-b bg-transparent text-white p-2 focus:outline-none focus:border-[#4DE4EC] transition duration-300 focus:ring-2 focus:ring-[#4DE4EC] rounded-md"
                                placeholder="Enter your email" 
                            />
                            {errors.email && <span className="text-red-400 text-sm">Email is required</span>}
                        </label>

                        {/* Password Field */}
                        <label className="flex flex-col">
                            <span className="text-[#4DE4EC] text-lg font-semibold">Password</span>
                            <input 
                                type="password" 
                                {...register('password', { required: true })}  
                                className="border-b bg-transparent text-white p-2 focus:outline-none focus:border-[#4DE4EC] transition duration-300 focus:ring-2 focus:ring-[#4DE4EC] rounded-md"
                                placeholder="Enter your password" 
                            />
                            {errors.password && <span className="text-red-400 text-sm">Password is required</span>}
                        </label>

                        {/* Login Button */}
                        <button 
                            className="w-full bg-[#4DE4EC] text-black font-semibold py-3 rounded-3xl hover:bg-[#3DC2C8] transition duration-300 shadow-md hover:shadow-lg"
                            type="submit"
                        >
                            Login
                        </button>
                    </form>
                    
                    {/* Divider */}
                    <div className="my-6 border-t border-gray-500"></div>
                    
                    {/* Google Login Button */}
                    <div 
                        onClick={handleGoogleLogin} 
                        className="flex items-center justify-center bg-white text-black py-3 rounded-3xl cursor-pointer hover:bg-gray-200 transition duration-300 shadow-md hover:shadow-lg"
                    >
                        <svg className="w-6 h-6 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 488 512">
                            <path d="M488 261.8C488 403.3 391.1 504 248 504 110.8 504 0 393.2 0 256S110.8 8 248 8c66.8 0 123 24.5 166.3 64.9l-67.5 64.9C258.5 52.6 94.3 116.6 94.3 256c0 86.5 69.1 156.6 153.7 156.6 98.2 0 135-70.4 140.8-106.9H248v-85.3h236.1c2.3 12.7 3.9 24.9 3.9 41.4z"/>
                        </svg>
                        <span className="font-semibold">Login with Google</span>
                    </div>
                </div>
                
                {/* Sign-up Link */}
                <p className="text-white mt-4">
                    Don’t have an account? 
                    <Link to='/signup' className="text-[#4DE4EC] hover:text-[#3DC2C8] ml-1 transition duration-300">Sign up</Link>
                </p>
            </div>
            <Footer />
        </div>
    );
}

export default Login;
