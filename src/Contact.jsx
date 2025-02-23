import React, { useState } from "react";
import Nav from "./Navbar/nav";
import Footer from "./Navbar/footer";
import { useForm } from "react-hook-form";
import axios from "axios";

function Contact() {
    const { register, handleSubmit, formState: { errors } } = useForm();
    const [serverResponse, setServerResponse] = useState(null);

    // Form submit function
    const onSubmit = async (formData) => {
        try {
            const response = await axios.post('http://localhost:3000/contact', formData);
            setServerResponse(response.data.message);
        } catch (error) {
            console.error("Error submitting form:", error);
            setServerResponse("Submission failed. Try again.");
        }
    };

    return (
        <div className="flex flex-col min-h-screen bg-[#1E293B]">
            <Nav />
            <div className="flex flex-grow items-center justify-center mt-30 mb-20">
                <div className="bg-[#2B2E3B] p-10 rounded-3xl shadow-lg w-[400px]">
                    <h1 className="text-center text-3xl font-bold text-[#4DE4EC] mb-6">Contact</h1>

                    {serverResponse && (
                        <p className="text-center text-sm text-white bg-[#4DE4EC] py-2 rounded mb-4">
                            {serverResponse}
                        </p>
                    )}

                    <form className="flex flex-col gap-4" onSubmit={handleSubmit(onSubmit)}>
                        {/* Name */}
                        <div>
                            <label className="text-[#4DE4EC] text-sm">Name</label>
                            <input 
                                type="text" 
                                {...register('name', { required: "Name is required", maxLength: 150 })} 
                                placeholder="Enter your name"
                                className="w-full bg-transparent border border-[#4DE4EC] rounded-md p-2 text-white focus:outline-none"
                            />
                            {errors.name && <p className="text-red-400 text-xs">{errors.name.message}</p>}
                        </div>

                        {/* Email */}
                        <div>
                            <label className="text-[#4DE4EC] text-sm">Email</label>
                            <input 
                                type="email" 
                                {...register('email', { required: "Email is required", maxLength: 100 })} 
                                placeholder="Enter your email"
                                className="w-full bg-transparent border border-[#4DE4EC] rounded-md p-2 text-white focus:outline-none"
                            />
                            {errors.email && <p className="text-red-400 text-xs">{errors.email.message}</p>}
                        </div>

                        {/* Title */}
                        <div>
                            <label className="text-[#4DE4EC] text-sm">Title</label>
                            <input 
                                type="text" 
                                {...register('topic', { required: "Title is required" })}  
                                placeholder="Enter title"
                                className="w-full bg-transparent border border-[#4DE4EC] rounded-md p-2 text-white focus:outline-none"
                            />
                            {errors.topic && <p className="text-red-400 text-xs">{errors.topic.message}</p>}
                        </div>

                        {/* Problem */}
                        <div>
                            <label className="text-[#4DE4EC] text-sm">Problem</label>
                            <textarea 
                                {...register('problem', { required: "Problem description is required" })}  
                                placeholder="Describe your problem in detail"
                                className="w-full bg-transparent border border-[#4DE4EC] rounded-md p-2 text-white focus:outline-none"
                            />
                            {errors.problem && <p className="text-red-400 text-xs">{errors.problem.message}</p>}
                        </div>

                        {/* Submit Button */}
                        <button 
                            type="submit" 
                            className="bg-[#4DE4EC] text-[#2B2E3B] font-bold rounded-md py-2 w-full hover:bg-[#3BC3D4] transition"
                        >
                            Submit
                        </button>
                    </form>
                </div>
            </div>
            <Footer />
        </div>
    );
}

export default Contact;
