import React from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom"; // Import useNavigate
import "./Create.css";

function Create({ toggleCreate }) {
    const { register, handleSubmit, formState: { errors } } = useForm();
    const navigate = useNavigate(); // Initialize useNavigate

    const onSubmit = (data) => {
        console.log("Submitted Note:", data);
        data['id']=0;
        console.log(data)
        // Store data in localStorage (improved)
        sessionStorage.setItem("userData", JSON.stringify(data));

        // Navigate to the editor page
        navigate('/editor');

        // Close the modal after successful submission (optional)
        toggleCreate(); 
    };

    return (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
            <div className="bg-[#101F28] border-white border-2 w-[40rem] h-[30rem] rounded-md p-6 flex flex-col">
                <h1 className="text-[#4DE4EC] text-4xl text-center mb-4">Create Note</h1>

                <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col items-center">
                    {/* Title Input */}
                    <div className="mb-4 w-full">
                        <label className="text-[#4DE4EC] text-xl">Title</label>
                        <input
                            className="border-b w-full bg-transparent text-white outline-none p-2"
                            {...register("title", { required: "Title is required" })} // Improved error message
                            type="text"
                        />
                        {errors.title && <p className="text-red-500">{errors.title.message}</p>} {/* Display specific error message */}
                    </div>

                    {/* Description Input */}
                    <div className="mb-4 w-full">
                        <label className="text-[#4DE4EC] text-xl">Description</label>
                        <textarea
                            className="border-b w-full bg-transparent text-white outline-none p-2 h-20"
                            {...register("description", { required: "Description is required" })} // Improved error message
                        ></textarea>
                        {errors.description && <p className="text-red-500">{errors.description.message}</p>} {/* Display specific error message */}
                    </div>

                    {/* Buttons */}
                    <div className="flex gap-4">
                        <button
                            type="button"
                            onClick={toggleCreate}
                            className="bg-gray-500 px-4 py-2 rounded-md text-white"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="bg-[#5EE6ED] px-4 py-2 rounded-md text-white"
                        >
                            Submit
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export default Create;