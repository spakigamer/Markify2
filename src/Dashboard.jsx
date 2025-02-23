import React, { useEffect, useState } from "react";
import Nav from "./Navbar/nav";
import Footer from "./Navbar/footer";
import Card from "./Card";
import Create from "./Create";
import axios from "axios";

function Dashboard() {
    const [notes, setNotes] = useState([]); // Store notes
    const [showCreate, setShowCreate] = useState(false); // Controls the modal visibility

    const toggleCreate = () => {
        setShowCreate(prev => !prev); // Toggle between true and false
    };

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        const token = localStorage.getItem('token'); // ✅ Get JWT token

        if (!token) {
            console.error("User not authenticated!");
            return;
        }

        try {
            const response = await axios.get("http://localhost:3000/get-data", {
                headers: {
                    'Authorization': `Bearer ${token}` // ✅ Send token in headers
                }
            });
            setNotes(response.data.data);
            console.log("Data received:", response.data);
            return response.data.data; // ✅ Return list of notes (without marktext)
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    const logout = async () => {
        localStorage.removeItem("token");
        window.location.href = "/login";
        await axios.get('http://localhost:3000/logout');
    };

    return (
        <div className="w-full min-h-screen flex flex-col bg-[#1E293B] text-white">
            {/* HEADER */}
            <div className="flex justify-between items-center bg-[#2D3748] h-16 px-6 shadow-lg">
                <div className="flex items-center gap-4">
                    <img src="icons8-male-user-48 (2).png" alt="User" className="w-10 h-10 rounded-full border border-gray-300" />
                </div>
                <button 
                    onClick={logout} 
                    className="bg-red-500 px-4 py-2 rounded-lg text-white font-semibold hover:bg-red-400 transition duration-300"
                >
                    Logout
                </button>
            </div>

            {/* MAIN CONTENT */}
            <div className="flex-grow flex flex-col items-center justify-center py-10 px-5">
                {/* Create Button */}
                <button 
                    onClick={toggleCreate} 
                    className="bg-[#4DE4EC] px-6 py-3 rounded-xl text-black font-semibold shadow-md hover:shadow-lg hover:bg-[#3DC2C8] transition duration-300 mb-6"
                >
                    + Create New Note
                </button>

                {/* Notes Section */}
                {notes.length === 0 ? (
                    <div className="bg-[#2D3748] text-[#4DE4EC] p-6 rounded-xl shadow-lg text-center w-72">
                        <h1 className="text-lg font-semibold">You don't have any notes yet</h1>
                        <p className="text-sm text-gray-400 mt-2">Start by creating a new one!</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-4 w-full max-w-5xl">
                        {notes.map((note) => (
                            <Card props={note} key={note.id} />
                        ))}
                    </div>
                )}
            </div>

            {/* FOOTER */}
            <Footer />

            {/* MODAL: Only show Create component if showCreate is true */}
            {showCreate && <Create toggleCreate={toggleCreate} />}
        </div>
    );
}

export default Dashboard;
