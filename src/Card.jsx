import React from "react";
import { useNavigate } from "react-router-dom";

function Card({ props }) {
    const navigate = useNavigate();

    const handleRedirect = () => {
        sessionStorage.setItem("userData", JSON.stringify(props));
        navigate("/Editor");
    };

    let descriptionData = props.description.length > 40 
        ? props.description.slice(0, 40) + "..." 
        : props.description;

    return (
        <div
            onClick={handleRedirect}
            className="bg-[#2B2E3B] w-[22rem] h-[16rem] rounded-2xl shadow-lg flex flex-col items-center justify-center 
                      cursor-pointer transition-transform transform hover:scale-105 hover:shadow-xl border border-[#4DE4EC] p-4"
        >
            <h1 className="text-[#4DE4EC] text-2xl font-bold text-center">{props.title}</h1>
            <p className="text-white text-sm text-center mt-3 w-4/5">{descriptionData}</p>

            <button 
                className="bg-[#4DE4EC] text-[#2B2E3B] font-semibold mt-4 px-5 py-2 rounded-lg hover:bg-[#3BC3D4] transition"
            >
                Open Editor
            </button>
        </div>
    );
}

export default Card;
    