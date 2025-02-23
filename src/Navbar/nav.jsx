import React, { useState } from "react";
import { Link } from "react-router-dom";

function Nav() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  return (
    <header className="bg-[#2D3748] h-20 border-b border-gray-700 shadow-md fixed w-full top-0 z-50">
      <nav className="flex justify-between items-center px-6 md:px-10 h-full max-w-7xl mx-auto">
        
        {/* Logo */}
        <Link to="/" className="flex items-center gap-3">
          <img
            className="w-14 h-14 transition-transform duration-300 hover:scale-105"
            src="DALL_E_2025-02-02_22.31.24_-_A_modern__minimalist_logo_for__Markify___a_Markdown_editor_website._The_logo_should_feature_a_stylized__M__with_a_pen_or_markdown_symbol_integrated_in-removebg-preview.png"
            alt="Markify Logo"
          />
          <span className="text-[#4DE4EC] text-2xl font-bold tracking-wide">
            Markify
          </span>
        </Link>

        {/* Desktop Navigation */}
        <ul className="hidden md:flex gap-8 text-lg font-medium">
          <li>
            <Link to="/" className="text-white hover:text-[#8EC5FC] transition duration-300">
              Home
            </Link>
          </li>
          <li>
            <Link to="/dashboard" className="text-white hover:text-[#8EC5FC] transition duration-300">
              Get Started
            </Link>
          </li>
          <li>
            <Link to="/mark" className="text-white hover:text-[#8EC5FC] transition duration-300">
              Edit
            </Link>
          </li>
          <li>
            <Link to="/contact" className="text-white hover:text-[#8EC5FC] transition duration-300">
              Contact
            </Link>
          </li>
        </ul>

        {/* Mobile Menu Button */}
        <button
          className="md:hidden text-white focus:outline-none p-2 rounded transition duration-300 hover:bg-gray-700"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        >
          <svg className="w-8 h-8" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16m-7 6h7" />
          </svg>
        </button>
      </nav>

      {/* Mobile Menu */}
      <div
        className={`md:hidden bg-[#2D3748] absolute top-20 left-0 w-full shadow-lg transition-all duration-300 ${
          isMobileMenuOpen ? "opacity-100 h-auto py-4" : "opacity-0 h-0 overflow-hidden"
        }`}
      >
        <ul className="flex flex-col items-center gap-5 text-lg font-medium">
          <li>
            <Link
              to="/"
              className="text-white hover:text-[#8EC5FC] transition duration-300"
              onClick={() => setIsMobileMenuOpen(false)}
            >
              Home
            </Link>
          </li>
          <li>
            <Link
              to="/dashboard"
              className="text-white hover:text-[#8EC5FC] transition duration-300"
              onClick={() => setIsMobileMenuOpen(false)}
            >
              Get Started
            </Link>
          </li>
          <li>
            <Link
              to="/mark"
              className="text-white hover:text-[#8EC5FC] transition duration-300"
              onClick={() => setIsMobileMenuOpen(false)}
            >
              Edit
            </Link>
          </li>
          <li>
            <Link
              to="/contact"
              className="text-white hover:text-[#8EC5FC] transition duration-300"
              onClick={() => setIsMobileMenuOpen(false)}
            >
              Contact
            </Link>
          </li>
        </ul>
      </div>
    </header>
  );
}

export default Nav;
