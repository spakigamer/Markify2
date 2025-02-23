import React from "react";
import { Link } from "react-router-dom";

function Footer() {
  return (
    <footer className="bg-[#101F28] py-12 text-white">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center px-5 gap-8">
        
        {/* Logo & Branding */}
        <div className="text-center md:text-left">
          <img
            className="w-20 h-20 mx-auto md:mx-0 transition-transform duration-300 hover:scale-105"
            src="DALL_E_2025-02-02_22.31.24_-_A_modern__minimalist_logo_for__Markify___a_Markdown_editor_website._The_logo_should_feature_a_stylized__M__with_a_pen_or_markdown_symbol_integrated_in-removebg-preview.png"
            alt="Markify Logo"
          />
          <h1 className="text-[#4DE4EC] text-2xl font-bold mt-3">Markify</h1>
          <p className="text-gray-400 text-sm">The Ultimate Markdown Editor</p>
        </div>

        {/* Contact & Navigation */}
        <div className="flex flex-col md:flex-row gap-8 text-center md:text-left">
          
          {/* Contact Details */}
          <div>
            <h1 className="text-[#4DE4EC] text-lg font-semibold">📞 Contact</h1>
            <ul className="text-gray-300 text-sm space-y-1 mt-2">
              <li className="hover:text-[#4DE4EC] transition">support@gmail.com</li>
              <li className="hover:text-[#4DE4EC] transition">+91 123456789</li>
            </ul>
          </div>

          {/* Quick Links */}
          <div>
            <h1 className="text-[#4DE4EC] text-lg font-semibold">🔗 Quick Links</h1>
            <ul className="text-gray-300 text-sm space-y-2 mt-2">
              <li>
                <Link to="/about" className="hover:text-[#4DE4EC] transition duration-300">
                  About Us
                </Link>
              </li>
              <li>
                <Link to="/dashboard" className="hover:text-[#4DE4EC] transition duration-300">
                  Start Editing
                </Link>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Divider Line */}
      <div className="border-t border-gray-700 mt-8"></div>

      {/* Copyright Text */}
      <h3 className="text-center text-gray-400 text-sm mt-5">
        © 2025 Markify. All rights reserved.
      </h3>
    </footer>
  );
}

export default Footer;
