import React from "react";
import Nav from "./Navbar/nav";
import Footer from "./Navbar/footer";
import "./Home.css";

function Home() {
  return (
    <div className="bg-[#2B2E3B] min-h-screen">
      <Nav />
      
      {/* Main Container */}
      <div className="w-full flex flex-col items-center justify-center px-6">
        
        {/* Logo & Title Section */}
        <div className="flex flex-col md:flex-row items-center text-center md:text-left py-16">
          <img
            className="w-[280px] h-[280px] md:w-[350px] md:h-[350px] drop-shadow-lg transition-transform duration-300 hover:scale-105"
            src="DALL_E_2025-02-02_22.31.24_-_A_modern__minimalist_logo_for__Markify___a_Markdown_editor_website._The_logo_should_feature_a_stylized__M__with_a_pen_or_markdown_symbol_integrated_in-removebg-preview.png"
            alt="Markify Logo"
          />
          <div className="md:ml-6">
            <h1 className="font-itim text-[4rem] md:text-[6rem] text-[#4DE4EC] drop-shadow-xl">
              Markify
            </h1>
            <p className="text-white text-lg md:text-xl mt-2">
              The Ultimate In-Browser Markdown Editor 🚀
            </p>
          </div>
        </div>

        {/* Read More Section */}
        <div className="mt-10 flex flex-col items-center animate-bounce">
          <h1 className="text-white text-xl md:text-2xl">Read More</h1>
          <img
            className="h-8 w-8 md:h-10 md:w-10 mt-2"
            src="icons8-down-arrow-50.png"
            alt="Down Arrow"
          />
        </div>

        {/* Video Section */}
        <div className="p-12 w-full flex flex-col items-center">
          <video
            className="rounded-lg shadow-xl w-full max-w-4xl transition-transform duration-300 hover:scale-105"
            src="Screen Recording 2025-02-03 133430.mp4"
            autoPlay
            loop
            muted
          ></video>
        </div>

        {/* Features Section */}
        <section className="py-24 text-center w-full max-w-5xl">
          <h1 className="text-[#4DE4EC] text-4xl font-semibold">
            🚀 Live Preview with Scroll Sync
          </h1>
          <p className="text-white text-lg mt-4">
            Markify’s Scroll Sync feature accurately binds the scrollbars of the editor and preview panels, ensuring you always see the output while writing.
          </p>
        </section>

        <section className="py-24 text-center w-full max-w-5xl">
          <h1 className="text-[#4DE4EC] text-4xl font-semibold">
            ✍️ Designed for Web Writers
          </h1>
          <div className="flex flex-col md:flex-row items-center mt-8 gap-8">
            <img
              className="w-64 md:w-72 rounded-lg shadow-lg transition-transform duration-300 hover:scale-105"
              src="providers.png"
              alt="Cloud Providers"
            />
            <p className="text-white text-lg md:text-xl">
              Create your notes and save them online, so you never have to worry about losing them again.
            </p>
          </div>
        </section>

        <section className="py-24 text-center w-full max-w-5xl">
          <h1 className="text-[#4DE4EC] text-4xl font-semibold">📶 Write Offline!</h1>
          <p className="text-white text-lg mt-4">
            Even when traveling, Markify is accessible and allows you to write offline, just like any desktop application. No excuses!
          </p>
        </section>

      </div>
      <Footer />
    </div>
  );
}

export default Home;
