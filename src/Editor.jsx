import React, { useState, useEffect, useRef } from "react";
import ReactMde from "react-mde";
import Footer from "./Navbar/footer";
import Showdown from "showdown";
import { useNavigate } from "react-router-dom";
import "react-mde/lib/styles/css/react-mde-all.css";
import './Editor.css'
import axios from "axios";

const MarkdownEditor = () => {
    const [markdown, setMarkdown] = useState("");
    const [convertedHtml, setConvertedHtml] = useState("");
    const previewRef = useRef(null);
    const navigate = useNavigate();
    let storedData;
    let message_to_be;

    const converter = new Showdown.Converter({
        sanitize: true,
        ghCompatibleHeaderId: true,
        tables: true,
        simpleLineBreaks: true,
        strikethrough: true,
        tasklists: true,
        openLinksInNewWindow: true,
    });

    useEffect(() => {
        const fetchData = async () => {
            try {
                storedData = sessionStorage.getItem("userData");
                const token = localStorage.getItem('token');
                console.log(storedData);
                if (!storedData) return;

                const parsedData = JSON.parse(storedData);
                const response = await axios.post('http://localhost:3000/search', parsedData,{headers: {
                    'Authorization': `Bearer ${token}`, // ✅ Send token in headers
                    'Content-Type': 'application/json'
                }});
                const answer = response.data;
                console.log(answer);

                if (answer.message === 'true') {
                    setMarkdown(answer.resultsgot?.marktext || "");
                    storedData=answer.data
                }
            } catch (error) {
                console.error("Error loading markdown from storage", error);
            }
        };

        fetchData();
    }, []);

    useEffect(() => {
        setConvertedHtml(converter.makeHtml(markdown));
    }, [markdown]);

    const handleUpdate = (text) => {
        setMarkdown(text);
    };

    const handleSave = async () => {
        let updatedData = JSON.parse(sessionStorage.getItem('userData'));
        updatedData.marktext = markdown;
    
        const token = localStorage.getItem('token'); // ✅ Get token
    
        if (!token) {
            alert("User not authenticated!");
            return;
        }
    
        console.log("Saving markdown...");
    
        try {
            let result;
            if (updatedData.id == 0) {
                result = await axios.post("http://localhost:3000/add", updatedData, {
                    headers: {
                        'Authorization': `Bearer ${token}`, // ✅ Send token in headers
                        'Content-Type': 'application/json'
                    }
                });
            } else {
                result = await axios.put("http://localhost:3000/add", updatedData, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            }
            storedData=result.note
            console.log(storedData)
    
            if (result.data.message === "ok") {
                alert("Notes saved successfully!");
                
            } else {
                alert("Notes not saved successfully!");
            }
        } catch (error) {
            console.error("Error saving markdown:", error);
        }
    };

    const handleDownload = () => {
        const blob = new Blob([markdown], { type: "text/markdown" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "markdown_content.md";
        link.click();
    };

    return (
        <div className="min-h-screen flex flex-col bg-gray-900 text-white">
            {/* HEADER */}
            <header className="bg-gray-800 p-4 shadow-lg sticky top-0 z-10 flex justify-between items-center">
                <h1 className="text-lg font-bold">Markdown Editor</h1>
                <div className="flex gap-6">
                    <p onClick={() => navigate('/dashboard')} className="cursor-pointer hover:underline">Dashboard</p>
                    <button onClick={() => { localStorage.removeItem("token"); navigate("/login"); }} className="hover:underline">Log out</button>
                </div>
            </header>

            {/* EDITOR & PREVIEW */}
            <div className="flex flex-col md:flex-row flex-grow gap-6 p-6">
                {/* Editor */}
                <div className="flex-1 bg-gray-700 p-4 rounded-lg shadow-lg">
                    <h3 className="text-xl font-semibold mb-2">Editor</h3>
                    <ReactMde
                        value={markdown}
                        onChange={handleUpdate}
                        childProps={{ textArea: { style: { height: "400px" } } }}
                    />
                    <div className="flex gap-4 mt-4">
                        <button onClick={handleSave} className="bg-blue-500 hover:bg-blue-400 px-4 py-2 rounded-lg shadow-md">Save</button>
                        <button onClick={handleDownload} className="bg-green-500 hover:bg-green-400 px-4 py-2 rounded-lg shadow-md">Download</button>
                    </div>
                </div>

                {/* Preview */}
                <div style={{ height: '95vh' }} className="preview-area">
                <h3 className="preview-heading">Preview</h3>
                <div
                    style={{ height: '80vh' }}
                    className="preview-content"
                    ref={previewRef}>
                    <style>{`
                        /* GENERAL CONTAINER STYLING */
                        .markdown-editor-container {
                            display: flex;
                            gap: 20px;
                            padding: 20px;
                            background: #1e1e1e;
                            color: #fff;
                        }
                        .preview-content hr {
                            border: none;
                            border-top: 2px solid #ccc; /* Gray horizontal line */
                            margin: 20px 0;
                        }

                        /* EDITOR AREA */
                        .editor-area {
                            flex: 1;
                            background: #282c34;
                            padding: 20px;
                            border-radius: 10px;
                        }

                        h1 {
                        font-size:30px;
                        font-weight: bold;
                        }

                        h2 {
                        font-size:22px;
                        font-weight: bold;
                        }

                        h3 {
                        font-size:19px;
                        font-weight: bold;
                        }

                        .editor-heading {
                            font-size: 22px;
                            font-weight: bold;
                            margin-bottom: 10px;
                        }

                        /* MARKDOWN PREVIEW AREA */
                        .preview-area {
                            flex: 1;
                            background: #ffffff;
                            color: #000;
                            padding: 20px;
                            border-radius: 10px;
                            overflow-y: auto;
                        }

                        .preview-heading {
                            font-size: 22px;
                            font-weight: bold;
                            margin-bottom: 10px;
                        }

                        /* CODE BLOCK STYLING */
                        .preview-content code {
                            font-family: 'Courier New', monospace;
                            background: #2d2d2d;
                            color: #ffcc00;
                            padding: 5px 10px;
                            border-radius: 6px;
                            display: inline-block;
                        }
                        

                        /* TABLE STYLING */
                        .preview-content table {
                            width: 100%;
                            border-collapse: collapse;
                            margin: 15px 0;
                        }

                        .preview-content th, 
                        .preview-content td {
                            border: 1px solid #ddd;
                            padding: 10px;
                            text-align: left;
                        }

                        .preview-content th {
                            background-color: #f4f4f4;
                            font-weight: bold;
                        }

                        /* BUTTON STYLING */
                        .editor-buttons {
                            margin-top: 10px;
                            display: flex;
                            gap: 10px;
                        }

                        .btn-save, 
                        .btn-download {
                            background: #ff6f00;
                            color: #fff;
                            border: none;
                            padding: 10px 15px;
                            border-radius: 6px;
                            cursor: pointer;
                            font-size: 16px;
                        }

                        .btn-save:hover, 
                        .btn-download:hover {
                            background: #e65c00;
                        }

                                                /* LIST STYLING */
                        .preview-content ul,
                        .preview-content ol {
                            padding-left: 20px;
                            margin: 10px 0;
                        }

                        .preview-content ul {
                            list-style-type: disc; /* Ensures bullet points appear */
                        }

                        .preview-content ol {
                            list-style-type: decimal; /* Ensures numbers appear */
                        }

                        /* CHECKLIST STYLING */
                        .preview-content input[type="checkbox"] {
                            margin-right: 8px;
                            width: 16px;
                            height: 16px;
                            cursor: pointer;
                            accent-color: #ff6f00; /* Change checkbox color */
                        }
                        /* BLOCKQUOTE STYLING */
                        .preview-content blockquote {
                            border-left: 4px solid gray; /* Orange left border */
                            background: #f9f9f9; /* Light gray background */
                            padding: 10px 15px;
                            margin: 10px 0;
                            font-style: italic;
                            color: #555;
                        }




                    `}</style>
                    <div dangerouslySetInnerHTML={{ __html: convertedHtml }}/>
                </div>
                </div>
            </div>
            <Footer />
        </div>
    );
};

export default MarkdownEditor;
